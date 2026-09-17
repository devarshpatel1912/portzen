"""Comparator Module
Detects state transitions between current, previous, and baseline port snapshots.
"""

from security.risk_engine import evaluate_port_risk

def compare_port_states(
    current_ports: list[dict],
    previous_ports: list[dict],
    baseline_ports: list[dict],
    is_initial_scan: bool = False,
) -> list[dict]:
    """Compare current port scan against previous snapshot and baseline.

    Returns a list of event dictionaries:
        [
            {
                "port": 8080,
                "protocol": "TCP",
                "event_type": "NEW_PORT" | "PORT_CLOSED" | "PROCESS_CHANGED" | "STATE_CHANGED" | "NO_CHANGE",
                "previous_state": "CLOSED" | "LISTEN",
                "current_state": "LISTEN" | "CLOSED",
                "process_name": "python",
                "pid": 2145,
                "service": "HTTP-Alt",
                "local_address": "0.0.0.0",
                "is_in_baseline": False,
                "risk_analysis": {...},
                "details": "..."
            }, ...
        ]
    """
    events = []

    curr_map = {(p["port"], p["protocol"]): p for p in current_ports}
    prev_map = {(p["port"], p["protocol"]): p for p in previous_ports}
    base_set = {(b["port"], b["protocol"]) for b in baseline_ports}

    all_keys = set(curr_map.keys()).union(set(prev_map.keys()))

    for key in sorted(all_keys):
        port, protocol = key
        curr_item = curr_map.get(key)
        prev_item = prev_map.get(key)
        in_baseline = key in base_set

        if prev_item is None and curr_item is not None:
            # Port was not in previous scan
            event_type = "NO_CHANGE" if is_initial_scan else "NEW_PORT"
            details = "Discovered during initial discovery." if is_initial_scan else "New listening port detected on host."
            
            risk_eval = evaluate_port_risk(
                port=port,
                protocol=protocol,
                local_address=curr_item.get("local_address", "0.0.0.0"),
                service=curr_item.get("service", "Unknown"),
                process_name=curr_item.get("process", "Unknown"),
                is_in_baseline=in_baseline,
                event_type=event_type,
            )

            events.append({
                "port": port,
                "protocol": protocol,
                "event_type": event_type,
                "previous_state": "CLOSED",
                "current_state": curr_item.get("state", "LISTEN"),
                "process_name": curr_item.get("process", "Unknown"),
                "pid": curr_item.get("pid"),
                "service": curr_item.get("service", "Unknown"),
                "local_address": curr_item.get("local_address", "0.0.0.0"),
                "is_in_baseline": in_baseline,
                "risk_analysis": risk_eval,
                "details": details,
            })

        elif curr_item is None and prev_item is not None:
            # Port was listening previously, but closed now
            risk_eval = {
                "risk": "LOW",
                "score": 10,
                "reasons": ["Port closed and no longer listening."],
                "recommendations": ["No remediation required for closed socket."],
            }
            events.append({
                "port": port,
                "protocol": protocol,
                "event_type": "PORT_CLOSED",
                "previous_state": prev_item.get("state", "LISTEN"),
                "current_state": "CLOSED",
                "process_name": prev_item.get("process", "Unknown"),
                "pid": prev_item.get("pid"),
                "service": prev_item.get("service", "Unknown"),
                "local_address": prev_item.get("local_address", "0.0.0.0"),
                "is_in_baseline": in_baseline,
                "risk_analysis": risk_eval,
                "details": f"Port {port}/{protocol} closed and stopped listening.",
            })

        elif curr_item is not None and prev_item is not None:
            # Port active in both scans
            prev_proc = prev_item.get("process")
            curr_proc = curr_item.get("process")
            prev_state = prev_item.get("state")
            curr_state = curr_item.get("state")

            if prev_proc and curr_proc and prev_proc != curr_proc and curr_proc != "Unknown":
                event_type = "PROCESS_CHANGED"
                details = f"Process bound to port {port}/{protocol} changed from '{prev_proc}' to '{curr_proc}'."
            elif prev_state != curr_state:
                event_type = "STATE_CHANGED"
                details = f"Port state changed from '{prev_state}' to '{curr_state}'."
            else:
                event_type = "NO_CHANGE"
                details = "Port remains active with identical process state."

            risk_eval = evaluate_port_risk(
                port=port,
                protocol=protocol,
                local_address=curr_item.get("local_address", "0.0.0.0"),
                service=curr_item.get("service", "Unknown"),
                process_name=curr_item.get("process", "Unknown"),
                is_in_baseline=in_baseline,
                event_type=event_type,
            )

            events.append({
                "port": port,
                "protocol": protocol,
                "event_type": event_type,
                "previous_state": prev_state,
                "current_state": curr_state,
                "process_name": curr_proc,
                "pid": curr_item.get("pid"),
                "service": curr_item.get("service", "Unknown"),
                "local_address": curr_item.get("local_address", "0.0.0.0"),
                "is_in_baseline": in_baseline,
                "risk_analysis": risk_eval,
                "details": details,
            })

    return events
