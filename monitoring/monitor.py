"""Host Monitoring Service
Orchestrates port discovery, state comparison, snapshot persistence,
event logging, and security alert generation.
"""

from datetime import datetime, timedelta, timezone
from database import db
from database.models import Host, BaselinePort, PortSnapshot, PortEvent, Alert, MonitoringConfig
from scanner.port_scanner import scan_local_ports, scan_remote_ports
from monitoring.comparator import compare_port_states
from config import logger

def execute_host_scan(host_id: int, is_initial: bool = False) -> dict:
    """Execute a single complete port inspection cycle for a host.

    Returns summary dictionary:
        {
            "host_id": int,
            "host_name": str,
            "open_ports_count": int,
            "events_count": int,
            "alerts_created": int,
            "events": list[dict],
            "timestamp": str
        }
    """
    host = db.session.get(Host, host_id)
    if not host:
        logger.error(f"Cannot scan: Host ID {host_id} not found.")
        return {"error": "Host not found", "success": False}

    logger.info(f"Initiating port scan for host '{host.name}' (ID: {host.id}, IP: {host.ip_address})...")

    # 1. Fetch current baseline
    baseline_records = BaselinePort.query.filter_by(host_id=host.id).all()
    baseline_ports = [b.to_dict() for b in baseline_records]

    # 2. Fetch previous snapshot
    prev_snapshots = PortSnapshot.query.filter_by(host_id=host.id).all()
    previous_ports = [p.to_dict() for p in prev_snapshots]

    # 3. Discover current ports
    if host.is_local:
        current_ports = scan_local_ports()
    else:
        current_ports = scan_remote_ports(host.ip_address)

    # 4. Compare states
    events_data = compare_port_states(
        current_ports=current_ports,
        previous_ports=previous_ports,
        baseline_ports=baseline_ports,
        is_initial_scan=is_initial,
    )

    created_alerts = 0
    logged_events = 0
    now = datetime.now(timezone.utc)

    # 5. Process events and generate alerts
    for ev in events_data:
        event_type = ev["event_type"]
        risk_data = ev["risk_analysis"]
        risk_level = risk_data["risk"]

        # Only persist events that represent real state changes or initial discovery
        if event_type != "NO_CHANGE" or is_initial:
            port_event = PortEvent(
                host_id=host.id,
                port=ev["port"],
                protocol=ev["protocol"],
                event_type=event_type,
                previous_state=ev["previous_state"],
                current_state=ev["current_state"],
                process_name=ev["process_name"],
                pid=ev["pid"],
                service=ev["service"],
                risk_level=risk_level,
                details=ev["details"],
                timestamp=now,
            )
            db.session.add(port_event)
            db.session.flush()  # assign port_event.id
            logged_events += 1

            # Decide alert generation criteria:
            # - New port detected
            # - Process changed on an existing listening port
            # - High risk port identified (e.g. database exposed, insecure telnet, etc.)
            # - Medium risk unexpected port
            should_alert = False
            if event_type in ["NEW_PORT", "PROCESS_CHANGED"]:
                should_alert = True
            elif risk_level in ["HIGH", "MEDIUM"] and ev["current_state"] != "CLOSED":
                should_alert = True

            if should_alert:
                # Check for existing duplicate OPEN or ACKNOWLEDGED alert for same port/protocol
                existing_alert = Alert.query.filter_by(
                    host_id=host.id,
                    port=ev["port"],
                    protocol=ev["protocol"],
                ).filter(Alert.status.in_(["OPEN", "ACKNOWLEDGED"])).first()

                reasons_text = "\n• ".join(risk_data["reasons"])
                recs_text = "\n• ".join(risk_data["recommendations"])

                reason_summary = f"{ev['details']}\n• {reasons_text}"

                if not existing_alert:
                    alert = Alert(
                        host_id=host.id,
                        event_id=port_event.id,
                        port=ev["port"],
                        protocol=ev["protocol"],
                        risk=risk_level,
                        score=risk_data["score"],
                        reason=reason_summary,
                        recommendation=f"• {recs_text}",
                        status="OPEN",
                        process_name=ev["process_name"],
                        pid=ev["pid"],
                        service=ev["service"],
                        created_at=now,
                    )
                    db.session.add(alert)
                    created_alerts += 1
                    logger.warning(
                        f"ALERT CREATED: Host={host.name} Port={ev['port']}/{ev['protocol']} Risk={risk_level} Reason={ev['details']}"
                    )
                else:
                    # Update existing open alert with updated score & event reference
                    existing_alert.event_id = port_event.id
                    existing_alert.risk = risk_level
                    existing_alert.score = risk_data["score"]
                    existing_alert.reason = reason_summary
                    existing_alert.recommendation = f"• {recs_text}"
                    existing_alert.process_name = ev["process_name"]
                    existing_alert.pid = ev["pid"]

    # 6. Replace snapshots with current active ports
    PortSnapshot.query.filter_by(host_id=host.id).delete()
    for cp in current_ports:
        # Determine port risk level for snapshot
        in_b = (cp["port"], cp["protocol"]) in {(b["port"], b["protocol"]) for b in baseline_ports}
        from security.risk_engine import evaluate_port_risk
        eval_res = evaluate_port_risk(
            port=cp["port"],
            protocol=cp["protocol"],
            local_address=cp["local_address"],
            service=cp["service"],
            process_name=cp["process"],
            is_in_baseline=in_b,
            event_type="NO_CHANGE",
        )
        snap = PortSnapshot(
            host_id=host.id,
            port=cp["port"],
            protocol=cp["protocol"],
            local_address=cp["local_address"],
            state=cp["state"],
            process_name=cp["process"],
            pid=cp["pid"],
            service=cp["service"],
            risk_level=eval_res["risk"],
            timestamp=now,
        )
        db.session.add(snap)

    # 7. Update host monitoring config timestamps
    config = host.monitoring_config
    if config:
        config.last_scan = now
        interval = config.interval_seconds or 60
        config.next_scan = now + timedelta(seconds=interval)

    db.session.commit()
    logger.info(
        f"Scan completed for host '{host.name}': {len(current_ports)} open ports, {logged_events} events, {created_alerts} new alerts."
    )

    return {
        "success": True,
        "host_id": host.id,
        "host_name": host.name,
        "open_ports_count": len(current_ports),
        "events_count": logged_events,
        "alerts_created": created_alerts,
        "timestamp": now.isoformat(),
    }
