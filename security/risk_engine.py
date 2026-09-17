"""Security Risk Engine Module
Calculates transparent, rule-based risk levels, scores, explainable reasons,
and actionable remediation recommendations for network ports.
"""

from security.rules import INSECURE_PROTOCOLS, DATABASE_PORTS, ADMIN_PORTS, WINDOWS_INFRASTRUCTURE

def evaluate_port_risk(
    port: int,
    protocol: str = "TCP",
    local_address: str = "0.0.0.0",
    service: str = "Unknown",
    process_name: str = "Unknown",
    is_in_baseline: bool = False,
    event_type: str = "NO_CHANGE",
) -> dict:
    """Evaluate port security risk based on deterministic, transparent rules.

    Returns:
        {
            "risk": "LOW" | "MEDIUM" | "HIGH",
            "score": int,
            "reasons": list[str],
            "recommendations": list[str]
        }
    """
    score = 10
    reasons = []
    recommendations = []

    is_network_facing = False
    clean_addr = (local_address or "").strip().lower()
    if clean_addr not in ["127.0.0.1", "::1", "localhost"]:
        is_network_facing = True

    # 1. Baseline Analysis
    if not is_in_baseline:
        score += 25
        reasons.append("Port was not present in the approved baseline.")
        recommendations.append("Investigate if this service is authorized; if approved, update baseline.")
    else:
        reasons.append("Port matches authorized baseline configuration.")
        reasons.append("Known system service or internal communication.")
        reasons.append("No indicators of suspicious activity.")

    # 2. Event Type Factor
    if event_type == "NEW_PORT":
        score += 15
        reasons.append("New listening port detected during monitoring cycle.")
    elif event_type == "PROCESS_CHANGED":
        score += 20
        reasons.append(f"Underlying process binding changed to '{process_name}'.")
        recommendations.append("Confirm the binary replacement is legitimate software update or maintenance.")

    # 3. Insecure Protocol Check (High Severity)
    if port in INSECURE_PROTOCOLS:
        proto_meta = INSECURE_PROTOCOLS[port]
        score += 45
        reasons.append(f"Insecure protocol detected ({proto_meta['name']}): {proto_meta['description']}")
        recommendations.append(proto_meta["remediation"])

    # 4. Database Exposure Check
    if port in DATABASE_PORTS:
        db_name = DATABASE_PORTS[port]
        if is_network_facing:
            score += 40
            reasons.append(f"Database service ({db_name}) is exposed on external/all interfaces ({local_address}).")
            recommendations.append("Restrict database listening address to 127.0.0.1 or configure host firewall rules.")
        else:
            score += 15
            reasons.append(f"Database service ({db_name}) detected listening on local loopback.")

    # 5. Remote Administration Exposure Check
    if port in ADMIN_PORTS:
        admin_name = ADMIN_PORTS[port]
        if is_network_facing:
            score += 30
            reasons.append(f"Remote administration interface ({admin_name}) exposed on {local_address}.")
            recommendations.append("Enforce multi-factor authentication, VPN gateway, and network access control lists.")
        else:
            score += 10
            reasons.append(f"Remote administration interface ({admin_name}) bound locally.")

    # 6. Windows Infrastructure Exposure Check
    if port in WINDOWS_INFRASTRUCTURE:
        infra_name = WINDOWS_INFRASTRUCTURE[port]
        if is_network_facing:
            score += 25
            reasons.append(f"Windows system service ({infra_name}) listening on external interface.")
            recommendations.append("Ensure port is blocked on external router/firewall boundaries.")

    # 7. Unknown Service Exposure on Public Interface
    if (not service or service.lower() == "unknown") and is_network_facing:
        score += 15
        if not is_in_baseline:
            reasons.append(f"Unknown listening service exposed on network interface {local_address}.")
            recommendations.append("Identify the software or binary generating this listening socket.")
        else:
            reasons.append(f"Listening on {local_address} (verify if external access is required).")

    # 8. Local Only Binding Mitigation
    if not is_network_facing:
        score = max(5, score - 20)
        reasons.append(f"Socket restricted to localhost loopback ({local_address}), mitigating external network exposure.")

    # Normalization & Categorization
    score = min(100, max(0, score))

    if score >= 65:
        risk = "HIGH"
    elif score >= 35:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # Default fallback recommendations if needed
    if is_in_baseline and len(recommendations) < 4:
        standard_baseline_recs = [
            "Verify the purpose of this service.",
            "Ensure it is required for your environment.",
            "Restrict network access if unnecessary.",
            "Monitor for unexpected changes.",
        ]
        for sbr in standard_baseline_recs:
            if sbr not in recommendations:
                recommendations.append(sbr)
    elif not recommendations:
        recommendations.append("Continue routine monitoring; no immediate corrective action required.")

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "recommendations": recommendations,
    }
