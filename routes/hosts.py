from datetime import datetime, timezone
from flask import render_template, request, redirect, url_for, flash, jsonify
from routes import hosts_bp
from auth.routes import login_required
from database import db
from database.models import Host, MonitoringConfig, BaselinePort, PortSnapshot, Alert, PortEvent
from monitoring.monitor import execute_host_scan
from monitoring.scheduler import start_host_monitoring, stop_host_monitoring
from config import logger

@hosts_bp.route("/")
@login_required
def index():
    hosts = Host.query.order_by(Host.is_local.desc(), Host.created_at.asc()).all()
    # Enrich hosts with open ports count and active alerts
    host_cards = []
    for h in hosts:
        open_cnt = PortSnapshot.query.filter_by(host_id=h.id).count()
        baseline_cnt = BaselinePort.query.filter_by(host_id=h.id).count()
        alerts_cnt = Alert.query.filter(Alert.host_id == h.id, Alert.status.in_(["OPEN", "ACKNOWLEDGED"])).count()
        high_risk_cnt = PortSnapshot.query.filter_by(host_id=h.id, risk_level="HIGH").count()
        
        host_cards.append({
            "host": h,
            "open_ports": open_cnt,
            "baseline_ports": baseline_cnt,
            "active_alerts": alerts_cnt,
            "high_risk": high_risk_cnt,
            "is_monitoring": h.monitoring_config.enabled if h.monitoring_config else False,
            "interval_seconds": h.monitoring_config.interval_seconds if h.monitoring_config else 60,
            "last_scan": h.monitoring_config.last_scan if h.monitoring_config else None,
        })
    online_count = sum(1 for item in host_cards if item["is_monitoring"])
    offline_count = len(host_cards) - online_count
    return render_template(
        "hosts.html",
        hosts=host_cards,
        total_hosts=len(host_cards),
        online_count=online_count,
        offline_count=offline_count,
    )


@hosts_bp.route("/add", methods=["POST"])
@login_required
def add_host():
    name = request.form.get("name", "").strip()
    ip_address = request.form.get("ip_address", "").strip()
    operating_system = request.form.get("operating_system", "").strip()
    description = request.form.get("description", "").strip()
    is_local = request.form.get("is_local") == "true" or ip_address in ["127.0.0.1", "localhost", "::1"]

    if not name or not ip_address:
        flash("Host Name and IP Address are required.", "danger")
        return redirect(url_for("hosts.index"))

    host = Host(
        name=name,
        ip_address=ip_address,
        operating_system=operating_system or "Unknown OS",
        description=description,
        is_local=is_local,
    )
    db.session.add(host)
    db.session.flush()

    config = MonitoringConfig(
        host_id=host.id,
        enabled=False,
        interval_seconds=60,
    )
    db.session.add(config)
    db.session.commit()

    logger.info(f"Added new host '{host.name}' ({host.ip_address})")
    flash(f"Host '{host.name}' added successfully.", "success")
    return redirect(url_for("hosts.detail", host_id=host.id))


@hosts_bp.route("/<int:host_id>")
@login_required
def detail(host_id: int):
    host = db.session.get(Host, host_id)
    if not host:
        flash("Host not found.", "danger")
        return redirect(url_for("hosts.index"))

    snapshots = PortSnapshot.query.filter_by(host_id=host.id).order_by(PortSnapshot.port.asc()).all()
    baselines = BaselinePort.query.filter_by(host_id=host.id).order_by(BaselinePort.port.asc()).all()
    recent_events = PortEvent.query.filter_by(host_id=host.id).order_by(PortEvent.timestamp.desc()).limit(15).all()

    return render_template(
        "host_detail.html",
        host=host,
        snapshots=snapshots,
        baselines=baselines,
        recent_events=recent_events,
    )


@hosts_bp.route("/<int:host_id>/scan", methods=["POST"])
@login_required
def scan_host(host_id: int):
    wants_json = request.is_json or "application/json" in request.headers.get("Accept", "")
    result = execute_host_scan(host_id, is_initial=False)
    if not result.get("success"):
        if wants_json:
            return jsonify(result), 400
        flash(f"Scan failed: {result.get('error', 'Unknown error')}", "danger")
        return redirect(url_for("hosts.detail", host_id=host_id))

    msg = f"Scan completed: {result['open_ports_count']} open ports found, {result['alerts_created']} new alert(s)."
    if wants_json:
        return jsonify({"success": True, "message": msg, **result})
    flash(msg, "success")
    return redirect(url_for("hosts.detail", host_id=host_id))


@hosts_bp.route("/<int:host_id>/baseline/create", methods=["POST"])
@login_required
def create_baseline(host_id: int):
    wants_json = request.is_json or "application/json" in request.headers.get("Accept", "")
    host = db.session.get(Host, host_id)
    if not host:
        if wants_json:
            return jsonify({"error": "Host not found"}), 404
        flash("Host not found.", "danger")
        return redirect(url_for("hosts.index"))

    # If no snapshots currently exist, perform a scan first
    snapshots = PortSnapshot.query.filter_by(host_id=host.id).all()
    if not snapshots:
        execute_host_scan(host.id, is_initial=True)
        snapshots = PortSnapshot.query.filter_by(host_id=host.id).all()

    # Clear existing baseline and flush deletion before adding new records
    BaselinePort.query.filter_by(host_id=host.id).delete()
    db.session.flush()

    seen_baseline_keys = set()
    added_count = 0
    for s in snapshots:
        proto_clean = (s.protocol or "TCP").strip().upper()
        key = (s.port, proto_clean)
        if key in seen_baseline_keys:
            continue
        seen_baseline_keys.add(key)
        b = BaselinePort(
            host_id=host.id,
            port=s.port,
            protocol=proto_clean,
            service=s.service,
            process_name=s.process_name,
            local_address=s.local_address,
        )
        db.session.add(b)
        added_count += 1
    db.session.commit()

    logger.info(f"Baseline created for host '{host.name}' with {added_count} approved ports.")
    msg = f"Baseline successfully created with {added_count} approved ports."
    if wants_json:
        return jsonify({"success": True, "message": msg, "count": added_count})
    flash(msg, "success")
    return redirect(url_for("hosts.detail", host_id=host_id))


@hosts_bp.route("/<int:host_id>/baseline/clear", methods=["POST"])
@login_required
def clear_baseline(host_id: int):
    BaselinePort.query.filter_by(host_id=host_id).delete()
    db.session.commit()
    flash("Baseline cleared for this host.", "info")
    return redirect(url_for("hosts.detail", host_id=host_id))


@hosts_bp.route("/<int:host_id>/monitor/start", methods=["POST"])
@login_required
def start_monitoring(host_id: int):
    wants_json = request.is_json or "application/json" in request.headers.get("Accept", "")
    json_body = request.get_json(silent=True) or {}
    interval = request.form.get("interval_seconds", type=int) or json_body.get("interval_seconds") or 60
    success = start_host_monitoring(host_id, interval_seconds=interval)
    msg = f"Continuous monitoring started (interval: {interval}s)."
    if wants_json:
        return jsonify({"success": success, "message": msg})
    flash(msg, "success")
    return redirect(url_for("hosts.detail", host_id=host_id))


@hosts_bp.route("/<int:host_id>/monitor/stop", methods=["POST"])
@login_required
def stop_monitoring(host_id: int):
    wants_json = request.is_json or "application/json" in request.headers.get("Accept", "")
    success = stop_host_monitoring(host_id)
    msg = "Continuous monitoring stopped."
    if wants_json:
        return jsonify({"success": success, "message": msg})
    flash(msg, "info")
    return redirect(url_for("hosts.detail", host_id=host_id))


@hosts_bp.route("/<int:host_id>/delete", methods=["POST"])
@login_required
def delete_host(host_id: int):
    host = db.session.get(Host, host_id)
    if not host:
        flash("Host not found.", "danger")
        return redirect(url_for("hosts.index"))

    if host.is_local and Host.query.filter_by(is_local=True).count() == 1:
        flash("Cannot delete primary local monitoring host.", "warning")
        return redirect(url_for("hosts.index"))

    stop_host_monitoring(host.id)
    db.session.delete(host)
    db.session.commit()
    flash(f"Host '{host.name}' deleted.", "info")
    return redirect(url_for("hosts.index"))
