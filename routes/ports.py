import csv
import io
import math
from collections import defaultdict
from datetime import datetime, timezone
from flask import render_template, request, jsonify, flash, redirect, url_for, Response
from routes import ports_bp
from auth.routes import login_required
from database import db
from database.models import Host, PortSnapshot, BaselinePort, PortEvent, Alert
from security.risk_engine import evaluate_port_risk

def get_page_numbers(current_page: int, total_pages: int):
    """Generate display page numbers list with ellipsis matching mockup."""
    if total_pages <= 7:
        return list(range(1, total_pages + 1))
    
    pages = []
    if current_page <= 4:
        pages.extend(range(1, 6))
        pages.append("...")
        pages.append(total_pages)
    elif current_page >= total_pages - 3:
        pages.append(1)
        pages.append("...")
        pages.extend(range(total_pages - 4, total_pages + 1))
    else:
        pages.append(1)
        pages.append("...")
        pages.extend(range(current_page - 1, current_page + 2))
        pages.append("...")
        pages.append(total_pages)
    return pages

@ports_bp.route("/ports")
@login_required
def index():
    hosts = Host.query.order_by(Host.name.asc()).all()
    
    # Filter parameters
    selected_host_id = request.args.get("host_id", type=int)
    risk_filter = request.args.get("risk", "").strip().upper()
    status_filter = request.args.get("status", "").strip().upper()
    search_query = (request.args.get("search") or request.args.get("q") or "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 8, type=int)
    if per_page not in [8, 10, 20, 50, 100]:
        per_page = 8
    if page < 1:
        page = 1

    query = PortSnapshot.query

    if selected_host_id:
        query = query.filter(PortSnapshot.host_id == selected_host_id)
    if risk_filter and risk_filter in ["LOW", "MEDIUM", "HIGH"]:
        query = query.filter(PortSnapshot.risk_level == risk_filter)
    if status_filter and status_filter in ["LISTEN", "ACTIVE"]:
        query = query.filter(PortSnapshot.state == status_filter)

    snapshots = query.order_by(PortSnapshot.port.asc(), PortSnapshot.protocol.asc()).all()

    # In-memory search filtering for service, process, port, or local address
    if search_query:
        sq = search_query.lower()
        snapshots = [
            s for s in snapshots
            if sq in str(s.port) or sq in (s.service or "").lower() or sq in (s.process_name or "").lower() or sq in s.local_address.lower()
        ]

    # Preload baseline set for visual indication
    baseline_keys = set()
    if snapshots:
        host_ids = list({s.host_id for s in snapshots})
        baselines = BaselinePort.query.filter(BaselinePort.host_id.in_(host_ids)).all()
        baseline_keys = {(b.host_id, b.port, b.protocol) for b in baselines}

    # Calculate summary metrics matching exact 4 card layout
    total_open_ports = len(snapshots)
    approved_ports = sum(1 for s in snapshots if (s.host_id, s.port, s.protocol) in baseline_keys)
    high_risk_ports = sum(1 for s in snapshots if s.risk_level == "HIGH")
    unregistered_ports = max(0, total_open_ports - approved_ports)

    approved_pct = round((approved_ports / total_open_ports * 100)) if total_open_ports > 0 else 0
    unregistered_pct = round((unregistered_ports / total_open_ports * 100)) if total_open_ports > 0 else 0
    high_risk_pct = round((high_risk_ports / total_open_ports * 100)) if total_open_ports > 0 else 0

    stats = {
        "total_open_ports": total_open_ports,
        "approved_ports": approved_ports,
        "approved_pct": approved_pct,
        "unregistered_ports": unregistered_ports,
        "unregistered_pct": unregistered_pct,
        "high_risk_ports": high_risk_ports,
        "high_risk_pct": high_risk_pct,
    }

    enriched_snapshots = []
    for s in snapshots:
        in_baseline = (s.host_id, s.port, s.protocol) in baseline_keys
        enriched_snapshots.append({
            "snapshot": s,
            "in_baseline": in_baseline,
        })

    # Pagination calculation
    total_items = len(enriched_snapshots)
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    page = min(max(1, page), total_pages)
    start_idx = (page - 1) * per_page
    end_idx = min(start_idx + per_page, total_items)
    paged_ports = enriched_snapshots[start_idx:end_idx]

    pagination = {
        "page": page,
        "per_page": per_page,
        "total": total_items,
        "total_pages": total_pages,
        "start_item": (start_idx + 1) if total_items > 0 else 0,
        "end_item": end_idx,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_page": page - 1,
        "next_page": page + 1,
        "pages": get_page_numbers(page, total_pages),
    }

    return render_template(
        "ports.html",
        hosts=hosts,
        selected_host_id=selected_host_id,
        risk_filter=risk_filter,
        status_filter=status_filter,
        search_query=search_query,
        ports=paged_ports,
        stats=stats,
        pagination=pagination,
    )


@ports_bp.route("/ports/export")
@login_required
def export_csv():
    """Export filtered discovered ports to CSV."""
    selected_host_id = request.args.get("host_id", type=int)
    risk_filter = request.args.get("risk", "").strip().upper()
    status_filter = request.args.get("status", "").strip().upper()
    search_query = (request.args.get("search") or request.args.get("q") or "").strip()

    query = PortSnapshot.query
    if selected_host_id:
        query = query.filter(PortSnapshot.host_id == selected_host_id)
    if risk_filter and risk_filter in ["LOW", "MEDIUM", "HIGH"]:
        query = query.filter(PortSnapshot.risk_level == risk_filter)
    if status_filter and status_filter in ["LISTEN", "ACTIVE"]:
        query = query.filter(PortSnapshot.state == status_filter)

    snapshots = query.order_by(PortSnapshot.port.asc(), PortSnapshot.protocol.asc()).all()

    if search_query:
        sq = search_query.lower()
        snapshots = [
            s for s in snapshots
            if sq in str(s.port) or sq in (s.service or "").lower() or sq in (s.process_name or "").lower() or sq in s.local_address.lower()
        ]

    host_ids = list({s.host_id for s in snapshots})
    baseline_keys = set()
    if host_ids:
        baselines = BaselinePort.query.filter(BaselinePort.host_id.in_(host_ids)).all()
        baseline_keys = {(b.host_id, b.port, b.protocol) for b in baselines}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Port", "Protocol", "Service", "Process", "PID", "Local Address", "Baseline", "Status", "Risk Level"])
    
    for s in snapshots:
        in_baseline = "Approved" if (s.host_id, s.port, s.protocol) in baseline_keys else "Unregistered"
        writer.writerow([
            s.port,
            s.protocol,
            s.service or "Unknown",
            s.process_name or "Unknown",
            s.pid or "",
            s.local_address,
            in_baseline,
            s.state,
            s.risk_level,
        ])

    filename = f"portzen_ports_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@ports_bp.route("/ports/<int:snapshot_id>/baseline-toggle", methods=["POST"])
@login_required
def toggle_baseline(snapshot_id: int):
    """Toggle baseline approval for a specific port snapshot."""
    snapshot = db.session.get(PortSnapshot, snapshot_id)
    if not snapshot:
        flash("Port snapshot not found.", "danger")
        return redirect(url_for("ports.index"))

    baseline = BaselinePort.query.filter_by(
        host_id=snapshot.host_id,
        port=snapshot.port,
        protocol=snapshot.protocol,
    ).first()

    if baseline:
        db.session.delete(baseline)
        db.session.commit()
        flash(f"Port {snapshot.port}/{snapshot.protocol} marked as Unregistered.", "warning")
    else:
        new_b = BaselinePort(
            host_id=snapshot.host_id,
            port=snapshot.port,
            protocol=snapshot.protocol,
            service=snapshot.service,
            process_name=snapshot.process_name,
            local_address=snapshot.local_address,
        )
        db.session.add(new_b)
        db.session.commit()
        flash(f"Port {snapshot.port}/{snapshot.protocol} approved and added to baseline.", "success")

    return redirect(request.referrer or url_for("ports.detail", snapshot_id=snapshot.id))


@ports_bp.route("/ports/<int:snapshot_id>/rescan", methods=["POST"])
@login_required
def rescan_port(snapshot_id: int):
    """Rescan host ports and refresh port snapshot."""
    snapshot = db.session.get(PortSnapshot, snapshot_id)
    if not snapshot:
        flash("Port snapshot not found.", "danger")
        return redirect(url_for("ports.index"))

    host_id = snapshot.host_id
    port = snapshot.port
    protocol = snapshot.protocol

    from monitoring.monitor import execute_host_scan
    execute_host_scan(host_id, is_initial=False)

    updated_snap = PortSnapshot.query.filter_by(
        host_id=host_id,
        port=port,
        protocol=protocol,
    ).first()

    flash(f"Port {port}/{protocol} rescanned successfully.", "success")
    if updated_snap:
        return redirect(url_for("ports.detail", snapshot_id=updated_snap.id))
    return redirect(url_for("ports.index", host_id=host_id))



@ports_bp.route("/ports/<int:snapshot_id>")
@login_required
def detail(snapshot_id: int):
    snapshot = db.session.get(PortSnapshot, snapshot_id)
    if not snapshot:
        flash("Port snapshot not found.", "danger")
        return redirect(url_for("ports.index"))

    host = snapshot.host
    in_baseline = BaselinePort.query.filter_by(
        host_id=snapshot.host_id,
        port=snapshot.port,
        protocol=snapshot.protocol,
    ).first() is not None

    # First seen / last seen
    first_event = PortEvent.query.filter_by(
        host_id=snapshot.host_id,
        port=snapshot.port,
        protocol=snapshot.protocol,
    ).order_by(PortEvent.timestamp.asc()).first()
    
    first_seen = first_event.timestamp if first_event else snapshot.timestamp
    last_seen = snapshot.timestamp

    # Risk evaluation
    risk_data = evaluate_port_risk(
        port=snapshot.port,
        protocol=snapshot.protocol,
        local_address=snapshot.local_address,
        service=snapshot.service,
        process_name=snapshot.process_name,
        is_in_baseline=in_baseline,
        event_type="NO_CHANGE",
    )

    # Related alerts
    alerts = Alert.query.filter_by(
        host_id=snapshot.host_id,
        port=snapshot.port,
        protocol=snapshot.protocol,
    ).order_by(Alert.created_at.desc()).all()

    # Recent history for this port
    events = PortEvent.query.filter_by(
        host_id=snapshot.host_id,
        port=snapshot.port,
        protocol=snapshot.protocol,
    ).order_by(PortEvent.timestamp.desc()).limit(10).all()

    data = {
        "snapshot": snapshot,
        "host": host,
        "in_baseline": in_baseline,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "risk_data": risk_data,
        "alerts": alerts,
        "events": events,
    }

    if request.is_json:
        return jsonify({
            "port": snapshot.port,
            "protocol": snapshot.protocol,
            "state": snapshot.state,
            "local_address": snapshot.local_address,
            "service": snapshot.service,
            "process": snapshot.process_name,
            "pid": snapshot.pid,
            "in_baseline": in_baseline,
            "risk": risk_data["risk"],
            "score": risk_data["score"],
            "reasons": risk_data["reasons"],
            "recommendations": risk_data["recommendations"],
        })

    return render_template("port_detail.html", **data)


@ports_bp.route("/processes")
@ports_bp.route("/ports/processes")
@login_required
def processes():
    hosts = Host.query.order_by(Host.name.asc()).all()
    selected_host_id = request.args.get("host_id", type=int)
    risk_filter = request.args.get("risk_level", "").strip().upper()
    min_sockets = request.args.get("min_sockets", type=int)
    search_query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)

    if per_page not in [5, 8, 10, 20, 25, 50, 100]:
        per_page = 10
    if page < 1:
        page = 1

    query = PortSnapshot.query
    if selected_host_id:
        query = query.filter_by(host_id=selected_host_id)
    snapshots = query.all()

    # Group by (process_name, pid, host_id)
    proc_map = defaultdict(list)
    for s in snapshots:
        key = (
            s.process_name or "Unknown",
            s.pid,
            s.host_id,
            s.host.name if s.host else "Unknown",
            s.host.ip_address if s.host else "127.0.0.1",
        )
        proc_map[key].append(s)

    all_processes = []
    for (p_name, pid, h_id, h_name, h_ip), sn_list in proc_map.items():
        sn_list.sort(key=lambda x: x.port)
        ports_summary = [f"{s.port}/{s.protocol}" for s in sn_list]
        max_risk = "LOW"
        for s in sn_list:
            if s.risk_level == "HIGH":
                max_risk = "HIGH"
                break
            elif s.risk_level == "MEDIUM":
                max_risk = "MEDIUM"

        first_snapshot_id = sn_list[0].id if sn_list else None

        all_processes.append({
            "process_name": p_name,
            "pid": pid,
            "host_id": h_id,
            "host_name": h_name,
            "host_ip": h_ip,
            "ports": ports_summary,
            "count": len(sn_list),
            "max_risk": max_risk,
            "snapshots": sn_list,
            "first_snapshot_id": first_snapshot_id,
        })

    # Stats for 4 KPI cards matching screenshot
    total_processes = len(all_processes)
    total_ports_count = sum(p["count"] for p in all_processes)
    medium_risk_count = sum(1 for p in all_processes if p["max_risk"] == "MEDIUM")
    high_risk_count = sum(1 for p in all_processes if p["max_risk"] == "HIGH")

    stats = {
        "total_processes": total_processes,
        "total_listening_ports": total_ports_count,
        "medium_risk_processes": medium_risk_count,
        "high_risk_processes": high_risk_count,
    }

    # Filter by risk level
    filtered_list = all_processes
    if risk_filter in ["HIGH", "MEDIUM", "LOW"]:
        filtered_list = [p for p in filtered_list if p["max_risk"] == risk_filter]

    # Filter by min sockets
    if min_sockets and min_sockets > 0:
        filtered_list = [p for p in filtered_list if p["count"] >= min_sockets]

    # Filter by search query
    if search_query:
        q = search_query.lower()
        filtered_list = [
            p for p in filtered_list
            if q in p["process_name"].lower()
            or (p["pid"] and q in str(p["pid"]))
            or any(q in pt.lower() for pt in p["ports"])
            or q in p["host_name"].lower()
            or q in p["host_ip"].lower()
        ]

    # Sort: High risk first, then sockets count desc, then name asc
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    filtered_list.sort(key=lambda x: (risk_order.get(x["max_risk"], 3), -x["count"], x["process_name"].lower()))

    # Pagination calculation
    total_count = len(filtered_list)
    total_pages = max(1, math.ceil(total_count / per_page)) if total_count > 0 else 1
    if page > total_pages:
        page = total_pages

    start_idx = (page - 1) * per_page
    end_idx = min(start_idx + per_page, total_count)
    paged_processes = filtered_list[start_idx:end_idx]

    page_numbers = get_page_numbers(page, total_pages)

    return render_template(
        "processes.html",
        hosts=hosts,
        selected_host_id=selected_host_id,
        risk_filter=risk_filter,
        min_sockets=min_sockets,
        search_query=search_query,
        stats=stats,
        processes=paged_processes,
        total_count=total_count,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        page_numbers=page_numbers,
        start_index=start_idx + 1 if total_count > 0 else 0,
        end_index=end_idx,
    )
