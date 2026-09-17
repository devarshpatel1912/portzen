import csv
import io
from datetime import datetime, timezone, timedelta
from flask import render_template, request, Response
from sqlalchemy import case
from routes import history_bp
from auth.routes import login_required
from database import db
from database.models import PortEvent, Host


def _build_history_query(selected_host_id=None, risk_filter=None, event_filter=None, port_filter=None, days_filter=None):
    query = PortEvent.query

    if selected_host_id:
        query = query.filter(PortEvent.host_id == selected_host_id)

    if risk_filter and risk_filter in ["LOW", "MEDIUM", "HIGH"]:
        query = query.filter(PortEvent.risk_level == risk_filter)

    if event_filter and event_filter not in ["ALL", ""]:
        query = query.filter(PortEvent.event_type == event_filter)

    if port_filter:
        query = query.filter(PortEvent.port == port_filter)

    if days_filter and days_filter > 0:
        since = datetime.now(timezone.utc) - timedelta(days=days_filter)
        query = query.filter(PortEvent.timestamp >= since)

    return query


@history_bp.route("/")
@login_required
def index():
    hosts = Host.query.order_by(Host.name.asc()).all()

    # Filter parameters
    selected_host_id = request.args.get("host_id", type=int)
    risk_filter = request.args.get("risk", "").strip().upper()
    event_filter = request.args.get("event", "").strip().upper()
    port_filter = request.args.get("port", type=int)
    days_filter = request.args.get("days", type=int)

    # Sorting
    sort_by = request.args.get("sort", "timestamp_desc").strip()

    # Pagination
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    if per_page not in [10, 25, 50, 100]:
        per_page = 10

    query = _build_history_query(
        selected_host_id=selected_host_id,
        risk_filter=risk_filter,
        event_filter=event_filter,
        port_filter=port_filter,
        days_filter=days_filter,
    )

    # Apply Sorting
    if sort_by == "timestamp_asc":
        query = query.order_by(PortEvent.timestamp.asc())
    elif sort_by == "port_asc":
        query = query.order_by(PortEvent.port.asc(), PortEvent.timestamp.desc())
    elif sort_by == "port_desc":
        query = query.order_by(PortEvent.port.desc(), PortEvent.timestamp.desc())
    elif sort_by == "risk_high":
        query = query.order_by(
            case((PortEvent.risk_level == "HIGH", 1), (PortEvent.risk_level == "MEDIUM", 2), else_=3),
            PortEvent.timestamp.desc(),
        )
    elif sort_by == "risk_low":
        query = query.order_by(
            case((PortEvent.risk_level == "LOW", 1), (PortEvent.risk_level == "MEDIUM", 2), else_=3),
            PortEvent.timestamp.desc(),
        )
    elif sort_by == "event_asc":
        query = query.order_by(PortEvent.event_type.asc(), PortEvent.timestamp.desc())
    elif sort_by == "event_desc":
        query = query.order_by(PortEvent.event_type.desc(), PortEvent.timestamp.desc())
    elif sort_by == "process_asc":
        query = query.order_by(PortEvent.process_name.asc().nullslast(), PortEvent.timestamp.desc())
    elif sort_by == "process_desc":
        query = query.order_by(PortEvent.process_name.desc().nullslast(), PortEvent.timestamp.desc())
    elif sort_by == "host_asc":
        query = query.outerjoin(Host).order_by(Host.name.asc(), PortEvent.timestamp.desc())
    elif sort_by == "host_desc":
        query = query.outerjoin(Host).order_by(Host.name.desc(), PortEvent.timestamp.desc())
    else:  # timestamp_desc (default)
        sort_by = "timestamp_desc"
        query = query.order_by(PortEvent.timestamp.desc())

    total_count = query.count()
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    events = query.offset((page - 1) * per_page).limit(per_page).all()

    # Pagination numbers calculation
    page_numbers = []
    if total_pages <= 7:
        page_numbers = list(range(1, total_pages + 1))
    else:
        if page <= 4:
            page_numbers = [1, 2, 3, 4, 5, '...', total_pages]
        elif page >= total_pages - 3:
            page_numbers = [1, '...', total_pages - 4, total_pages - 3, total_pages - 2, total_pages - 1, total_pages]
        else:
            page_numbers = [1, '...', page - 1, page, page + 1, '...', total_pages]

    start_index = (page - 1) * per_page + 1 if total_count > 0 else 0
    end_index = min(page * per_page, total_count)

    # Calculate 5 KPI Metrics
    total_events = PortEvent.query.count()
    new_ports = PortEvent.query.filter_by(event_type="NEW_PORT").count()
    closed_ports = PortEvent.query.filter_by(event_type="PORT_CLOSED").count()
    proc_changes = PortEvent.query.filter_by(event_type="PROCESS_CHANGED").count()
    state_transitions = PortEvent.query.filter(
        PortEvent.event_type.in_(["STATE_CHANGED", "PORT_CLOSED", "PROCESS_CHANGED"])
    ).count()

    kpis = {
        "total_events": total_events,
        "new_ports": new_ports,
        "new_ports_trend": 12,
        "closed_ports": closed_ports,
        "closed_ports_trend": 8,
        "process_changes": proc_changes,
        "process_changes_trend": 5,
        "state_transitions": state_transitions,
        "state_transitions_trend": 3,
    }

    return render_template(
        "history.html",
        events=events,
        hosts=hosts,
        selected_host_id=selected_host_id,
        risk_filter=risk_filter,
        event_filter=event_filter,
        port_filter=port_filter,
        days_filter=days_filter,
        sort_by=sort_by,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_count=total_count,
        start_index=start_index,
        end_index=end_index,
        page_numbers=page_numbers,
        kpis=kpis,
    )


@history_bp.route("/export")
@login_required
def export_csv():
    """Export filtered history events to a CSV audit log."""
    selected_host_id = request.args.get("host_id", type=int)
    risk_filter = request.args.get("risk", "").strip().upper()
    event_filter = request.args.get("event", "").strip().upper()
    port_filter = request.args.get("port", type=int)
    days_filter = request.args.get("days", type=int)

    query = _build_history_query(
        selected_host_id=selected_host_id,
        risk_filter=risk_filter,
        event_filter=event_filter,
        port_filter=port_filter,
        days_filter=days_filter,
    ).order_by(PortEvent.timestamp.desc())

    events = query.limit(5000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp (UTC)",
        "Host Name",
        "IP Address",
        "Port",
        "Protocol",
        "Event Type",
        "Process Name",
        "Process ID (PID)",
        "Risk Level",
        "Details",
    ])

    for ev in events:
        writer.writerow([
            ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if ev.timestamp else "",
            ev.host.name if ev.host else "Unknown",
            ev.host.ip_address if ev.host else "",
            ev.port,
            ev.protocol,
            ev.event_type,
            ev.process_name or "Unknown",
            ev.pid or "",
            ev.risk_level or "LOW",
            ev.details or "",
        ])

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"portzen_history_audit_{timestamp}.csv"

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
