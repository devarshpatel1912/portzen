from datetime import datetime, timezone
from flask import render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import case, or_
from routes import alerts_bp
from auth.routes import login_required
from database import db
from database.models import Alert, Host
from config import logger

@alerts_bp.route("/")
@login_required
def index():
    status_filter = request.args.get("status", "ALL").strip().upper()
    risk_filter = request.args.get("risk", "").strip().upper()
    host_id = request.args.get("host_id", type=int)
    alert_type = request.args.get("alert_type", "").strip().lower()
    search_query = request.args.get("q", "").strip()
    sort_by = request.args.get("sort", "newest").strip().lower()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 15, type=int)
    if per_page not in [10, 15, 25, 50, 100]:
        per_page = 15

    query = Alert.query.join(Host, Alert.host_id == Host.id)

    # Status filter
    if status_filter and status_filter != "ALL":
        if status_filter in ["OPEN", "ACKNOWLEDGED", "RESOLVED", "IGNORED"]:
            query = query.filter(Alert.status == status_filter)
    
    # Risk filter
    if risk_filter and risk_filter in ["HIGH", "MEDIUM", "LOW"]:
        query = query.filter(Alert.risk == risk_filter)

    # Host filter
    if host_id:
        query = query.filter(Alert.host_id == host_id)

    # Alert Type filter
    if alert_type:
        if "port" in alert_type:
            query = query.filter(or_(Alert.reason.ilike("%listening port%"), Alert.reason.ilike("%new port%")))
        elif "process" in alert_type:
            query = query.filter(Alert.reason.ilike("%process%"))
        elif "policy" in alert_type or "baseline" in alert_type:
            query = query.filter(Alert.reason.ilike("%baseline%"))
        elif "exposure" in alert_type or "interface" in alert_type:
            query = query.filter(or_(Alert.reason.ilike("%interface%"), Alert.reason.ilike("%0.0.0.0%"), Alert.reason.ilike("%exposure%")))

    # Search filter
    if search_query:
        search_terms = []
        if search_query.isdigit():
            search_terms.append(Alert.port == int(search_query))
            search_terms.append(Alert.pid == int(search_query))
        search_terms.append(Alert.process_name.ilike(f"%{search_query}%"))
        search_terms.append(Alert.service.ilike(f"%{search_query}%"))
        search_terms.append(Alert.reason.ilike(f"%{search_query}%"))
        search_terms.append(Host.name.ilike(f"%{search_query}%"))
        search_terms.append(Host.ip_address.ilike(f"%{search_query}%"))
        query = query.filter(or_(*search_terms))

    # Sorting
    if sort_by == "oldest":
        query = query.order_by(Alert.created_at.asc())
    elif sort_by == "risk_high":
        query = query.order_by(
            case((Alert.risk == "HIGH", 1), (Alert.risk == "MEDIUM", 2), else_=3),
            Alert.created_at.desc(),
        )
    elif sort_by == "risk_low":
        query = query.order_by(
            case((Alert.risk == "LOW", 1), (Alert.risk == "MEDIUM", 2), else_=3),
            Alert.created_at.desc(),
        )
    else:  # newest
        sort_by = "newest"
        query = query.order_by(Alert.created_at.desc())

    total_count_filtered = query.count()
    total_pages = max(1, (total_count_filtered + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    alerts = query.offset((page - 1) * per_page).limit(per_page).all()
    hosts = Host.query.order_by(Host.name.asc()).all()

    # Calculate pagination numbers
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

    start_index = (page - 1) * per_page + 1 if total_count_filtered > 0 else 0
    end_index = min(page * per_page, total_count_filtered)

    # Comprehensive counts for KPI cards & status pills
    total_all = Alert.query.count()
    open_count = Alert.query.filter_by(status="OPEN").count()
    resolved_count = Alert.query.filter_by(status="RESOLVED").count()
    high_count = Alert.query.filter_by(risk="HIGH").count()
    medium_count = Alert.query.filter_by(risk="MEDIUM").count()
    low_count = Alert.query.filter_by(risk="LOW").count()

    open_pct = round((open_count / total_all * 100)) if total_all else 0
    high_pct = round((high_count / total_all * 100)) if total_all else 0
    medium_pct = round((medium_count / total_all * 100)) if total_all else 0
    resolved_pct = "<1%" if (0 < resolved_count < (total_all * 0.01)) else (f"{round((resolved_count / total_all * 100))}%" if total_all else "0%")

    return render_template(
        "alerts.html",
        alerts=alerts,
        hosts=hosts,
        status_filter=status_filter,
        risk_filter=risk_filter,
        selected_host_id=host_id,
        alert_type=alert_type,
        search_query=search_query,
        sort_by=sort_by,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_count=total_count_filtered,
        start_index=start_index,
        end_index=end_index,
        page_numbers=page_numbers,
        counts={
            "total": total_all,
            "open": open_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "resolved": resolved_count,
            "open_pct": open_pct,
            "high_pct": high_pct,
            "medium_pct": medium_pct,
            "resolved_pct": resolved_pct,
        },
    )


@alerts_bp.route("/<int:alert_id>")
@login_required
def detail(alert_id: int):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        flash("Alert not found.", "danger")
        return redirect(url_for("alerts.index"))

    return render_template("alert_detail.html", alert=alert)


@alerts_bp.route("/<int:alert_id>/acknowledge", methods=["POST"])
@login_required
def acknowledge(alert_id: int):
    wants_json = request.is_json or "application/json" in request.headers.get("Accept", "")
    alert = db.session.get(Alert, alert_id)
    if not alert:
        if wants_json:
            return jsonify({"error": "Alert not found"}), 404
        flash("Alert not found.", "danger")
        return redirect(url_for("alerts.index"))

    alert.status = "ACKNOWLEDGED"
    db.session.commit()
    logger.info(f"Alert #{alert.id} acknowledged by user.")

    msg = f"Alert #{alert.id} marked as Acknowledged."
    if wants_json:
        return jsonify({"success": True, "status": "ACKNOWLEDGED", "message": msg})
    flash(msg, "info")
    return redirect(request.referrer or url_for("alerts.index"))


@alerts_bp.route("/<int:alert_id>/resolve", methods=["POST"])
@login_required
def resolve(alert_id: int):
    wants_json = request.is_json or "application/json" in request.headers.get("Accept", "")
    alert = db.session.get(Alert, alert_id)
    if not alert:
        if wants_json:
            return jsonify({"error": "Alert not found"}), 404
        flash("Alert not found.", "danger")
        return redirect(url_for("alerts.index"))

    alert.status = "RESOLVED"
    alert.resolved_at = datetime.now(timezone.utc)
    db.session.commit()
    logger.info(f"Alert #{alert.id} marked as Resolved.")

    msg = f"Alert #{alert.id} resolved successfully."
    if wants_json:
        return jsonify({"success": True, "status": "RESOLVED", "message": msg})
    flash(msg, "success")
    return redirect(request.referrer or url_for("alerts.index"))


@alerts_bp.route("/<int:alert_id>/ignore", methods=["POST"])
@login_required
def ignore(alert_id: int):
    wants_json = request.is_json or "application/json" in request.headers.get("Accept", "")
    alert = db.session.get(Alert, alert_id)
    if not alert:
        if wants_json:
            return jsonify({"error": "Alert not found"}), 404
        flash("Alert not found.", "danger")
        return redirect(url_for("alerts.index"))

    alert.status = "IGNORED"
    db.session.commit()
    logger.info(f"Alert #{alert.id} marked as Ignored.")

    msg = f"Alert #{alert.id} ignored."
    if wants_json:
        return jsonify({"success": True, "status": "IGNORED", "message": msg})
    flash(msg, "secondary")
    return redirect(request.referrer or url_for("alerts.index"))
