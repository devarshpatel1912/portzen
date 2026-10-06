import atexit
from flask import Flask, render_template, session
from config import Config, logger
from database import db
from database.models import User, Alert, Host
from auth import auth_bp
from routes import (
    dashboard_bp,
    hosts_bp,
    ports_bp,
    alerts_bp,
    history_bp,
    reports_bp,
    settings_bp,
)
from monitoring.scheduler import scheduler

def create_app(config_class=Config):
    """Application factory for PortZen."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(hosts_bp)
    app.register_blueprint(ports_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)

    @app.route("/login")
    def login_shortcut():
        from flask import redirect, url_for
        return redirect(url_for("auth.login"))

    # Global template context processor
    @app.context_processor
    def inject_global_data():
        current_user = None
        open_alerts_count = 0
        is_global_monitoring = False
        if "user_id" in session:
            current_user = db.session.get(User, session["user_id"])
            open_alerts_count = Alert.query.filter_by(status="OPEN").count()
            # Check if any host has active monitoring
            local_host = Host.query.filter_by(is_local=True).first()
            if local_host and local_host.monitoring_config and local_host.monitoring_config.enabled:
                is_global_monitoring = True

        return {
            "current_user": current_user,
            "global_open_alerts_count": open_alerts_count,
            "is_global_monitoring": is_global_monitoring,
        }

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("base.html", custom_error="404 - Requested resource or page was not found."), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        logger.error(f"Internal server error: {e}", exc_info=True)
        return render_template("base.html", custom_error="500 - An unexpected internal error occurred."), 500

    # Initialize and start background scheduler
    with app.app_context():
        # Ensure database tables exist
        db.create_all()

    # Start background scheduler if not in testing mode
    if not app.config.get("TESTING"):
        scheduler.init_app(app)
        scheduler.start()
        atexit.register(scheduler.stop)

    return app

app = create_app()

if __name__ == "__main__":
    port = Config.PORT
    logger.info(f"Starting PortZen Web Application on http://127.0.0.1:{port}")
    # Set use_reloader=False when running background thread scheduler to avoid duplicate scheduler threads
    app.run(host="127.0.0.1", port=port, debug=True, use_reloader=False)
