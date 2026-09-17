from flask import Blueprint

dashboard_bp = Blueprint("dashboard", __name__)
hosts_bp = Blueprint("hosts", __name__, url_prefix="/hosts")
ports_bp = Blueprint("ports", __name__)
alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")
history_bp = Blueprint("history", __name__, url_prefix="/history")
reports_bp = Blueprint("reports", __name__, url_prefix="/reports")
settings_bp = Blueprint("settings", __name__, url_prefix="/settings")

from routes import dashboard, hosts, ports, alerts, history, reports, settings
