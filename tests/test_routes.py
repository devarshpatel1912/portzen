import pytest
from app import create_app
from database import db
from database.models import User, Host, MonitoringConfig, PortEvent, PortSnapshot, Alert

class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret-key-12345"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = False
    PORT = 5099
    DEFAULT_SCAN_INTERVAL = 60
    SUPPORTED_INTERVALS = [10, 30, 60, 300]
    LOG_FILE_PATH = "logs/portzen.log"
    LOG_LEVEL = "ERROR"

@pytest.fixture
def app():
    test_app = create_app(TestConfig)

    with test_app.app_context():
        db.create_all()
        # Seed test admin
        user = User(username="testadmin", email="testadmin@example.com")
        user.set_password("correctpassword")
        db.session.add(user)

        # Seed test host
        host = Host(name="Test Host", ip_address="127.0.0.1", operating_system="Linux", is_local=True)
        db.session.add(host)
        db.session.flush()

        config = MonitoringConfig(host_id=host.id, enabled=False, interval_seconds=60)
        db.session.add(config)

        event = PortEvent(
            host_id=host.id,
            port=8080,
            protocol="TCP",
            event_type="NEW_PORT",
            current_state="LISTEN",
            process_name="nginx",
            risk_level="HIGH",
            details="New port opened"
        )
        db.session.add(event)
        db.session.flush()

        alert = Alert(
            host_id=host.id,
            event_id=event.id,
            port=8080,
            protocol="TCP",
            risk="HIGH",
            score=80,
            reason="Test reason",
            status="OPEN",
            process_name="nginx",
        )
        db.session.add(alert)

        snap = PortSnapshot(
            host_id=host.id,
            port=8080,
            protocol="TCP",
            local_address="0.0.0.0",
            state="LISTEN",
            process_name="nginx",
            service="HTTP",
            risk_level="HIGH"
        )
        db.session.add(snap)
        db.session.commit()

        yield test_app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_unauthenticated_redirect(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]

    api_resp = client.get("/api/dashboard/stats")
    assert api_resp.status_code == 401


def test_login_failure(client):
    response = client.post("/auth/login", data={
        "username": "testadmin",
        "password": "wrongpassword"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Invalid credentials" in response.data


def test_login_success(client):
    response = client.post("/auth/login", data={
        "username": "testadmin",
        "password": "correctpassword"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Dashboard" in response.data


def test_dashboard_api_authenticated(client):
    # Log in
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})
    
    # Test API
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    json_data = resp.get_json()
    assert "open_ports" in json_data
    assert "high_risk" in json_data
    assert "active_alerts" in json_data
    assert "timeline" in json_data
    assert json_data["timeline"]["time_range"] == "1h"
    assert len(json_data["timeline"]["labels"]) == 7


def test_dashboard_api_time_ranges(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    timelines = {}
    for tr in ["1h", "6h", "24h", "7d"]:
        resp = client.get(f"/api/dashboard/stats?time_range={tr}&risk_scope=current")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["timeline"]["time_range"] == tr
        assert len(data["timeline"]["labels"]) == 7
        assert len(data["timeline"]["values"]) == 7
        assert data["risk_distribution"]["SCOPE"] == "current"
        timelines[tr] = (data["timeline"]["labels"], data["timeline"]["values"])

    # Verify that labels are distinct across different time ranges
    assert timelines["1h"][0] != timelines["6h"][0]
    assert timelines["6h"][0] != timelines["24h"][0]
    assert timelines["24h"][0] != timelines["7d"][0]


def test_reports_export_csv_and_pdf(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    # Test CSV
    csv_resp = client.get("/reports/export/csv")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["Content-Type"]
    assert b"PortZen Security Analysis Report" in csv_resp.data

    # Test PDF
    pdf_resp = client.get("/reports/export/pdf")
    assert pdf_resp.status_code == 200
    assert "application/pdf" in pdf_resp.headers["Content-Type"]
    assert pdf_resp.data.startswith(b"%PDF")


def test_reports_page_view(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    resp = client.get("/reports/")
    assert resp.status_code == 200
    # Header & navigation
    assert b"Back to Reports" in resp.data
    assert b"Security Analysis Report" in resp.data
    assert b"Executive overview of system exposure" in resp.data
    assert b"btn-report-export-csv" in resp.data
    assert b"btn-report-export-pdf" in resp.data

    # Filter card & Host banner
    assert b"Target Host" in resp.data
    assert b"Audit Timeframe" in resp.data
    assert b"Update Report" in resp.data
    assert b"report-host-card" in resp.data
    assert b"Report generated" in resp.data

    # 5 KPI cards
    assert b"Open Ports" in resp.data
    assert b"New Ports" in resp.data
    assert b"Closed Ports" in resp.data
    assert b"High Risk" in resp.data
    assert b"Medium Risk" in resp.data

    # Risk Distribution Bar
    assert b"Risk Distribution" in resp.data
    assert b"report-multi-bar" in resp.data

    # Two columns: Recommendations & Top Risky Services
    assert b"Security Findings &amp; Recommendations" in resp.data or b"Security Findings & Recommendations" in resp.data
    assert b"Top Risky Services" in resp.data
    assert b"report-risky-table" in resp.data


def test_processes_page(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    for route in ["/processes", "/ports/processes"]:
        resp = client.get(route)
        assert resp.status_code == 200
        assert b"Listening Processes" in resp.data
        assert b"Total Processes" in resp.data
        assert b"Total Listening Ports" in resp.data
        assert b"Medium Risk Processes" in resp.data
        assert b"High Risk Processes" in resp.data

    # Test filtering params
    filter_resp = client.get("/processes?risk_level=HIGH&min_sockets=1&q=test")
    assert filter_resp.status_code == 200


def test_history_page(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    resp = client.get("/history/")
    assert resp.status_code == 200
    assert b"Port History Log" in resp.data
    assert b"Total Events" in resp.data
    assert b"New Ports" in resp.data
    assert b"Closed Ports" in resp.data
    assert b"Process Changes" in resp.data
    # Test alert-style filter bar elements
    assert b"alert-filter-bar" in resp.data
    assert b"filter-select-soc" in resp.data
    assert b"btn-clear-filters" in resp.data

    # Test column toggle dropdown
    assert b"col-toggle-checkbox" in resp.data
    assert b"data-bs-auto-close=\"outside\"" in resp.data
    assert b"btnResetColumns" in resp.data
    assert b"checked disabled" not in resp.data

    # Test three-dots action dropdown
    assert b"btn-history-menu dropdown-toggle no-chevron" in resp.data
    assert b"Filter by Port" in resp.data

    # Test filtering and sorting
    resp_filter = client.get("/history/?event=NEW_PORT&risk=HIGH&sort=timestamp_asc&page=1&per_page=10")
    assert resp_filter.status_code == 200


def test_history_export_csv(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    resp = client.get("/history/export")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("Content-Type", "")
    assert b"Timestamp (UTC),Host Name,IP Address,Port,Protocol,Event Type" in resp.data


def test_settings_page_view(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    resp = client.get("/settings/")
    assert resp.status_code == 200
    assert b"Settings" in resp.data
    assert b"Monitoring Policy" in resp.data
    assert b"Alert Notifications" in resp.data
    assert b"Account Security" in resp.data
    assert b"System Operational Log" in resp.data
    assert b"portzen.log" in resp.data
    assert b"Password Requirements" in resp.data
    assert b"Reset to Default" in resp.data


def test_settings_update_monitoring(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    resp = client.post("/settings/monitoring", data={
        "interval_seconds": "30",
        "auto_start": "on",
        "scan_closed_ports": "on",
        "monitoring_engine": "local"
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Monitoring settings updated successfully" in resp.data


def test_settings_update_notifications(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    resp = client.post("/settings/notifications", data={
        "dashboard_alerts": "on",
        "high_risk_alerts": "on"
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Notification preferences updated successfully" in resp.data


def test_settings_clear_log_ajax(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    resp = client.post("/settings/clear-log", headers={"X-Requested-With": "XMLHttpRequest"})
    assert resp.status_code == 200
    json_data = resp.get_json()
    assert json_data["success"] is True


def test_settings_reset_defaults(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    resp = client.post("/settings/reset", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Settings successfully restored to default configuration" in resp.data


def test_ports_page_and_search(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    # Test default ports page
    resp = client.get("/ports")
    assert resp.status_code == 200
    assert b"Discovered Ports" in resp.data
    assert b"Total Open Ports" in resp.data
    assert b"Unregistered Ports" in resp.data

    # Test search by search parameter
    resp_search = client.get("/ports?search=8080")
    assert resp_search.status_code == 200
    assert b"8080" in resp_search.data

    # Test search by q parameter (from dashboard inspect links)
    resp_q = client.get("/ports?q=8080")
    assert resp_q.status_code == 200
    assert b"8080" in resp_q.data


def test_alert_actions(client):
    client.post("/auth/login", data={"username": "testadmin", "password": "correctpassword"})

    # Test acknowledge
    resp_ack = client.post("/alerts/1/acknowledge", headers={"Accept": "application/json"})
    assert resp_ack.status_code == 200
    assert resp_ack.get_json()["success"] is True
    assert resp_ack.get_json()["status"] == "ACKNOWLEDGED"

    # Test resolve
    resp_res = client.post("/alerts/1/resolve", headers={"Accept": "application/json"})
    assert resp_res.status_code == 200
    assert resp_res.get_json()["success"] is True
    assert resp_res.get_json()["status"] == "RESOLVED"

    # Test ignore
    resp_ign = client.post("/alerts/1/ignore", headers={"Accept": "application/json"})
    assert resp_ign.status_code == 200
    assert resp_ign.get_json()["success"] is True
    assert resp_ign.get_json()["status"] == "IGNORED"



