# PortZen — Real-Time Port Monitoring & Security Analysis Platform

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/Security-SOC%20Ready-green.svg)]()

**PortZen** is a professional, modular cybersecurity web platform designed for continuous network port discovery, baseline compliance auditing, real-time socket change detection, process attribution, and transparent security risk analysis.

Unlike simple, point-in-time port scanner wrappers, PortZen is architected as an **active continuous monitoring and change detection engine**. It monitors authorized systems, maintains approved baselines, flags unauthorized listening sockets or swapped processes, calculates transparent rule-based risk scores, and equips analysts with an intuitive SOC-style triage console.

---

## Key Features

1. **Continuous Port Discovery & Inspection**: Non-intrusive local listening socket discovery (TCP and UDP) powered by `psutil`.
2. **Process Attribution**: Identifies the binary name, PID, command line, and user context bound to each port with graceful elevation fallback.
3. **Approved Baseline System**: Snapshot and enforce approved network services. Ports outside the baseline trigger policy deviation alerts.
4. **State Transition Engine**: Compares successive snapshots to detect:
   - `NEW_PORT`: Unauthorized or unexpected listening port appeared.
   - `PORT_CLOSED`: Port ceased listening.
   - `PROCESS_CHANGED`: Underlying executable or PID binding changed on an active port.
   - `STATE_CHANGED`: State transitions.
5. **Explainable Security Risk Engine**: Transparent, deterministic rules (LOW, MEDIUM, HIGH) evaluating baseline deviation, network-facing bindings (`0.0.0.0` vs `127.0.0.1`), insecure protocols (Telnet, unencrypted FTP), database exposures (MySQL, PostgreSQL, Redis, MongoDB), and remote administrative services (RDP, VNC, SSH).
6. **SOC Alert Triage Queue**: Manage incidents through full lifecycle states: `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `IGNORED`.
7. **Interactive Dashboard**: Real-time metrics, Chart.js Port Exposure Timeline, and Risk Distribution doughnut chart.
8. **Compliance Reporting**: Executive security summary with instant **CSV Export** and print-ready **PDF Export** using ReportLab.
9. **Authentication & Session Security**: Secure password hashing with Werkzeug, session fixation protection, and `@login_required` decorators guarding all sensitive endpoints.
10. **Background Monitoring Scheduler**: Thread-safe daemon scheduler supporting configurable continuous scan intervals (10s, 30s, 60s, 300s).

---

## Architecture & Technology Stack

```
PortZen/
├── app.py                     # Flask application factory & background scheduler lifecycle
├── config.py                  # Environment settings, SQLite DB URI, and logging configuration
├── requirements.txt           # Verified project dependencies
├── .env.example               # Environment variables template
│
├── database/
│   ├── __init__.py            # SQLAlchemy database instance
│   └── models.py              # User, Host, PortSnapshot, BaselinePort, PortEvent, Alert, MonitoringConfig
│
├── auth/
│   ├── __init__.py            # Authentication blueprint
│   └── routes.py              # Login, Logout, and session protection
│
├── scanner/
│   ├── __init__.py
│   ├── port_scanner.py        # psutil socket discovery with graceful error handling
│   ├── process_detector.py    # Process PID, exe, command line, and user attribution
│   └── service_detector.py    # Known IANA service recognition and sensitivity catalog
│
├── monitoring/
│   ├── __init__.py
│   ├── comparator.py          # State comparison & transition event generator
│   ├── monitor.py             # Single-cycle scan orchestrator & alert pipeline
│   └── scheduler.py           # Thread-safe background monitoring scheduler
│
├── security/
│   ├── __init__.py
│   ├── rules.py               # Deterministic rule catalog and risk boundaries
│   └── risk_engine.py         # Transparent scoring engine (score 0-100, reasons, recommendations)
│
├── routes/
│   ├── __init__.py
│   ├── dashboard.py           # Dashboard stats API & metrics view
│   ├── hosts.py               # Host management, baseline creation, and on-demand scans
│   ├── ports.py               # Port discovery table, detailed inspection, and processes view
│   ├── alerts.py              # SOC alert queue & incident triage actions
│   ├── history.py             # Audit event history log with multi-field filtering
│   ├── reports.py             # Security reports, CSV export, and PDF generation
│   └── settings.py            # Monitoring intervals, password updates, and operational log preview
│
├── templates/                 # Reusable Jinja2 templates (SOC slate dark theme)
│   ├── base.html              # Fixed sidebar, top navbar, status indicators, and toasts
│   ├── login.html             # Centered login card with password visibility toggle
│   ├── dashboard.html         # Live summary cards, Chart.js graphs, and recent events
│   ├── hosts.html             # Host management card grid & Add Host modal
│   ├── host_detail.html       # Individual host monitoring controls, baseline view, snapshot
│   ├── ports.html             # Filterable ports table with risk badges and baseline status
│   ├── port_detail.html       # Deep port inspection view with remediation guidance
│   ├── processes.html         # Listening processes overview grouped by PID
│   ├── alerts.html            # SOC alert queue with status filters (OPEN, ACKNOWLEDGED, etc.)
│   ├── alert_detail.html      # Alert investigation view with technical rationale
│   ├── history.html           # Immutable audit timeline
│   ├── reports.html           # Security posture report, CSV export, and PDF export
│   └── settings.html          # Scan interval policies, account security, and log terminal
│
├── static/
│   ├── css/style.css          # Custom SOC stylesheet (slate sidebar, clean cards, risk badges)
│   └── js/
│       ├── dashboard.js       # Live chart initialization and asynchronous polling
│       ├── monitoring.js      # On-demand scan, baseline creation, and monitoring toggles
│       └── alerts.js          # Asynchronous alert triage actions
│
├── logs/
│   └── portzen.log            # Security and daemon execution logs
│
├── scripts/
│   ├── init_db.py             # Database creation & default local host seeding
│   └── create_admin.py        # Administrator seeding script
│
└── tests/
    ├── test_scanner.py        # Unit tests for socket and process inspection
    ├── test_comparator.py     # Unit tests for NEW_PORT, CLOSED, and PROCESS_CHANGED events
    ├── test_risk_engine.py    # Unit tests for transparent risk scoring
    └── test_routes.py         # Integration tests for auth, routes, and exports
```

---

## Installation & Setup

### 1. Prerequisites
- Python 3.11+ (Python 3.14 compatible)
- Windows, Linux, or macOS

### 2. Create Virtual Environment
```bash
python -m venv venv
```

Activate the environment:
- **Windows (PowerShell)**:
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **Linux / macOS**:
  ```bash
  source venv/bin/activate
  ```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment
Copy `.env.example` to `.env` (optional; safe defaults are provided):
```bash
cp .env.example .env
```

### 5. Initialize Database & Seed Administrator
Initialize tables and register the default local machine:
```bash
python scripts/init_db.py
```

Seed the default development administrator:
```bash
python scripts/create_admin.py --username admin --password admin123
```

---

## Running the Application

Start PortZen with:
```bash
python app.py
```

Access the web interface at:
```text
http://127.0.0.1:5100
```

Default credentials:
- **Username**: `admin`
- **Password**: `admin123`

---

## Standard Workflow

```text
LOGIN  ──>  DASHBOARD  ──>  SELECT HOST  ──>  SCAN NOW
                                                  │
                                                  ▼
                                           CREATE BASELINE
                                                  │
                                                  ▼
                                           START MONITORING
                                                  │
                  ┌───────────────────────────────┴───────────────────────────────┐
                  ▼                                                               ▼
            [NO CHANGES]                                                  [CHANGE DETECTED]
      Continue routine scans                                                      │
                                                                                  ▼
                                                                          SECURITY ANALYSIS
                                                                  (Risk Engine evaluates exposure)
                                                                                  │
                                                                                  ▼
                                                                            CREATE ALERT
                                                                                  │
                                                                                  ▼
                                                                          ANALYST TRIAGE
                                                              (Investigate / Acknowledge / Resolve)
                                                                                  │
                                                                                  ▼
                                                                          HISTORY / REPORT
                                                                       (Export CSV or PDF)
```

---

## Running Automated Tests

Run the full test suite with `pytest`:
```bash
python -m pytest -v
```

Expected output:
```text
============================= test session starts =============================
tests/test_comparator.py::test_comparator_new_port PASSED                [  6%]
tests/test_comparator.py::test_comparator_closed_port PASSED             [ 12%]
tests/test_comparator.py::test_comparator_process_changed PASSED         [ 18%]
tests/test_risk_engine.py::test_risk_expected_baseline_localhost PASSED  [ 25%]
tests/test_risk_engine.py::test_risk_unexpected_service PASSED           [ 31%]
tests/test_risk_engine.py::test_risk_network_facing_database PASSED      [ 37%]
tests/test_risk_engine.py::test_risk_insecure_telnet PASSED              [ 43%]
tests/test_routes.py::test_unauthenticated_redirect PASSED               [ 50%]
tests/test_routes.py::test_login_failure PASSED                          [ 56%]
tests/test_routes.py::test_login_success PASSED                          [ 62%]
tests/test_routes.py::test_dashboard_api_authenticated PASSED            [ 68%]
tests/test_routes.py::test_reports_export_csv_and_pdf PASSED             [ 75%]
tests/test_scanner.py::test_service_detector_known_services PASSED       [ 81%]
tests/test_scanner.py::test_is_network_exposed PASSED                    [ 87%]
tests/test_scanner.py::test_process_detector_safe_handling PASSED        [ 93%]
tests/test_scanner.py::test_scan_local_ports_structure PASSED            [100%]
============================= 16 passed in 4.71s ==============================
```

---

## Security Considerations

1. **Authorization Boundaries**: PortZen strictly monitors authorized local systems. Unauthorized network scanning of external IP ranges without explicit written consent is strictly prohibited.
2. **Elevation & Permissions**: Socket discovery via `psutil` runs in user context. To inspect system-level processes owned by `SYSTEM` or root, run the terminal session with elevated privileges. If elevated information is unavailable, PortZen gracefully logs `"Process information unavailable (Elevated permissions required)"` without crashing.
3. **Password Security**: Passwords are cryptographically hashed using PBKDF2 with HMAC-SHA256 via Werkzeug. Plaintext credentials are never persisted.
4. **Injection Safety**: Database access is fully parameterized using SQLAlchemy ORM. User inputs are never passed into raw shell command execution.

---

## Limitations & Future Roadmap

- **Multi-Node Agent Architecture**: Future iterations can deploy lightweight gRPC/HTTPS telemetry agents on remote servers to feed events into a centralized PortZen server.
- **Process Memory Hash Verification**: Hash executable binaries (SHA-256) upon socket binding to detect process hollowing or malicious binary substitution.
- **Webhook Integration**: Stream critical alerts to Slack, Microsoft Teams, or SIEM endpoints (Splunk, Elastic).
