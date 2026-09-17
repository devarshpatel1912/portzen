import pytest
from security.risk_engine import evaluate_port_risk

def test_risk_expected_baseline_localhost():
    res = evaluate_port_risk(
        port=80,
        protocol="TCP",
        local_address="127.0.0.1",
        service="HTTP",
        process_name="nginx",
        is_in_baseline=True,
        event_type="NO_CHANGE",
    )
    assert res["risk"] == "LOW"
    assert res["score"] < 35
    assert any("matches authorized baseline" in r for r in res["reasons"])


def test_risk_unexpected_service():
    res = evaluate_port_risk(
        port=8080,
        protocol="TCP",
        local_address="0.0.0.0",
        service="Unknown",
        process_name="custom_daemon",
        is_in_baseline=False,
        event_type="NEW_PORT",
    )
    assert res["risk"] in ["MEDIUM", "HIGH"]
    assert res["score"] >= 35
    assert any("not present in the approved baseline" in r for r in res["reasons"])


def test_risk_network_facing_database():
    res = evaluate_port_risk(
        port=3306,
        protocol="TCP",
        local_address="0.0.0.0",
        service="MySQL",
        process_name="mysqld",
        is_in_baseline=False,
        event_type="NEW_PORT",
    )
    assert res["risk"] == "HIGH"
    assert res["score"] >= 65
    assert any("Database service (MySQL Database) is exposed" in r for r in res["reasons"])
    assert any("Restrict database listening address" in r for r in res["recommendations"])


def test_risk_insecure_telnet():
    res = evaluate_port_risk(
        port=23,
        protocol="TCP",
        local_address="0.0.0.0",
        service="Telnet",
        process_name="telnetd",
        is_in_baseline=False,
        event_type="NEW_PORT",
    )
    assert res["risk"] == "HIGH"
    assert any("Insecure protocol detected" in r for r in res["reasons"])
