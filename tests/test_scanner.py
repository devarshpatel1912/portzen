import pytest
from scanner.port_scanner import scan_local_ports, scan_remote_ports, is_network_exposed
from scanner.service_detector import detect_service
from scanner.process_detector import get_process_info

def test_service_detector_known_services():
    http_svc = detect_service(80, "TCP")
    assert http_svc["service"] == "HTTP"
    assert http_svc["is_known"] is True

    mysql_svc = detect_service(3306, "TCP")
    assert mysql_svc["service"] == "MySQL"
    assert mysql_svc["sensitive"] is True

    ssh_svc = detect_service(22, "TCP")
    assert ssh_svc["service"] == "SSH"
    assert ssh_svc["sensitive"] is True

    unknown_svc = detect_service(41234, "TCP")
    assert unknown_svc["is_known"] is False


def test_is_network_exposed():
    assert is_network_exposed("0.0.0.0") is True
    assert is_network_exposed("::") is True
    assert is_network_exposed("192.168.1.50") is True
    assert is_network_exposed("127.0.0.1") is False
    assert is_network_exposed("localhost") is False
    assert is_network_exposed("::1") is False


def test_process_detector_safe_handling():
    # Test with invalid / None PID
    res_none = get_process_info(None)
    assert res_none["process_name"] == "Unknown"
    assert res_none["accessible"] is False

    # Test with negative PID
    res_neg = get_process_info(-1)
    assert res_neg["accessible"] is False


def test_scan_local_ports_structure():
    ports = scan_local_ports()
    assert isinstance(ports, list)
    if ports:
        item = ports[0]
        assert "port" in item
        assert "protocol" in item
        assert "local_address" in item
        assert "state" in item
        assert "process" in item
        assert "service" in item
        assert isinstance(item["port"], int)
        assert item["protocol"] in ["TCP", "UDP"]


def test_scan_remote_ports():
    # Scanning loopback with high nonexistent ports with short timeout
    results = scan_remote_ports("127.0.0.1", ports=[59998, 59999], timeout=0.1)
    assert isinstance(results, list)
    # Empty ip should return empty list
    assert scan_remote_ports("") == []

