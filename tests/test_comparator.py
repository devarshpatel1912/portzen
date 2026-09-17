import pytest
from monitoring.comparator import compare_port_states

def test_comparator_new_port():
    prev = [
        {"port": 22, "protocol": "TCP", "process": "sshd", "state": "LISTEN", "local_address": "0.0.0.0", "service": "SSH"},
        {"port": 80, "protocol": "TCP", "process": "nginx", "state": "LISTEN", "local_address": "0.0.0.0", "service": "HTTP"},
        {"port": 443, "protocol": "TCP", "process": "nginx", "state": "LISTEN", "local_address": "0.0.0.0", "service": "HTTPS"},
    ]
    curr = [
        {"port": 22, "protocol": "TCP", "process": "sshd", "state": "LISTEN", "local_address": "0.0.0.0", "service": "SSH"},
        {"port": 80, "protocol": "TCP", "process": "nginx", "state": "LISTEN", "local_address": "0.0.0.0", "service": "HTTP"},
        {"port": 443, "protocol": "TCP", "process": "nginx", "state": "LISTEN", "local_address": "0.0.0.0", "service": "HTTPS"},
        {"port": 8080, "protocol": "TCP", "process": "python", "state": "LISTEN", "local_address": "0.0.0.0", "service": "HTTP-Alt"},
    ]
    baseline = prev

    events = compare_port_states(curr, prev, baseline)
    new_port_events = [e for e in events if e["event_type"] == "NEW_PORT"]

    assert len(new_port_events) == 1
    assert new_port_events[0]["port"] == 8080
    assert new_port_events[0]["is_in_baseline"] is False


def test_comparator_closed_port():
    prev = [
        {"port": 22, "protocol": "TCP", "process": "sshd", "state": "LISTEN", "local_address": "0.0.0.0", "service": "SSH"},
        {"port": 8080, "protocol": "TCP", "process": "python", "state": "LISTEN", "local_address": "0.0.0.0", "service": "HTTP-Alt"},
    ]
    curr = [
        {"port": 22, "protocol": "TCP", "process": "sshd", "state": "LISTEN", "local_address": "0.0.0.0", "service": "SSH"},
    ]
    baseline = prev

    events = compare_port_states(curr, prev, baseline)
    closed_events = [e for e in events if e["event_type"] == "PORT_CLOSED"]

    assert len(closed_events) == 1
    assert closed_events[0]["port"] == 8080
    assert closed_events[0]["current_state"] == "CLOSED"


def test_comparator_process_changed():
    prev = [
        {"port": 8080, "protocol": "TCP", "process": "python", "state": "LISTEN", "local_address": "0.0.0.0", "service": "HTTP-Alt"},
    ]
    curr = [
        {"port": 8080, "protocol": "TCP", "process": "java", "state": "LISTEN", "local_address": "0.0.0.0", "service": "HTTP-Alt"},
    ]
    baseline = prev

    events = compare_port_states(curr, prev, baseline)
    proc_events = [e for e in events if e["event_type"] == "PROCESS_CHANGED"]

    assert len(proc_events) == 1
    assert proc_events[0]["port"] == 8080
    assert proc_events[0]["process_name"] == "java"
