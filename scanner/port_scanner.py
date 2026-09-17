"""Port Scanner Module
Performs non-intrusive listening port discovery on the authorized host using psutil.
"""

import socket
import psutil
from concurrent.futures import ThreadPoolExecutor
from scanner.process_detector import get_process_info
from scanner.service_detector import detect_service, KNOWN_SERVICES
from config import logger

def is_network_exposed(address: str) -> bool:
    """Return True if local address binds to all network interfaces or an external IP."""
    if not address:
        return True
    addr_str = address.strip().lower()
    if addr_str in ["127.0.0.1", "::1", "localhost"]:
        return False
    return True


def scan_local_ports() -> list[dict]:
    """Discover all currently listening TCP ports and active UDP endpoints on the local system.
    
    Returns structured list of dictionaries:
        [
            {
                "port": 22,
                "protocol": "TCP",
                "local_address": "0.0.0.0",
                "state": "LISTEN",
                "pid": 821,
                "process": "sshd",
                "service": "SSH",
                "category": "Remote Administration",
                "sensitive": True,
                "is_network_facing": True
            }, ...
        ]
    """
    logger.info("Starting local port scan...")
    discovered = []
    seen_keys = set()

    try:
        # psutil.net_connections returns all system socket connections
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        logger.warning("Access denied when calling psutil.net_connections(kind='inet'). Retrying with tcp...")
        try:
            connections = psutil.net_connections(kind="tcp")
        except Exception as e:
            logger.error(f"Failed to scan network connections: {e}")
            return []
    except Exception as e:
        logger.error(f"Failed to scan network connections: {e}")
        return []

    for conn in connections:
        # Identify protocol
        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

        # For TCP, we only care about listening ports (server sockets)
        if protocol == "TCP" and conn.status != psutil.CONN_LISTEN:
            continue

        # For UDP, socket status is usually NONE or empty, but must have a local port
        if not conn.laddr:
            continue

        l_ip = conn.laddr.ip if hasattr(conn.laddr, "ip") else str(conn.laddr[0])
        l_port = conn.laddr.port if hasattr(conn.laddr, "port") else int(conn.laddr[1])

        # Avoid duplicate (port, protocol, ip)
        unique_key = (l_port, protocol, l_ip)
        if unique_key in seen_keys:
            continue
        seen_keys.add(unique_key)

        state = "LISTEN" if protocol == "TCP" else "ACTIVE"

        # Resolve process details
        proc_data = get_process_info(conn.pid)
        service_data = detect_service(l_port, protocol)
        network_facing = is_network_exposed(l_ip)

        item = {
            "port": l_port,
            "protocol": protocol,
            "local_address": l_ip,
            "state": state,
            "pid": conn.pid,
            "process": proc_data["process_name"],
            "process_exe": proc_data.get("exe"),
            "process_user": proc_data.get("username"),
            "process_cmdline": proc_data.get("cmdline"),
            "service": service_data["service"],
            "category": service_data["category"],
            "sensitive": service_data["sensitive"],
            "is_network_facing": network_facing,
        }
        discovered.append(item)

    # Sort primarily by port number, then protocol
    discovered.sort(key=lambda x: (x["port"], x["protocol"], x["local_address"]))
    logger.info(f"Local port scan completed. Discovered {len(discovered)} listening endpoints.")
    return discovered


def scan_remote_ports(ip_address: str, ports: list[int] = None, timeout: float = 0.5) -> list[dict]:
    """Scan common or specified TCP ports on an authorized remote host.
    
    Uses concurrent socket connections with short timeouts.
    """
    if not ip_address:
        return []

    logger.info(f"Starting remote port scan for host {ip_address}...")
    if not ports:
        # Default to standard known service ports
        ports = sorted(list(KNOWN_SERVICES.keys()))

    discovered = []

    def check_port(port: int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            result = s.connect_ex((ip_address, port))
            if result == 0:
                service_data = detect_service(port, "TCP")
                return {
                    "port": port,
                    "protocol": "TCP",
                    "local_address": ip_address,
                    "state": "LISTEN",
                    "pid": None,
                    "process": "Remote Service",
                    "process_exe": None,
                    "process_user": None,
                    "process_cmdline": "",
                    "service": service_data["service"],
                    "category": service_data["category"],
                    "sensitive": service_data["sensitive"],
                    "is_network_facing": True,
                }
        except Exception:
            pass
        finally:
            s.close()
        return None

    with ThreadPoolExecutor(max_workers=min(30, len(ports))) as executor:
        results = executor.map(check_port, ports)
        for res in results:
            if res:
                discovered.append(res)

    discovered.sort(key=lambda x: x["port"])
    logger.info(f"Remote scan for {ip_address} completed. Found {len(discovered)} open ports.")
    return discovered

