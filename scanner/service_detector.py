"""Service Detector Module
Provides lookup of well-known port numbers to network services and categories.
"""

KNOWN_SERVICES = {
    # File & Remote Admin
    20: {"service": "FTP-Data", "category": "File Transfer", "sensitive": True},
    21: {"service": "FTP", "category": "File Transfer", "sensitive": True},
    22: {"service": "SSH", "category": "Remote Administration", "sensitive": True},
    23: {"service": "Telnet", "category": "Remote Administration (Insecure)", "sensitive": True},
    69: {"service": "TFTP", "category": "File Transfer", "sensitive": True},
    3389: {"service": "RDP", "category": "Remote Administration", "sensitive": True},
    5900: {"service": "VNC", "category": "Remote Administration", "sensitive": True},
    5901: {"service": "VNC-1", "category": "Remote Administration", "sensitive": True},

    # Web & Proxies
    80: {"service": "HTTP", "category": "Web Service", "sensitive": False},
    443: {"service": "HTTPS", "category": "Web Service", "sensitive": False},
    8000: {"service": "HTTP-Dev", "category": "Web Service", "sensitive": False},
    8080: {"service": "HTTP-Alt", "category": "Web Service", "sensitive": False},
    8443: {"service": "HTTPS-Alt", "category": "Web Service", "sensitive": False},
    8888: {"service": "HTTP-Alt / Jupyter", "category": "Web Service", "sensitive": False},
    3000: {"service": "Web App / Dev", "category": "Web Service", "sensitive": False},
    5000: {"service": "Flask / Web Dev", "category": "Web Service", "sensitive": False},

    # Databases
    1433: {"service": "MSSQL", "category": "Database", "sensitive": True},
    1521: {"service": "Oracle", "category": "Database", "sensitive": True},
    3306: {"service": "MySQL", "category": "Database", "sensitive": True},
    5432: {"service": "PostgreSQL", "category": "Database", "sensitive": True},
    6379: {"service": "Redis", "category": "Database / Cache", "sensitive": True},
    9200: {"service": "Elasticsearch", "category": "Database / Search", "sensitive": True},
    27017: {"service": "MongoDB", "category": "Database", "sensitive": True},

    # Windows / SMB / RPC
    135: {"service": "MS-RPC", "category": "Windows Infrastructure", "sensitive": True},
    137: {"service": "NetBIOS-NS", "category": "Windows Infrastructure", "sensitive": True},
    138: {"service": "NetBIOS-DGM", "category": "Windows Infrastructure", "sensitive": True},
    139: {"service": "NetBIOS-SSN", "category": "Windows Infrastructure", "sensitive": True},
    445: {"service": "Microsoft-DS / SMB", "category": "File Sharing", "sensitive": True},

    # Mail
    25: {"service": "SMTP", "category": "Mail", "sensitive": False},
    110: {"service": "POP3", "category": "Mail", "sensitive": False},
    143: {"service": "IMAP", "category": "Mail", "sensitive": False},
    465: {"service": "SMTPS", "category": "Mail", "sensitive": False},
    587: {"service": "SMTP-Submission", "category": "Mail", "sensitive": False},
    993: {"service": "IMAPS", "category": "Mail", "sensitive": False},
    995: {"service": "POP3S", "category": "Mail", "sensitive": False},

    # Network Infrastructure
    53: {"service": "DNS", "category": "Network Infrastructure", "sensitive": False},
    67: {"service": "DHCP-Server", "category": "Network Infrastructure", "sensitive": False},
    68: {"service": "DHCP-Client", "category": "Network Infrastructure", "sensitive": False},
    123: {"service": "NTP", "category": "Network Infrastructure", "sensitive": False},
    161: {"service": "SNMP", "category": "Network Monitoring", "sensitive": True},
    162: {"service": "SNMP-Trap", "category": "Network Monitoring", "sensitive": True},
}


def detect_service(port: int, protocol: str = "TCP") -> dict:
    """Identify the service name, category, and sensitivity level for a given port."""
    info = KNOWN_SERVICES.get(port)
    if info:
        return {
            "service": info["service"],
            "category": info["category"],
            "sensitive": info["sensitive"],
            "is_known": True,
        }

    # Dynamic heuristics
    if 49152 <= port <= 65535:
        category = "Dynamic / Ephemeral"
        service = "Dynamic RPC / Private"
    else:
        category = "Unregistered Service"
        service = "Unknown"

    return {
        "service": service,
        "category": category,
        "sensitive": False,
        "is_known": False,
    }
