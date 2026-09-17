"""Security Rules Module
Defines transparent, deterministic security rules for evaluating network port risks.
"""

INSECURE_PROTOCOLS = {
    23: {
        "name": "Telnet",
        "description": "Cleartext administrative protocol with no cryptographic confidentiality or integrity.",
        "remediation": "Disable Telnet and replace with SSH (Port 22).",
    },
    21: {
        "name": "FTP",
        "description": "Unencrypted file transfer protocol transmits credentials in plaintext.",
        "remediation": "Migrate to SFTP (Port 22) or FTPS with enforced TLS.",
    },
    69: {
        "name": "TFTP",
        "description": "Trivial File Transfer Protocol lacks authentication.",
        "remediation": "Restrict TFTP strictly to authorized provisioning subnets or terminate service.",
    },
}

DATABASE_PORTS = {
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    6379: "Redis In-Memory Store",
    9200: "Elasticsearch Search Engine",
    27017: "MongoDB NoSQL Database",
}

ADMIN_PORTS = {
    22: "SSH Remote Shell",
    3389: "Microsoft Remote Desktop (RDP)",
    5900: "VNC Remote Desktop",
    5901: "VNC Remote Desktop Display :1",
}

WINDOWS_INFRASTRUCTURE = {
    135: "Microsoft RPC Endpoint Mapper",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    445: "Microsoft SMB File Sharing",
}
