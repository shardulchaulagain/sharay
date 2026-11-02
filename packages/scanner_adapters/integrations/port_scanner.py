"""High-speed native multi-port scanner and service banner grabber.

Performs concurrent TCP connect scanning and banner extraction across top
network service ports directly over the approved destination IP, with zero
external tool dependencies.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import socket
import ssl
import time
from datetime import UTC, datetime
from typing import Any

TOP_PORTS = [
    21,  # FTP
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS
    80,  # HTTP
    110,  # POP3
    111,  # RPC
    135,  # MSRPC
    139,  # NetBIOS
    143,  # IMAP
    443,  # HTTPS
    445,  # SMB
    993,  # IMAPS
    995,  # POP3S
    1433,  # MSSQL
    1521,  # Oracle
    1723,  # PPTP
    2049,  # NFS
    2082,  # cPanel
    2083,  # cPanel SSL
    3000,  # Node.js / React Dev
    3306,  # MySQL
    3389,  # RDP
    5000,  # Flask / Docker
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8000,  # Common Dev Web
    8080,  # HTTP Alt
    8443,  # HTTPS Alt
    8888,  # Jupyter / Alt Web
    9000,  # SonarQube / PHP-FPM
    9200,  # Elasticsearch
    11211,  # Memcached
    27017,  # MongoDB
]

SERVICE_NAMES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    3000: "http-dev",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "upnp-http",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "cslistener",
    9200: "wap-wsp",
    11211: "memcached",
    27017: "mongodb",
}

DANGEROUS_PORTS = {
    21: ("Cleartext FTP Protocol Exposed", "low", "CWE-319", "Unencrypted credentials transmitted over FTP."),
    23: (
        "Insecure Telnet Protocol Exposed",
        "critical",
        "CWE-319",
        "Telnet sends credentials in plain cleartext.",
    ),
    445: (
        "Exposed SMB / File Sharing Service",
        "high",
        "CWE-200",
        "SMB exposed to the public internet enables lateral movement and relay attacks.",
    ),
    1433: (
        "Exposed Microsoft SQL Server Database",
        "high",
        "CWE-200",
        "Direct database listener exposed to public network.",
    ),
    3306: ("Exposed MySQL Database Port", "high", "CWE-200", "Direct MySQL port exposed to public internet."),
    3389: (
        "Exposed Remote Desktop Protocol (RDP)",
        "high",
        "CWE-200",
        "RDP exposed publicly invites brute-force attacks and BlueKeep exploitation.",
    ),
    5432: (
        "Exposed PostgreSQL Database Port",
        "high",
        "CWE-200",
        "Direct PostgreSQL database listener exposed.",
    ),
    5900: ("Exposed VNC Remote Access", "high", "CWE-200", "VNC exposed without network isolation."),
    6379: (
        "Exposed Redis In-Memory Datastore",
        "critical",
        "CWE-306",
        "Redis instances frequently lack authentication, allowing remote code execution.",
    ),
    9200: (
        "Exposed Elasticsearch Search Engine",
        "high",
        "CWE-306",
        "Elasticsearch cluster exposed publicly without authentication.",
    ),
    11211: (
        "Exposed Memcached Server",
        "high",
        "CWE-306",
        "Memcached exposed publicly can be abused for massive amplification DDoS.",
    ),
    27017: (
        "Exposed MongoDB Database Listener",
        "critical",
        "CWE-306",
        "MongoDB default installations often lack authentication, leading to complete data exfiltration.",
    ),
}


def _probe_port(ip: str, host: str, port: int, timeout: float = 1.0) -> dict[str, Any] | None:
    """Attempt TCP connection and banner grabbing on a single port."""
    started = time.monotonic()
    sock = None
    try:
        # Address family determination
        parsed = ipaddress.ip_address(ip)
        af = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
        sock = socket.socket(af, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        latency = round((time.monotonic() - started) * 1000, 2)

        service = SERVICE_NAMES.get(port, f"tcp-{port}")
        banner = ""

        # Banner Grab: HTTP / HTTPS
        if port in (80, 8080, 3000, 5000, 8000, 8888, 9000):
            try:
                sock.sendall(
                    f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: SHARAY-PortScan/1.0\r\n\r\n".encode()
                )
                raw_resp = sock.recv(1024).decode("utf-8", errors="replace")
                for line in raw_resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        banner = line.split(":", 1)[1].strip()
                        break
            except Exception:
                pass

        elif port in (443, 8443, 2083):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.getpeercert(binary_form=False)
                    version = ssock.version()
                    cipher = ssock.cipher()
                    banner = f"{version} ({cipher[0] if cipher else 'unknown'})"
            except Exception:
                banner = "TLS Listener"

        # Banner Grab: Generic SSH / FTP / SMTP
        elif port in (21, 22, 25, 110, 143):
            try:
                banner = sock.recv(512).decode("utf-8", errors="replace").strip()
            except Exception:
                pass

        return {
            "port": port,
            "protocol": "tcp",
            "state": "open",
            "service": service,
            "banner": banner or f"{service} active",
            "latency_ms": latency,
        }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def scan_network_ports(
    destination_ip: str,
    target_host: str,
    additional_ports: list[int] | None = None,
    timeout: float = 1.0,
    max_workers: int = 30,
) -> dict[str, Any]:
    """Execute high-speed concurrent TCP port scan across common and specified ports."""
    target_ports = sorted(list(set(TOP_PORTS + (additional_ports or []))))

    open_services: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(_probe_port, destination_ip, target_host, p, timeout): p for p in target_ports
        }
        for future in concurrent.futures.as_completed(future_map):
            port = future_map[future]
            try:
                res = future.result()
                if res is not None:
                    open_services.append(res)
                    # Check if port is high risk
                    if port in DANGEROUS_PORTS:
                        title, severity, cwe, desc = DANGEROUS_PORTS[port]
                        findings.append(
                            {
                                "category": "network_security",
                                "severity": severity,
                                "title": f"{title} (Port {port}/TCP)",
                                "description": f"{desc} Banner observed: {res.get('banner', 'N/A')}.",
                                "target_url": f"{target_host}:{port}",
                                "fingerprint": hashlib.sha256(
                                    f"port_{destination_ip}_{port}".encode()
                                ).hexdigest(),
                                "cwe_id": cwe,
                                "attributes": {
                                    "port": port,
                                    "service": res.get("service"),
                                    "banner": res.get("banner"),
                                    "latency_ms": res.get("latency_ms"),
                                },
                            }
                        )
            except Exception:
                pass

    # Sort by port number
    open_services.sort(key=lambda x: x["port"])

    observations: list[dict[str, Any]] = []
    for s in open_services:
        observations.append(
            {
                "kind": "network_service",
                "category": "network_inventory",
                "address": destination_ip,
                "port": s["port"],
                "protocol": s["protocol"],
                "state": s["state"],
                "service": s["service"],
                "banner": s["banner"],
                "latency_ms": s["latency_ms"],
                "captured_at": datetime.now(UTC).isoformat(),
                "tool": "sharay_native_port_scanner",
            }
        )

    open_summary = ", ".join(f"{s['port']}/{s['service']}" for s in open_services) or "none open"
    check = {
        "category": "network_inventory",
        "status": "completed",
        "detail": f"SHARAY Native TCP Scanner probed {len(target_ports)} common ports on {destination_ip}: {len(open_services)} open ({open_summary}).",
    }

    return {
        "open_services": open_services,
        "observations": observations,
        "findings": findings,
        "check": check,
    }


__all__ = ["scan_network_ports", "TOP_PORTS"]
