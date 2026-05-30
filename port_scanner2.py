import socket
import threading

PORTS = {
    21:   ("FTP",        "HIGH",     "FTP is unencrypted and transfers credentials in plaintext."),
    22:   ("SSH",        "INFO",     "SSH port is open. Ensure password auth is disabled and key-based auth is enforced."),
    23:   ("Telnet",     "CRITICAL", "Telnet is unencrypted and extremely insecure. Disable immediately."),
    25:   ("SMTP",       "MEDIUM",   "SMTP port is open. Ensure it is not an open relay."),
    80:   ("HTTP",       "LOW",      "HTTP port is open. Ensure the site redirects to HTTPS."),
    443:  ("HTTPS",      "INFO",     "HTTPS port is open."),
    3306: ("MySQL",      "CRITICAL", "MySQL database port is publicly exposed. Restrict immediately."),
    5432: ("PostgreSQL", "CRITICAL", "PostgreSQL port is publicly exposed. Restrict immediately."),
    6379: ("Redis",      "CRITICAL", "Redis port is publicly exposed without authentication by default."),
    8080: ("HTTP-Alt",   "MEDIUM",   "Alternate HTTP port is open. Ensure this is intentional."),
    8443: ("HTTPS-Alt",  "INFO",     "Alternate HTTPS port is open."),
    27017:("MongoDB",    "CRITICAL", "MongoDB port is publicly exposed. Restrict access immediately."),
}

FIX_MAP = {
    "CRITICAL": "Immediately restrict this port using a firewall. Allow only trusted IPs.",
    "HIGH":     "Disable this service or restrict it behind a VPN or firewall.",
    "MEDIUM":   "Review whether this port needs to be publicly accessible.",
    "LOW":      "Ensure HTTP redirects to HTTPS. Consider disabling plain HTTP.",
    "INFO":     "No immediate action required. Continue monitoring.",
}


def _scan_port(target, port, results, lock):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        if sock.connect_ex((target, port)) == 0:
            with lock:
                results.append(port)
        sock.close()
    except Exception:
        pass


def scan_ports(target):
    open_ports = []
    lock = threading.Lock()
    threads = []

    for port in PORTS:
        t = threading.Thread(target=_scan_port, args=(target, port, open_ports, lock))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    findings = []
    for port in sorted(open_ports):
        service, severity, description = PORTS.get(port, ("Unknown", "MEDIUM", "Unknown service."))
        findings.append({
            "title":       f"Port {port} Open ({service})",
            "severity":    severity,
            "owasp":       "A05:2021 - Security Misconfiguration",
            "description": description,
            "affected_url": f"{target}:{port}",
            "fix":         FIX_MAP.get(severity, "Review and restrict this port."),
        })

    if not findings:
        findings.append({
            "title":       "No Common Ports Open",
            "severity":    "INFO",
            "owasp":       "A05:2021 - Security Misconfiguration",
            "description": "None of the scanned common ports were found open.",
            "affected_url": target,
            "fix":         "No action needed.",
        })

    return findings
