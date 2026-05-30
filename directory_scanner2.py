import requests
from urllib.parse import urlparse

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

SENSITIVE_PATHS = [
    ("admin",         "CRITICAL", "Admin panel exposed"),
    ("administrator", "CRITICAL", "Administrator panel exposed"),
    ("login",         "HIGH",     "Login page exposed"),
    ("dashboard",     "HIGH",     "Dashboard exposed"),
    ("uploads",       "HIGH",     "Upload directory exposed"),
    ("backup",        "CRITICAL", "Backup directory exposed"),
    ("backups",       "CRITICAL", "Backup directory exposed"),
    ("config",        "CRITICAL", "Config directory exposed"),
    ("configuration", "CRITICAL", "Configuration directory exposed"),
    ("phpmyadmin",    "CRITICAL", "phpMyAdmin panel exposed"),
    ("wp-admin",      "HIGH",     "WordPress admin exposed"),
    ("wp-login.php",  "HIGH",     "WordPress login page exposed"),
    (".git",          "CRITICAL", "Git repository exposed — source code may be leaked"),
    (".env",          "CRITICAL", ".env file exposed — credentials may be leaked"),
    ("api",           "MEDIUM",   "API endpoint exposed"),
    ("api/v1",        "MEDIUM",   "API v1 endpoint exposed"),
    ("test",          "MEDIUM",   "Test directory exposed"),
    ("dev",           "MEDIUM",   "Dev directory exposed"),
    ("debug",         "HIGH",     "Debug endpoint exposed"),
    ("console",       "HIGH",     "Console endpoint exposed"),
    ("logs",          "HIGH",     "Logs directory exposed"),
    ("server-status", "HIGH",     "Apache server-status exposed"),
    ("robots.txt",    "INFO",     "robots.txt found — may reveal hidden paths"),
    ("sitemap.xml",   "INFO",     "sitemap.xml found"),
]

FIX_MAP = {
    "CRITICAL": "Immediately restrict access. Remove from public access or place behind strong authentication.",
    "HIGH":     "Restrict access with authentication and authorization. Review who needs access.",
    "MEDIUM":   "Review whether this endpoint should be public. Add authentication if needed.",
    "INFO":     "Review the file contents to ensure no sensitive paths are disclosed.",
}


def scan_directories(url):
    findings = []
    parsed = urlparse(url)
    base = parsed.scheme + "://" + parsed.netloc

    for path, severity, label in SENSITIVE_PATHS:
        target = f"{base}/{path}"
        try:
            r = requests.get(target, headers=UA, timeout=5, allow_redirects=False)
            if r.status_code in (200, 301, 302, 403):
                status_note = {
                    200: "accessible (HTTP 200)",
                    301: "redirected (HTTP 301)",
                    302: "redirected (HTTP 302)",
                    403: "exists but forbidden (HTTP 403) — still a finding",
                }.get(r.status_code, f"HTTP {r.status_code}")

                findings.append({
                    "title":       f"Sensitive Path: /{path}",
                    "severity":    severity,
                    "owasp":       "A05:2021 - Security Misconfiguration",
                    "description": f"{label} — /{path} is {status_note}.",
                    "affected_url": target,
                    "fix":         FIX_MAP.get(severity, "Review and restrict this endpoint."),
                })
        except Exception:
            pass

    if not findings:
        findings.append({
            "title":       "No Sensitive Directories Found",
            "severity":    "INFO",
            "owasp":       "A05:2021 - Security Misconfiguration",
            "description": "No common sensitive directories or admin paths found publicly accessible.",
            "affected_url": base,
            "fix":         "Regularly audit exposed endpoints and enforce strict access controls.",
        })

    return findings
