import requests

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity":    "HIGH",
        "owasp":       "A05:2021 - Security Misconfiguration",
        "description": "Content-Security-Policy header is missing. This exposes the site to XSS and data injection attacks.",
        "fix":         "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Frame-Options": {
        "severity":    "MEDIUM",
        "owasp":       "A05:2021 - Security Misconfiguration",
        "description": "X-Frame-Options is missing. The page may be embedded in iframes, enabling clickjacking.",
        "fix":         "Add: X-Frame-Options: DENY  or  X-Frame-Options: SAMEORIGIN",
    },
    "Strict-Transport-Security": {
        "severity":    "MEDIUM",
        "owasp":       "A02:2021 - Cryptographic Failures",
        "description": "HSTS header is missing. Attackers can downgrade HTTPS connections to HTTP.",
        "fix":         "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "X-Content-Type-Options": {
        "severity":    "LOW",
        "owasp":       "A05:2021 - Security Misconfiguration",
        "description": "X-Content-Type-Options is missing. Browsers may MIME-sniff responses, enabling content injection.",
        "fix":         "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity":    "LOW",
        "owasp":       "A05:2021 - Security Misconfiguration",
        "description": "Referrer-Policy is missing. Sensitive URLs may leak via the Referer header.",
        "fix":         "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity":    "LOW",
        "owasp":       "A05:2021 - Security Misconfiguration",
        "description": "Permissions-Policy is missing. The site does not restrict access to browser APIs like camera or geolocation.",
        "fix":         "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}


def check_headers(url):
    findings = []
    try:
        response = requests.get(url, headers=UA, timeout=10, allow_redirects=True)
        present = response.headers

        for header, info in SECURITY_HEADERS.items():
            if header.lower() in [h.lower() for h in present.keys()]:
                findings.append({
                    "title":       f"{header} Present",
                    "severity":    "INFO",
                    "owasp":       info["owasp"],
                    "description": f"Security header '{header}' is correctly set.",
                    "affected_url": url,
                    "fix":         "No action needed.",
                })
            else:
                findings.append({
                    "title":       f"Missing: {header}",
                    "severity":    info["severity"],
                    "owasp":       info["owasp"],
                    "description": info["description"],
                    "affected_url": url,
                    "fix":         info["fix"],
                })

        # Check for information leakage headers
        leak_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
        for lh in leak_headers:
            if lh in present:
                findings.append({
                    "title":       f"Information Disclosure: {lh}",
                    "severity":    "LOW",
                    "owasp":       "A05:2021 - Security Misconfiguration",
                    "description": f"The '{lh}' header reveals server technology: {present[lh]}",
                    "affected_url": url,
                    "fix":         f"Remove or suppress the '{lh}' response header in your server config.",
                })

    except requests.exceptions.ConnectionError as e:
        findings.append({
            "title":       "Connection Failed",
            "severity":    "INFO",
            "owasp":       "A05:2021 - Security Misconfiguration",
            "description": f"Could not connect to target: {type(e).__name__}. Check the URL and try again.",
            "affected_url": url,
            "fix":         "Ensure the target URL is reachable and accessible.",
        })
    except Exception as e:
        findings.append({
            "title":       "Header Check Error",
            "severity":    "INFO",
            "owasp":       "A05:2021 - Security Misconfiguration",
            "description": f"Scanner encountered an error: {type(e).__name__}: {e}",
            "affected_url": url,
            "fix":         "Ensure the target URL is reachable.",
        })

    return findings
