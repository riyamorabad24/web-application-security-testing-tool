import ssl
import socket
import datetime


def check_ssl(url):
    findings = []
    hostname = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    # If the URL is http-only and not https, note that
    if url.startswith("http://"):
        findings.append({
            "title":       "Site Uses HTTP (Not HTTPS)",
            "severity":    "HIGH",
            "owasp":       "A02:2021 - Cryptographic Failures",
            "description": "The target URL uses plain HTTP. All data is transmitted unencrypted.",
            "affected_url": url,
            "fix":         "Obtain an SSL/TLS certificate and enforce HTTPS redirects.",
        })
        # Still try to check port 443
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        conn.settimeout(6)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        proto = conn.version()
        conn.close()

        # Certificate expiry
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.datetime.utcnow()).days
            if days_left < 0:
                findings.append({
                    "title":       "SSL Certificate Expired",
                    "severity":    "CRITICAL",
                    "owasp":       "A02:2021 - Cryptographic Failures",
                    "description": f"The SSL certificate expired {abs(days_left)} days ago. All connections are insecure.",
                    "affected_url": f"https://{hostname}",
                    "fix":         "Renew the SSL certificate immediately via your CA or Let's Encrypt.",
                })
            elif days_left < 30:
                findings.append({
                    "title":       "SSL Certificate Expiring Soon",
                    "severity":    "MEDIUM",
                    "owasp":       "A02:2021 - Cryptographic Failures",
                    "description": f"The SSL certificate expires in {days_left} days.",
                    "affected_url": f"https://{hostname}",
                    "fix":         "Renew the SSL certificate before it expires.",
                })
            else:
                findings.append({
                    "title":       "SSL Certificate Valid",
                    "severity":    "INFO",
                    "owasp":       "A02:2021 - Cryptographic Failures",
                    "description": f"SSL certificate is valid with {days_left} days remaining.",
                    "affected_url": f"https://{hostname}",
                    "fix":         "No action needed.",
                })

        # Protocol version
        if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            findings.append({
                "title":       f"Weak Protocol Detected: {proto}",
                "severity":    "HIGH",
                "owasp":       "A02:2021 - Cryptographic Failures",
                "description": f"The server supports {proto}, which is deprecated and insecure.",
                "affected_url": f"https://{hostname}",
                "fix":         "Disable TLS 1.0 and 1.1. Use TLS 1.2 or TLS 1.3 only.",
            })
        else:
            findings.append({
                "title":       f"Secure Protocol in Use: {proto}",
                "severity":    "INFO",
                "owasp":       "A02:2021 - Cryptographic Failures",
                "description": f"Server negotiated {proto}, which is a secure protocol version.",
                "affected_url": f"https://{hostname}",
                "fix":         "No action needed.",
            })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "title":       "SSL Certificate Verification Failed",
            "severity":    "CRITICAL",
            "owasp":       "A02:2021 - Cryptographic Failures",
            "description": f"SSL certificate could not be verified: {e}",
            "affected_url": f"https://{hostname}",
            "fix":         "Install a valid certificate from a trusted Certificate Authority (CA).",
        })
    except (ConnectionRefusedError, OSError):
        findings.append({
            "title":       "HTTPS Not Available on Port 443",
            "severity":    "MEDIUM",
            "owasp":       "A02:2021 - Cryptographic Failures",
            "description": "Port 443 is closed or unreachable. The site may not support HTTPS.",
            "affected_url": f"https://{hostname}",
            "fix":         "Enable HTTPS and obtain a valid SSL/TLS certificate.",
        })
    except Exception as e:
        findings.append({
            "title":       "SSL Check Could Not Complete",
            "severity":    "INFO",
            "owasp":       "A02:2021 - Cryptographic Failures",
            "description": f"SSL check skipped: {type(e).__name__}. Verify manually at ssllabs.com.",
            "affected_url": f"https://{hostname}",
            "fix":         "Manually verify the site SSL config using ssllabs.com/ssltest.",
        })

    return findings
