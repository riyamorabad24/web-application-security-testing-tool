import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1 --",
    "1' AND 1=2 --",
    "\" OR \"1\"=\"1",
    "'; DROP TABLE users; --",
]

ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql error",
    "you have an error in your sql",
    "warning: mysql",
    "unclosed quotation mark",
    "syntax error",
    "database error",
    "sqlite3.operationalerror",
    "pg::syntaxerror",
    "ora-01756",
    "microsoft ole db",
    "odbc sql server driver",
    "jdbc",
    "unexpected token",
    "unterminated string",
]

FIX = (
    "Use parameterized queries (prepared statements) for all database operations. "
    "Implement proper input validation. "
    "Apply least privilege for database accounts. "
    "Disable detailed error messages in production."
)


def _check_response(text):
    low = text.lower()
    return any(sig in low for sig in ERROR_SIGNATURES)


def test_sql_injection(url):
    findings = []

    try:
        response = requests.get(url, headers=UA, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        base_url = parsed.scheme + "://" + parsed.netloc

        # 1. Test URL parameters
        if params:
            for param_name in params:
                for payload in SQL_PAYLOADS:
                    test_params = dict(params)
                    test_params[param_name] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    try:
                        r = requests.get(test_url, headers=UA, timeout=10)
                        if _check_response(r.text):
                            findings.append({
                                "title":       "SQL Injection (Error-Based)",
                                "severity":    "CRITICAL",
                                "owasp":       "A03:2021 - Injection",
                                "description": (
                                    "SQL injection detected via error-based testing. "
                                    "The app returns database error messages when malformed SQL is injected."
                                ),
                                "affected_url": test_url,
                                "fix":         FIX,
                            })
                            break
                    except Exception:
                        pass

        # 2. Test forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            target_url = (base_url + action) if action else url

            for payload in SQL_PAYLOADS:
                data = {inp.get("name"): payload for inp in inputs if inp.get("name")}
                if not data:
                    continue
                try:
                    if method == "post":
                        r = requests.post(target_url, data=data, headers=UA, timeout=10)
                    else:
                        r = requests.get(target_url, params=data, headers=UA, timeout=10)
                    if _check_response(r.text):
                        findings.append({
                            "title":       "SQL Injection in Form",
                            "severity":    "CRITICAL",
                            "owasp":       "A03:2021 - Injection",
                            "description": (
                                "SQL injection detected via form submission. "
                                "The app exposes database error details when injected SQL is submitted."
                            ),
                            "affected_url": target_url,
                            "fix":         FIX,
                        })
                        break
                except Exception:
                    pass

    except requests.exceptions.ConnectionError:
        return [{
            "title":       "SQL Check — Connection Failed",
            "severity":    "INFO",
            "owasp":       "A03:2021 - Injection",
            "description": "Could not connect to the target. The host may be unreachable from this scanner.",
            "affected_url": url,
            "fix":         "Verify the target URL is reachable and try again.",
        }]
    except requests.exceptions.Timeout:
        return [{
            "title":       "SQL Check — Request Timed Out",
            "severity":    "INFO",
            "owasp":       "A03:2021 - Injection",
            "description": "The target did not respond within the timeout window.",
            "affected_url": url,
            "fix":         "The site may be slow or blocking automated requests.",
        }]
    except Exception as e:
        return [{
            "title":       "SQL Injection Check Error",
            "severity":    "INFO",
            "owasp":       "A03:2021 - Injection",
            "description": f"Scanner encountered an error: {type(e).__name__}",
            "affected_url": url,
            "fix":         "Ensure the target URL is reachable.",
        }]

    if not findings:
        return [{
            "title":       "No SQL Injection Detected",
            "severity":    "INFO",
            "owasp":       "A03:2021 - Injection",
            "description": "No SQL injection vulnerabilities detected with the tested payloads.",
            "affected_url": url,
            "fix":         "Continue using parameterized queries and keep dependencies updated.",
        }]

    return findings
