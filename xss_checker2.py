import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
]

FIX = (
    "Implement proper output encoding for all user inputs. "
    "Use a Content Security Policy (CSP) header. "
    "Sanitize all input on the server side before rendering. "
    "Use modern frameworks with built-in XSS protection."
)


def _safe_get(url, **kwargs):
    """GET with short timeout and clean error."""
    return requests.get(url, headers=UA, timeout=8, **kwargs)


def test_xss(url):
    findings = []

    try:
        response = _safe_get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        base_url = parsed.scheme + "://" + parsed.netloc

        # 1. Test URL query parameters
        if params:
            for param_name in params:
                for payload in XSS_PAYLOADS:
                    test_params = dict(params)
                    test_params[param_name] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    try:
                        r = _safe_get(test_url)
                        if payload in r.text:
                            findings.append({
                                "title":       "Reflected XSS in URL Parameter",
                                "severity":    "HIGH",
                                "owasp":       "A03:2021 - Injection",
                                "description": (
                                    f"Reflected XSS detected in URL parameter '{param_name}'. "
                                    "The injected script appears in the response without sanitization."
                                ),
                                "affected_url": test_url,
                                "fix":         FIX,
                            })
                            break
                    except Exception:
                        pass

        # 2. Test HTML forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            target_url = (base_url + action) if action else url

            for payload in XSS_PAYLOADS:
                data = {inp.get("name"): payload for inp in inputs if inp.get("name")}
                if not data:
                    continue
                try:
                    if method == "post":
                        r = requests.post(target_url, data=data, headers=UA, timeout=8)
                    else:
                        r = _safe_get(target_url, params=data)
                    if payload in r.text:
                        findings.append({
                            "title":       "Reflected XSS in Form",
                            "severity":    "HIGH",
                            "owasp":       "A03:2021 - Injection",
                            "description": (
                                "Reflected XSS detected via form submission. "
                                "Form input is reflected in the response without sanitization."
                            ),
                            "affected_url": target_url,
                            "fix":         FIX,
                        })
                        break
                except Exception:
                    pass

    except requests.exceptions.ConnectionError:
        return [{
            "title":       "XSS Check — Connection Failed",
            "severity":    "INFO",
            "owasp":       "A03:2021 - Injection",
            "description": "Could not connect to the target. The host may be unreachable from this scanner.",
            "affected_url": url,
            "fix":         "Verify the target URL is reachable and try again.",
        }]
    except requests.exceptions.Timeout:
        return [{
            "title":       "XSS Check — Request Timed Out",
            "severity":    "INFO",
            "owasp":       "A03:2021 - Injection",
            "description": "The target did not respond within the timeout window.",
            "affected_url": url,
            "fix":         "The site may be slow or blocking automated requests.",
        }]
    except Exception as e:
        return [{
            "title":       "XSS Check Error",
            "severity":    "INFO",
            "owasp":       "A03:2021 - Injection",
            "description": f"Scanner encountered an error: {type(e).__name__}",
            "affected_url": url,
            "fix":         "Ensure the target URL is reachable.",
        }]

    if not findings:
        return [{
            "title":       "No XSS Vulnerabilities Detected",
            "severity":    "INFO",
            "owasp":       "A03:2021 - Injection",
            "description": "No reflected XSS vulnerabilities found with the tested payloads.",
            "affected_url": url,
            "fix":         "Continue sanitizing user inputs and enforcing a Content Security Policy.",
        }]

    return findings
