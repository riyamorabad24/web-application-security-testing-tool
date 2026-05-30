import requests
from bs4 import BeautifulSoup

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

FIX = (
    "Implement CSRF tokens for all state-changing requests. "
    "Use the SameSite cookie attribute (Lax or Strict). "
    "Validate Origin and Referer headers on the server side."
)

CSRF_KEYWORDS = ["csrf", "token", "nonce", "_token", "verify", "authenticity"]


def test_csrf(url):
    findings = []

    try:
        response = requests.get(url, headers=UA, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return [{
                "title":       "No Forms Found for CSRF Testing",
                "severity":    "INFO",
                "owasp":       "A01:2021 - Broken Access Control",
                "description": "No HTML forms were found on this page.",
                "affected_url": url,
                "fix":         "Ensure CSRF tokens are present on any state-changing forms.",
            }]

        vulnerable_count = 0
        for form in forms:
            method = form.get("method", "get").lower()
            if method != "post":
                continue

            inputs = form.find_all("input")
            input_names = [(i.get("name") or "").lower() for i in inputs]
            input_types = [(i.get("type") or "").lower() for i in inputs]

            has_csrf = any(any(k in n for k in CSRF_KEYWORDS) for n in input_names)
            has_hidden = "hidden" in input_types

            if not has_csrf and not has_hidden:
                vulnerable_count += 1
                findings.append({
                    "title":       "CSRF Token Missing in POST Form",
                    "severity":    "HIGH",
                    "owasp":       "A01:2021 - Broken Access Control",
                    "description": (
                        "A POST form was found without a CSRF token. "
                        "Attackers can trick authenticated users into submitting unintended requests."
                    ),
                    "affected_url": url,
                    "fix":         FIX,
                })

        if not findings:
            findings.append({
                "title":       "CSRF Tokens Present",
                "severity":    "INFO",
                "owasp":       "A01:2021 - Broken Access Control",
                "description": "All POST forms appear to include CSRF protection tokens.",
                "affected_url": url,
                "fix":         "No action needed. Continue enforcing CSRF protection.",
            })

    except requests.exceptions.ConnectionError:
        findings.append({
            "title":       "CSRF Check — Connection Failed",
            "severity":    "INFO",
            "owasp":       "A01:2021 - Broken Access Control",
            "description": "Could not connect to the target for CSRF inspection.",
            "affected_url": url,
            "fix":         "Verify the target URL is reachable and try again.",
        })
    except requests.exceptions.Timeout:
        findings.append({
            "title":       "CSRF Check — Request Timed Out",
            "severity":    "INFO",
            "owasp":       "A01:2021 - Broken Access Control",
            "description": "The target did not respond within the timeout window.",
            "affected_url": url,
            "fix":         "The site may be slow or blocking automated requests.",
        })
    except Exception as e:
        findings.append({
            "title":       "CSRF Check Error",
            "severity":    "INFO",
            "owasp":       "A01:2021 - Broken Access Control",
            "description": f"Scanner encountered an error: {type(e).__name__}",
            "affected_url": url,
            "fix":         "Ensure the target URL is reachable.",
        })

    return findings
