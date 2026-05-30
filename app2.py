from flask import Flask, render_template, request

from port_scanner2 import scan_ports
from header_checker2 import check_headers
from xss_checker2 import test_xss
from sql_checker2 import test_sql_injection
from directory_scanner2 import scan_directories
from csrf_checker2 import test_csrf
from ssl_checker2 import check_ssl

app = Flask(__name__)


def categorize(severity):
    s = severity.upper()
    if s == "CRITICAL": return "critical"
    if s == "HIGH":     return "high"
    if s == "MEDIUM":   return "medium"
    if s == "LOW":      return "low"
    return "info"


def build_section(title, icon, findings):
    results = []
    for f in findings:
        results.append({
            "title":        f.get("title", "Unknown"),
            "severity":     f.get("severity", "INFO"),
            "category":     categorize(f.get("severity", "INFO")),
            "owasp":        f.get("owasp", ""),
            "description":  f.get("description", ""),
            "affected_url": f.get("affected_url", ""),
            "fix":          f.get("fix", ""),
        })
    # NOTE: key is "results" not "items" — "items" is a dict built-in and
    # causes Jinja2 dot-access to return the method instead of the list.
    return {"title": title, "icon": icon, "results": results}


@app.route("/")
def home():
    return render_template("index2.html", page="home")


@app.route("/about")
def about():
    return render_template("index2.html", page="about")


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method != "POST":
        return render_template("index2.html", page="scan")

    target_url = request.form.get("url", "").strip()
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    clean_target = (
        target_url.replace("https://", "").replace("http://", "").split("/")[0]
    )

    sections = []

    runners = [
        ("Port Scan",        "PORT",  lambda: scan_ports(clean_target)),
        ("SSL / TLS",        "SSL",   lambda: check_ssl(target_url)),
        ("Security Headers", "HDR",   lambda: check_headers(target_url)),
        ("XSS Detection",    "XSS",   lambda: test_xss(target_url)),
        ("SQL Injection",    "SQL",   lambda: test_sql_injection(target_url)),
        ("CSRF",             "CSRF",  lambda: test_csrf(target_url)),
        ("Directory Scan",   "DIR",   lambda: scan_directories(target_url)),
    ]

    for title, icon, runner in runners:
        try:
            findings = runner()
        except Exception as e:
            findings = [{
                "title":        "Error running " + title,
                "severity":     "INFO",
                "owasp":        "",
                "description":  str(e),
                "affected_url": target_url,
                "fix":          "Ensure the target is reachable.",
            }]
        sections.append(build_section(title, icon, findings))

    # Build summary counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for section in sections:
        for item in section["results"]:
            counts[item["category"]] += 1

    total_issues = (
        counts["critical"] + counts["high"] + counts["medium"] + counts["low"]
    )
    summary = dict(counts)
    summary["total"] = total_issues

    # Pre-compute in Python so template needs no namespace tricks
    has_vulns = any(
        item["category"] != "info"
        for section in sections
        for item in section["results"]
    )

    vuln_findings = []
    for section in sections:
        for item in section["results"]:
            if item["category"] != "info":
                entry = dict(item)
                entry["section_title"] = section["title"]
                vuln_findings.append(entry)

    return render_template(
        "index2.html",
        page="results",
        sections=sections,
        target_url=target_url,
        summary=summary,
        has_vulns=has_vulns,
        vuln_findings=vuln_findings,
    )


if __name__ == "__main__":
    app.run(debug=True, port=5001)
