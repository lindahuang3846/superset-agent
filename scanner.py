"""
Daily scanner — detects SQL injection patterns in the repo and creates GitHub issues.

Run via: python -m app.scanner
Or scheduled via the cron container (see docker-compose.yml).
"""

import logging
import os
import re
import subprocess
import sys
import time

import httpx

log = logging.getLogger(__name__)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "lindahuang3846/superset")
SECURITY_LABEL = os.environ.get("SECURITY_LABEL", "security")

# Patterns that indicate SQL injection risk: f-strings inside SQL execution calls
# or SQL strings with direct variable interpolation.
INJECTION_PATTERNS = [
    # f-string passed to execute() or text()
    r'\.execute\(f["\']',
    r'text\(f["\']',
    # Direct f-string SQL with common SQL keywords
    r'f["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP|SHOW|ALTER)[^"\']*\{',
    r'get_df\(\s*f["\']',
    # noqa S608 suppression — developer acknowledged but didn't fix
    r'#\s*noqa:\s*S608',
]

COMPILED = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

# Files already known to be fixed (updated as PRs merge)
IGNORE_PATHS = {
    "superset/migrations/",
    "tests/",
    "superset-frontend/",
}


def calculate_severity(filepath: str, findings: list[dict]) -> tuple[int, str, int]:
    """
    Calculate severity score for SQL injection vulnerabilities.

    Returns: (severity_score, severity_label, vulnerability_count)
    """
    score = 0
    count = len(findings)

    # SQL Operation Weight (0-50 points)
    sql_ops_high = ["DROP", "DELETE", "ALTER"]
    sql_ops_medium = ["INSERT", "UPDATE"]
    sql_ops_low = ["SELECT", "SHOW", "GET"]

    max_op_score = 0
    for finding in findings:
        code = finding["code"].upper()
        if any(op in code for op in sql_ops_high):
            max_op_score = max(max_op_score, 50)
        elif any(op in code for op in sql_ops_medium):
            max_op_score = max(max_op_score, 30)
        elif any(op in code for op in sql_ops_low):
            max_op_score = max(max_op_score, 10)

    score += max_op_score

    # Vulnerability Count (0-30 points)
    count_score = min(count * 10, 30)
    score += count_score

    # Pattern Severity (0-20 points)
    max_pattern_score = 0
    for finding in findings:
        code = finding["code"]
        if ".execute(" in code and "f\"" in code or "f'" in code:
            max_pattern_score = max(max_pattern_score, 20)
        elif ".text(" in code and "f\"" in code or "f'" in code:
            max_pattern_score = max(max_pattern_score, 15)
        elif "noqa" in code.lower():
            max_pattern_score = max(max_pattern_score, 10)

    score += max_pattern_score

    # Determine severity label
    if score >= 80:
        label = "Critical"
    elif score >= 60:
        label = "High"
    elif score >= 40:
        label = "Medium"
    else:
        label = "Low"

    return score, label, count


def scan_repo(repo_path: str) -> list[dict]:
    findings = []
    result = subprocess.run(
        ["grep", "-rn", "--include=*.py",
         "-E", "|".join(INJECTION_PATTERNS),
         repo_path],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        filepath, lineno, code = parts[0], parts[1], parts[2]

        rel = filepath.replace(repo_path, "").lstrip("/")
        if any(rel.startswith(p) for p in IGNORE_PATHS):
            continue

        findings.append({"file": rel, "line": lineno, "code": code.strip()})
    return findings


def group_by_file(findings: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for f in findings:
        grouped.setdefault(f["file"], []).append(f)
    return grouped


def existing_issue_titles(headers: dict) -> set[str]:
    url = f"https://api.github.com/repos/{GITHUB_REPO}/issues"
    params = {"state": "open", "labels": SECURITY_LABEL, "per_page": 100}
    resp = httpx.get(url, headers=headers, params=params)
    resp.raise_for_status()
    return {i["title"] for i in resp.json()}


def ensure_label_exists(headers: dict) -> None:
    url = f"https://api.github.com/repos/{GITHUB_REPO}/labels/{SECURITY_LABEL}"
    resp = httpx.get(url, headers=headers)
    if resp.status_code == 404:
        httpx.post(
            f"https://api.github.com/repos/{GITHUB_REPO}/labels",
            headers=headers,
            json={"name": SECURITY_LABEL, "color": "d73a4a", "description": "Security vulnerability"},
        )


def create_issue(headers: dict, title: str, body: str) -> dict:
    resp = httpx.post(
        f"https://api.github.com/repos/{GITHUB_REPO}/issues",
        headers=headers,
        json={"title": title, "body": body, "labels": [SECURITY_LABEL]},
    )
    resp.raise_for_status()
    return resp.json()


def build_issue_body(filepath: str, findings: list[dict], severity_score: int = 0, severity_label: str = "Low") -> str:
    lines_section = "\n".join(
        f"- Line {f['line']}: `{f['code']}`" for f in findings
    )

    # Severity badge emoji
    severity_emoji = {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "⚪"
    }.get(severity_label, "⚪")

    return f"""## Summary

{severity_emoji} **Severity: {severity_label}** (Score: {severity_score}/100)

Automated daily scan detected SQL injection risk (CWE-89) in `{filepath}`.

Variables are interpolated directly into SQL strings using f-strings without using
SQLAlchemy's identifier quoting (`dialect.identifier_preparer.quote()`).

**Vulnerability Count:** {len(findings)} instance(s)

## Affected Lines

{lines_section}

## Fix

Replace f-string interpolation with properly quoted identifiers:

```python
# Before
conn.execute(f"SELECT * FROM {{table_name}}")

# After
from sqlalchemy.sql import quoted_name
safe = quoted_name(table_name, quote=True)
conn.execute(f"SELECT * FROM {{safe}}")
```

Remove the `# noqa: S608` suppression comment after applying the fix.

## References

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- OWASP A03:2021 – Injection
- Detected by: superset-security-bot daily scan ({time.strftime('%Y-%m-%d')})

---
**Metadata:** `severity_score={severity_score}` `severity_label={severity_label}` `vulnerability_count={len(findings)}`
"""


def run_scan(repo_path: str) -> None:
    if not GITHUB_TOKEN:
        log.error("GITHUB_TOKEN not set — cannot create issues")
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    log.info("Scanning %s for SQL injection patterns...", repo_path)
    findings = scan_repo(repo_path)
    log.info("Found %d matching lines", len(findings))

    if not findings:
        log.info("No findings. Exiting.")
        return

    ensure_label_exists(headers)
    existing = existing_issue_titles(headers)
    grouped = group_by_file(findings)

    # Calculate severity for all findings and sort by severity (highest first)
    files_with_severity = []
    for filepath, file_findings in grouped.items():
        title = f"Security: SQL injection risk in {filepath}"
        if title in existing:
            log.info("Issue already exists for %s — skipping", filepath)
            continue

        severity_score, severity_label, vuln_count = calculate_severity(filepath, file_findings)
        files_with_severity.append({
            "filepath": filepath,
            "findings": file_findings,
            "severity_score": severity_score,
            "severity_label": severity_label,
            "vuln_count": vuln_count,
            "title": title,
        })

    # Sort by severity (highest first)
    files_with_severity.sort(key=lambda x: -x["severity_score"])

    # Limit to 5 issues per scan
    max_issues_per_scan = 5
    to_create = files_with_severity[:max_issues_per_scan]
    remaining = len(files_with_severity) - len(to_create)

    log.info("Found %d new vulnerabilities. Creating %d issue(s) (limit: %d per scan)",
             len(files_with_severity), len(to_create), max_issues_per_scan)

    created = 0
    for item in to_create:
        filepath = item["filepath"]
        file_findings = item["findings"]
        severity_score = item["severity_score"]
        severity_label = item["severity_label"]
        title = item["title"]

        log.info("Creating issue for %s: %s (score=%d, count=%d)",
                 filepath, severity_label, severity_score, item["vuln_count"])

        body = build_issue_body(filepath, file_findings, severity_score, severity_label)
        issue = create_issue(headers, title, body)
        log.info("Created issue #%d: %s", issue["number"], issue["html_url"])
        created += 1
        time.sleep(1)  # avoid GitHub rate limit

    log.info("Scan complete. Created %d new issue(s).", created)
    if remaining > 0:
        log.info("%d vulnerabilities remaining. Run scan again to create more issues.", remaining)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    repo = os.environ.get("SUPERSET_REPO_PATH", "/repo")
    run_scan(repo)
