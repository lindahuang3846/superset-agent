"""
Webhook server — receives GitHub issue events, dispatches Devin sessions.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.database import SessionLocal, init_db
from app.devin_client import DevinClient
from app.models import SessionRecord
from app.observability import get_dashboard_html, record_session_start

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
SECURITY_LABEL = os.environ.get("SECURITY_LABEL", "security")

# Throttling configuration
DEVIN_API_DELAY = int(os.environ.get("DEVIN_API_DELAY_SECONDS", "3"))  # seconds between API calls
_devin_api_lock = asyncio.Lock()
_last_devin_call = 0


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Superset Security Bot", lifespan=lifespan)
devin = DevinClient()


def verify_github_signature(body: bytes, signature: str) -> bool:
    if not GITHUB_WEBHOOK_SECRET:
        return True
    expected = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_severity_from_issue(issue: dict) -> tuple[int, str, int]:
    """
    Parse severity information from GitHub issue body.
    Returns: (severity_score, severity_label, vulnerability_count)
    """
    body = issue.get("body") or ""

    # Try to parse from metadata section
    severity_score = 0
    severity_label = "Low"
    vulnerability_count = 1

    # Look for metadata in format: severity_score=XX severity_label=YY vulnerability_count=ZZ
    score_match = re.search(r'severity_score=(\d+)', body)
    if score_match:
        severity_score = int(score_match.group(1))

    label_match = re.search(r'severity_label=(\w+)', body)
    if label_match:
        severity_label = label_match.group(1)

    count_match = re.search(r'vulnerability_count=(\d+)', body)
    if count_match:
        vulnerability_count = int(count_match.group(1))

    # If no metadata found, try to parse from summary section
    if severity_score == 0:
        # Look for "Severity: XXX (Score: YY/100)"
        summary_match = re.search(r'Severity:\s*(\w+).*Score:\s*(\d+)', body)
        if summary_match:
            severity_label = summary_match.group(1)
            severity_score = int(summary_match.group(2))

    return severity_score, severity_label, vulnerability_count


def append_log(db_session, session_id: str, event: str, details: str = ""):
    """Append a log entry to a session's log timeline."""
    record = db_session.query(SessionRecord).filter_by(devin_session_id=session_id).first()
    if not record:
        return

    logs = json.loads(record.logs or "[]")
    logs.append({
        "timestamp": int(time.time()),
        "event": event,
        "details": details
    })
    record.logs = json.dumps(logs)
    db_session.commit()


async def throttled_devin_create_session(**kwargs):
    """
    Wrapper around devin.create_session that enforces rate limiting.
    Ensures at least DEVIN_API_DELAY seconds between consecutive API calls.
    """
    global _last_devin_call

    async with _devin_api_lock:
        # Calculate how long we need to wait
        now = time.time()
        time_since_last = now - _last_devin_call

        if time_since_last < DEVIN_API_DELAY:
            delay = DEVIN_API_DELAY - time_since_last
            log.info("Throttling Devin API call, waiting %.1fs...", delay)
            await asyncio.sleep(delay)

        # Make the API call
        result = await devin.create_session(**kwargs)
        _last_devin_call = time.time()

        return result


def build_devin_prompt(issue: dict, repo: str) -> str:
    issue_number = issue["number"]
    issue_title = issue["title"]
    issue_body = issue.get("body") or ""
    issue_url = issue["html_url"]

    return f"""You are fixing a confirmed SQL injection vulnerability in the Apache Superset repository.

## Issue
GitHub Issue #{issue_number}: {issue_title}
{issue_url}

## Details
{issue_body}

## Your Task
1. Clone the repository: https://github.com/{repo}
2. Find the exact file and line numbers mentioned in the issue
3. Fix the SQL injection by replacing f-string identifier interpolation with SQLAlchemy's \
`dialect.identifier_preparer.quote()` or `sqlalchemy.sql.quoted_name()`
4. Remove the `# noqa: S608` suppression comment from the fixed line(s)
5. Add a brief inline comment explaining why the quoting is necessary
6. Run any existing tests for the affected file
7. Open a pull request with:
   - Title: `fix(security): {issue_title}`
   - Body referencing this issue: "Closes #{issue_number}"
   - Clear description of the change

Focus only on the specific lines mentioned in the issue. Do not refactor unrelated code.
"""


async def handle_issue_event(issue: dict, repo: str):
    issue_number = issue["number"]
    issue_title = issue["title"]

    # Check if we've already hit the session limit (5 concurrent sessions)
    db = SessionLocal()
    try:
        running_count = db.query(SessionRecord).filter(
            SessionRecord.status.in_(["running", "new", "claimed"])
        ).count()

        if running_count >= 5:
            log.warning("Session limit reached (%d/5 running). Skipping issue #%s", running_count, issue_number)
            return
    finally:
        db.close()

    log.info("Dispatching Devin session for issue #%s: %s (%d/5 slots used)", issue_number, issue_title, running_count)

    # Parse severity from issue body
    severity_score, severity_label, vulnerability_count = parse_severity_from_issue(issue)
    log.info("Parsed severity for issue #%s: %s (score=%d, count=%d)", issue_number, severity_label, severity_score, vulnerability_count)

    prompt = build_devin_prompt(issue, repo)
    tags = ["security", "sql-injection", f"issue-{issue_number}"]

    # Try to create Devin session with error handling and throttling
    session_id = None
    session_url = None
    status = "running"
    error_message = None

    try:
        result = await throttled_devin_create_session(
            prompt=prompt,
            title=f"Fix #{issue_number}: {issue_title[:60]}",
            tags=tags,
            repos=[f"https://github.com/{repo}"],
        )
        session_id = result["session_id"]
        session_url = result["url"]
        log.info("Devin session created: %s — %s", session_id, session_url)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            status = "rate_limited"
            error_message = "Devin API rate limit exceeded. Session will be retried."
            log.error("Rate limit exceeded for issue #%s: %s", issue_number, str(e))
        else:
            status = "error"
            error_message = f"Devin API error: {e.response.status_code}"
            log.error("Failed to create Devin session for issue #%s: %s", issue_number, str(e))
        # Use a placeholder session ID for tracking
        session_id = f"failed-{issue_number}-{int(time.time())}"
        session_url = f"https://github.com/{repo}/issues/{issue_number}"
    except Exception as e:
        status = "error"
        error_message = f"Unexpected error: {str(e)}"
        log.error("Unexpected error creating Devin session for issue #%s: %s", issue_number, str(e))
        session_id = f"failed-{issue_number}-{int(time.time())}"
        session_url = f"https://github.com/{repo}/issues/{issue_number}"

    # Always create a database record to track what happened
    db = SessionLocal()
    try:
        # Create initial logs
        logs = [
            {
                "timestamp": int(time.time()),
                "event": "webhook_received",
                "details": f"GitHub webhook received for issue #{issue_number}"
            }
        ]

        if status == "running":
            logs.append({
                "timestamp": int(time.time()),
                "event": "devin_session_created",
                "details": f"Devin session {session_id} created"
            })
        else:
            logs.append({
                "timestamp": int(time.time()),
                "event": "devin_session_failed",
                "details": error_message
            })

        initial_logs = json.dumps(logs)

        record = SessionRecord(
            devin_session_id=session_id,
            devin_session_url=session_url,
            github_issue_number=issue_number,
            github_issue_title=issue_title,
            github_repo=repo,
            status=status,
            created_at=int(time.time()),
            severity_score=severity_score,
            severity_label=severity_label,
            vulnerability_count=vulnerability_count,
            logs=initial_logs,
        )
        db.add(record)
        db.commit()
    finally:
        db.close()

    if status == "running":
        record_session_start(session_id, issue_number)


@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str = Header(default=""),
    x_hub_signature_256: str = Header(default=""),
):
    body = await request.body()

    if GITHUB_WEBHOOK_SECRET and not verify_github_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid signature")

    if x_github_event != "issues":
        return {"status": "ignored", "reason": f"event={x_github_event}"}

    payload = await request.json()
    action = payload.get("action")

    if action != "opened":
        return {"status": "ignored", "reason": f"action={action}"}

    issue = payload["issue"]
    labels = [lbl["name"] for lbl in issue.get("labels", [])]
    repo = payload["repository"]["full_name"]

    if SECURITY_LABEL not in labels:
        return {"status": "ignored", "reason": "no security label"}

    background_tasks.add_task(handle_issue_event, issue, repo)
    return {"status": "accepted", "issue": issue["number"]}


@app.get("/sessions")
async def list_sessions():
    """Return all tracked Devin sessions with latest status."""
    db = SessionLocal()
    try:
        records = db.query(SessionRecord).order_by(SessionRecord.created_at.desc()).all()
        # Refresh status for running sessions
        async with httpx.AsyncClient() as client:
            for record in records:
                if record.status in ("running", "new", "claimed"):
                    updated = await devin.get_session(record.devin_session_id, client)
                    new_status = updated.get("status")
                    log.info("Devin session %s status: %s", record.devin_session_id, new_status)

                    # Log status change
                    if new_status != record.status:
                        append_log(db, record.devin_session_id, "status_updated", f"Status changed from {record.status} to {new_status}")
                        record.status = new_status

                    prs = updated.get("pull_requests", [])
                    if prs and not record.pull_request_url:
                        record.pull_request_url = prs[0]["pr_url"]
                        log.info("PR found: %s", prs[0]["pr_url"])
                        append_log(db, record.devin_session_id, "pr_created", f"Pull request opened: {prs[0]['pr_url']}")

                # Check if PR is merged - if so, mark as completed
                if record.pull_request_url and record.status != "exit":
                    try:
                        # Extract PR number from URL
                        pr_num = record.pull_request_url.split("/pull/")[-1]
                        pr_url = f"https://api.github.com/repos/{record.github_repo}/pulls/{pr_num}"
                        pr_resp = await client.get(pr_url, headers={
                            "Authorization": f"Bearer {GITHUB_TOKEN}",
                            "Accept": "application/vnd.github+json",
                        })
                        if pr_resp.status_code == 200:
                            pr_data = pr_resp.json()
                            if pr_data.get("merged"):
                                log.info("PR #%s is merged, marking session as completed", pr_num)
                                append_log(db, record.devin_session_id, "pr_merged", f"Pull request #{pr_num} was merged")
                                record.status = "exit"
                    except Exception as e:
                        log.warning("Failed to check PR status: %s", e)
            db.commit()
        return [
            {
                "devin_session_id": r.devin_session_id,
                "devin_session_url": r.devin_session_url,
                "github_issue_number": r.github_issue_number,
                "github_issue_title": r.github_issue_title,
                "status": r.status,
                "pull_request_url": r.pull_request_url,
                "created_at": r.created_at,
            }
            for r in records
        ]
    finally:
        db.close()


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Lightweight observability dashboard."""
    db = SessionLocal()
    try:
        records = db.query(SessionRecord).order_by(SessionRecord.created_at.desc()).all()
        # Refresh status for running sessions
        async with httpx.AsyncClient() as client:
            for record in records:
                if record.status in ("running", "new", "claimed"):
                    updated = await devin.get_session(record.devin_session_id, client)
                    new_status = updated.get("status")
                    log.info("Devin session %s status: %s", record.devin_session_id, new_status)

                    # Log status change
                    if new_status != record.status:
                        append_log(db, record.devin_session_id, "status_updated", f"Status changed from {record.status} to {new_status}")
                        record.status = new_status

                    prs = updated.get("pull_requests", [])
                    if prs and not record.pull_request_url:
                        record.pull_request_url = prs[0]["pr_url"]
                        log.info("PR found: %s", prs[0]["pr_url"])
                        append_log(db, record.devin_session_id, "pr_created", f"Pull request opened: {prs[0]['pr_url']}")

                # Check if PR is merged - if so, mark as completed
                if record.pull_request_url and record.status != "exit":
                    try:
                        # Extract PR number from URL
                        pr_num = record.pull_request_url.split("/pull/")[-1]
                        pr_url = f"https://api.github.com/repos/{record.github_repo}/pulls/{pr_num}"
                        pr_resp = await client.get(pr_url, headers={
                            "Authorization": f"Bearer {GITHUB_TOKEN}",
                            "Accept": "application/vnd.github+json",
                        })
                        if pr_resp.status_code == 200:
                            pr_data = pr_resp.json()
                            if pr_data.get("merged"):
                                log.info("PR #%s is merged, marking session as completed", pr_num)
                                append_log(db, record.devin_session_id, "pr_merged", f"Pull request #{pr_num} was merged")
                                record.status = "exit"
                    except Exception as e:
                        log.warning("Failed to check PR status: %s", e)
            db.commit()
        return get_dashboard_html(records)
    finally:
        db.close()


@app.post("/scan/trigger")
async def trigger_scan(background_tasks: BackgroundTasks):
    """Manually trigger a repository scan for SQL injection vulnerabilities."""
    import os
    from app.scanner import run_scan
    repo_path = os.environ.get("SUPERSET_REPO_PATH", "/repo")
    background_tasks.add_task(run_scan, repo_path)
    log.info("Manual scan triggered for %s", repo_path)
    return {"message": f"Scan started for {repo_path}. New issues will appear in GitHub shortly."}


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
