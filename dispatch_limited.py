"""
Dispatch Devin sessions for existing issues with a 5 session limit.
Prioritizes by severity (highest first).
"""
import asyncio
import os
import sys
import time
import logging

import httpx

# Add app to path
sys.path.insert(0, '/app')

from app.database import SessionLocal
from app.models import SessionRecord
from app.devin_client import DevinClient
from app.main import build_devin_prompt, parse_severity_from_issue

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


async def dispatch_with_limit():
    """Dispatch Devin sessions respecting 5 concurrent session limit."""
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPO")
    label = os.environ.get("SECURITY_LABEL")

    if not token:
        log.error("GITHUB_TOKEN not set")
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }

    # Check current running sessions
    db = SessionLocal()
    try:
        running_count = db.query(SessionRecord).filter(
            SessionRecord.status.in_(["running", "new", "claimed"])
        ).count()

        log.info(f"Current running sessions: {running_count}/5")

        if running_count >= 5:
            log.info("Session limit reached. No new sessions will be created.")
            log.info("Wait for some sessions to complete, then run this script again.")
            return

        available_slots = 5 - running_count
        log.info(f"Available slots: {available_slots}")

        # Get existing session issue numbers
        existing_issue_numbers = {r.github_issue_number for r in db.query(SessionRecord).all()}
    finally:
        db.close()

    # Get all open issues with security label
    resp = httpx.get(
        f"https://api.github.com/repos/{repo}/issues",
        headers=headers,
        params={"state": "open", "labels": label, "per_page": 100}
    )
    resp.raise_for_status()
    issues = resp.json()

    # Filter to issues without sessions and calculate severity
    issues_with_severity = []
    for issue in issues:
        issue_num = issue["number"]
        if issue_num in existing_issue_numbers:
            continue

        severity_score, severity_label, vulnerability_count = parse_severity_from_issue(issue)
        issues_with_severity.append({
            "issue": issue,
            "severity_score": severity_score,
            "severity_label": severity_label,
            "vulnerability_count": vulnerability_count,
        })

    # Sort by severity (highest first)
    issues_with_severity.sort(key=lambda x: -x["severity_score"])

    log.info(f"Found {len(issues_with_severity)} issues without sessions")

    if not issues_with_severity:
        log.info("No new issues to dispatch. All done!")
        return

    # Dispatch up to available_slots sessions
    to_dispatch = issues_with_severity[:available_slots]

    log.info(f"Dispatching {len(to_dispatch)} session(s)...")

    devin = DevinClient()
    created = 0

    for item in to_dispatch:
        issue = item["issue"]
        issue_num = issue["number"]
        issue_title = issue["title"]
        severity_score = item["severity_score"]
        severity_label = item["severity_label"]
        vulnerability_count = item["vulnerability_count"]

        log.info(f"Creating session for issue #{issue_num} ({severity_label}, score={severity_score})")

        try:
            prompt = build_devin_prompt(issue, repo)
            tags = ["security", "sql-injection", f"issue-{issue_num}"]

            result = await devin.create_session(
                prompt=prompt,
                title=f"Fix #{issue_num}: {issue_title[:60]}",
                tags=tags,
                repos=[f"https://github.com/{repo}"],
            )

            session_id = result["session_id"]
            session_url = result["url"]

            # Save to database
            db = SessionLocal()
            record = SessionRecord(
                devin_session_id=session_id,
                devin_session_url=session_url,
                github_issue_number=issue_num,
                github_issue_title=issue_title,
                github_repo=repo,
                status="running",
                created_at=int(time.time()),
                severity_score=severity_score,
                severity_label=severity_label,
                vulnerability_count=vulnerability_count,
            )
            db.add(record)
            db.commit()
            db.close()

            log.info(f"✓ Created session {session_id} for issue #{issue_num}")
            log.info(f"  URL: {session_url}")
            created += 1

            # Rate limit
            await asyncio.sleep(2)
        except Exception as e:
            log.error(f"✗ Failed to create session for issue #{issue_num}: {e}")

    log.info(f"Done! Created {created}/{len(to_dispatch)} new sessions.")
    log.info(f"Total running: {running_count + created}/5")

    remaining = len(issues_with_severity) - len(to_dispatch)
    if remaining > 0:
        log.info(f"{remaining} issues remaining. Run this script again after some sessions complete.")


if __name__ == "__main__":
    asyncio.run(dispatch_with_limit())
