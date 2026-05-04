"""
Backfill severity scores for existing sessions by fetching GitHub issue data.
"""
import asyncio
import os
import sys
import logging

import httpx

# Add app to path
sys.path.insert(0, '/app')

from app.database import SessionLocal
from app.models import SessionRecord
from app.main import parse_severity_from_issue

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


async def backfill_severity():
    """Backfill severity scores for existing sessions."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        log.error("GITHUB_TOKEN not set")
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }

    db = SessionLocal()
    try:
        # Get all sessions without severity scores
        records = db.query(SessionRecord).filter(
            (SessionRecord.severity_score == None) | (SessionRecord.severity_score == 0)
        ).all()

        log.info(f"Found {len(records)} sessions without severity scores")

        updated = 0
        async with httpx.AsyncClient() as client:
            for record in records:
                issue_num = record.github_issue_number
                repo = record.github_repo

                log.info(f"Fetching issue #{issue_num} from {repo}...")

                try:
                    # Fetch the issue from GitHub
                    issue_url = f"https://api.github.com/repos/{repo}/issues/{issue_num}"
                    resp = await client.get(issue_url, headers=headers)

                    if resp.status_code == 200:
                        issue = resp.json()
                        severity_score, severity_label, vulnerability_count = parse_severity_from_issue(issue)

                        record.severity_score = severity_score
                        record.severity_label = severity_label
                        record.vulnerability_count = vulnerability_count

                        log.info(f"✓ Updated issue #{issue_num}: {severity_label} (score={severity_score}, count={vulnerability_count})")
                        updated += 1
                    else:
                        log.warning(f"✗ Failed to fetch issue #{issue_num}: {resp.status_code}")

                    # Rate limit
                    await asyncio.sleep(0.5)

                except Exception as e:
                    log.error(f"✗ Error processing issue #{issue_num}: {e}")

        db.commit()
        log.info(f"Done! Updated {updated}/{len(records)} sessions with severity scores.")

    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(backfill_severity())
