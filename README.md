# Superset Security Bot

An event-driven automation that detects SQL injection vulnerabilities in Apache Superset, creates GitHub issues, and dispatches Devin to fix them and open PRs automatically.

## Architecture

```
Daily cron (scanner)
  └── Scans repo for SQL injection patterns (CWE-89)
  └── Creates GitHub issues labeled "security"
        │
        ▼
GitHub Webhook (issues.opened)
  └── Fires when new security issue is opened
  └── Calls webhook server
        │
        ▼
Webhook Server (FastAPI)
  └── Validates signature
  └── Dispatches Devin session with fix instructions
  └── Tracks session in SQLite
        │
        ▼
Devin
  └── Clones repo, finds vulnerable line, applies fix
  └── Opens pull request
        │
        ▼
Observability Dashboard (/dashboard)
  └── Sessions, statuses, PRs opened, success rate
```

## Prerequisites

- Docker + Docker Compose
- [Devin API key](https://app.devin.ai/settings/api-keys) (`cog_...`) and org ID (`org-...`)
- GitHub personal access token with `repo` scope
- A public URL for the webhook (use [ngrok](https://ngrok.com) locally)

## Setup

### 1. Configure environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

### 2. Start the server

```bash
docker compose up --build
```

The webhook server starts on `http://localhost:8000`.

### 3. Expose locally with ngrok (for testing)

```bash
ngrok http 8000
# Copy the https://xxxx.ngrok.io URL
```

### 4. Register the GitHub webhook

In your fork → **Settings → Webhooks → Add webhook**:

| Field | Value |
|-------|-------|
| Payload URL | `https://xxxx.ngrok.io/webhook/github` |
| Content type | `application/json` |
| Secret | Same value as `GITHUB_WEBHOOK_SECRET` in `.env` |
| Events | **Issues** only |

### 5. Trigger the flow

**Option A — Manual (instant demo):**
```bash
gh issue create \
  --repo lindahuang3846/superset \
  --label security \
  --title "Security: SQL injection risk in superset/db_engine_specs/hive.py" \
  --body "..."
```
The webhook fires immediately, Devin picks it up within seconds.

**Option B — Daily scan (automated):**
The `scanner` container runs at 09:00 UTC daily. To run it now:
```bash
docker compose run --rm scanner python -m app.scanner
```

## Observability

| Endpoint | Description |
|----------|-------------|
| `GET /dashboard` | HTML dashboard — sessions, statuses, PRs, success rate |
| `GET /sessions` | JSON API — all tracked sessions |
| `GET /health` | Health check |

The dashboard answers: *"Is this working?"*
- **Sessions started** — how many issues were picked up
- **Completed / Failed** — success/failure signals
- **PRs Opened** — throughput (did Devin actually produce output?)
- **Success Rate** — percentage of sessions that completed

## Project Layout

```
superset-security-bot/
├── app/
│   ├── main.py          # FastAPI webhook server + /dashboard + /sessions
│   ├── devin_client.py  # Devin API wrapper (create/get/list sessions)
│   ├── scanner.py       # Daily scan: grep repo → create GitHub issues
│   ├── observability.py # Dashboard HTML + metrics
│   ├── models.py        # SQLAlchemy session tracking model
│   └── database.py      # SQLite setup
├── Dockerfile
├── docker-compose.yml   # webhook-server + scanner (cron) services
├── requirements.txt
└── .env.example
```

## How Devin fixes the issues

Each Devin session receives a prompt that:
1. Points to the exact file and line numbers from the issue
2. Instructs Devin to replace f-string identifier interpolation with `dialect.identifier_preparer.quote()`
3. Tells Devin to remove the `# noqa: S608` suppression comment
4. Requires a PR titled `fix(security): <issue title>` with `Closes #N`

The fix pattern is consistent across all 5 issues, making this highly automatable.
