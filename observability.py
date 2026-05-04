"""
Observability: in-memory counters + HTML dashboard.
"""

import json
import logging
import time
from collections import defaultdict

log = logging.getLogger(__name__)

_metrics: dict = defaultdict(int)


def record_session_start(session_id: str, issue_number: int) -> None:
    _metrics["sessions_started"] += 1
    log.info("[METRIC] sessions_started=%d issue=#%d session=%s",
             _metrics["sessions_started"], issue_number, session_id)


def get_dashboard_html(records: list) -> str:
    # Sort by severity score (descending), then by created_at (newest first)
    sorted_records = sorted(records, key=lambda r: (-(r.severity_score or 0), -r.created_at))

    total = len(sorted_records)
    running = sum(1 for r in sorted_records if r.status in ("new", "claimed", "running"))
    success = sum(1 for r in sorted_records if r.status == "exit")
    failed = sum(1 for r in sorted_records if r.status in ("error", "suspended", "rate_limited"))
    prs_opened = sum(1 for r in sorted_records if r.pull_request_url)
    success_rate = f"{(success / total * 100):.0f}%" if total else "—"

    rows = ""
    for idx, r in enumerate(sorted_records):
        status_color = {
            "exit": "#22c55e",
            "running": "#3b82f6",
            "new": "#3b82f6",
            "claimed": "#3b82f6",
            "error": "#ef4444",
            "suspended": "#f97316",
            "rate_limited": "#eab308",
        }.get(r.status, "#6b7280")

        # Severity badge
        severity_label = r.severity_label or "Low"
        severity_score = r.severity_score or 0
        severity_class = {
            "Critical": "severity-critical",
            "High": "severity-high",
            "Medium": "severity-medium",
            "Low": "severity-low",
        }.get(severity_label, "severity-low")

        pr_link = (
            f'<a href="{r.pull_request_url}" target="_blank" onclick="event.stopPropagation()">View PR</a>'
            if r.pull_request_url
            else "—"
        )
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(r.created_at))

        # Parse logs
        logs = json.loads(r.logs or "[]")
        logs_html = ""
        if logs:
            for log_entry in logs:
                log_ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(log_entry["timestamp"]))
                event_icon = {
                    "webhook_received": "📩",
                    "devin_session_created": "🚀",
                    "devin_session_failed": "❌",
                    "status_updated": "🔄",
                    "pr_created": "🔀",
                    "pr_merged": "✅",
                }.get(log_entry["event"], "📝")
                logs_html += f"""
                <div class="log-entry">
                  <span class="log-time">{log_ts}</span>
                  <span class="log-icon">{event_icon}</span>
                  <span class="log-event">{log_entry['event'].replace('_', ' ').title()}</span>
                  <span class="log-details">{log_entry.get('details', '')}</span>
                </div>
                """
        else:
            logs_html = '<div class="log-entry"><span class="log-details">No logs available</span></div>'

        rows += f"""
        <tr class="session-row" onclick="toggleDetails('details-{idx}')">
          <td><span class="expand-icon" id="icon-{idx}">▶</span> #{r.github_issue_number}</td>
          <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{r.github_issue_title}</td>
          <td><span class="severity-badge {severity_class}" title="Score: {severity_score}/100">{severity_label}</span></td>
          <td><span style="color:{status_color};font-weight:600">{r.status}</span></td>
          <td><a href="{r.devin_session_url}" target="_blank" onclick="event.stopPropagation()">Session</a></td>
          <td>{pr_link}</td>
          <td>{ts}</td>
        </tr>
        <tr id="details-{idx}" class="details-row">
          <td colspan="7">
            <div class="details-content">
              <h3>Event Timeline</h3>
              <div class="logs-container">
                {logs_html}
              </div>
            </div>
          </td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html>
<head>
  <title>Superset Security Bot</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }}
    .header {{ background: #1e293b; padding: 24px 32px; border-bottom: 1px solid #334155; }}
    .header h1 {{ margin: 0; font-size: 1.4rem; }}
    .header p {{ margin: 4px 0 0; color: #94a3b8; font-size: 0.9rem; }}
    .metrics {{ display: flex; gap: 16px; padding: 24px 32px; flex-wrap: wrap; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
             padding: 16px 24px; min-width: 140px; }}
    .card .label {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: .05em; }}
    .card .value {{ font-size: 2rem; font-weight: 700; margin-top: 4px; }}
    .banner {{ margin: 0 32px; padding: 14px 18px; background: #1e3a5f;
               border: 1px solid #2563eb; border-radius: 8px;
               display: flex; align-items: center; justify-content: space-between; gap: 16px; }}
    .banner-text {{ font-size: 0.875rem; color: #93c5fd; }}
    .banner-text strong {{ color: #e2e8f0; }}
    .scan-btn {{ background: #2563eb; color: #fff; border: none; border-radius: 6px;
                 padding: 8px 18px; font-size: 0.875rem; font-weight: 600;
                 cursor: pointer; white-space: nowrap; }}
    .scan-btn:hover {{ background: #1d4ed8; }}
    .scan-btn:disabled {{ background: #334155; color: #64748b; cursor: not-allowed; }}
    .toast {{ display: none; margin: 12px 32px 0; padding: 10px 16px;
              background: #166534; border: 1px solid #16a34a; border-radius: 6px;
              font-size: 0.875rem; color: #86efac; }}
    .section {{ padding: 0 32px 32px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
    th {{ text-align: left; padding: 10px 12px; background: #1e293b;
          border-bottom: 1px solid #334155; color: #94a3b8; font-weight: 500; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; }}
    .session-row {{ cursor: pointer; }}
    .session-row:hover td {{ background: #1e293b55; }}
    .details-row {{ display: none; }}
    .details-row.expanded {{ display: table-row; }}
    .details-content {{ padding: 16px; background: #1e293b; border-radius: 6px; margin: 8px 0; }}
    .details-content h3 {{ margin: 0 0 12px 0; color: #e2e8f0; font-size: 0.9rem; }}
    .logs-container {{ background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 12px; max-height: 400px; overflow-y: auto; }}
    .log-entry {{ display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid #1e293b; }}
    .log-entry:last-child {{ border-bottom: none; }}
    .log-time {{ color: #64748b; font-size: 0.75rem; min-width: 140px; }}
    .log-icon {{ font-size: 1.1rem; }}
    .log-event {{ color: #94a3b8; font-weight: 600; min-width: 150px; }}
    .log-details {{ color: #cbd5e1; flex: 1; }}
    .expand-icon {{ display: inline-block; transition: transform 0.2s; margin-right: 6px; font-size: 0.7rem; }}
    .expand-icon.expanded {{ transform: rotate(90deg); }}
    a {{ color: #60a5fa; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .severity-badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px;
                       font-size: 0.75rem; font-weight: 600; }}
    .severity-critical {{ background: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626; }}
    .severity-high {{ background: #7c2d12; color: #fdba74; border: 1px solid #ea580c; }}
    .severity-medium {{ background: #713f12; color: #fde047; border: 1px solid #eab308; }}
    .severity-low {{ background: #27272a; color: #a1a1aa; border: 1px solid #52525b; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>Superset Security Bot — Observability Dashboard</h1>
    <p>Automated SQL injection remediation via Devin</p>
  </div>
  <div style="height:16px"></div>
  <div class="banner">
    <span class="banner-text">
      🕛 <strong>Scheduled scan:</strong> Every night at midnight Devin scans the repository
      and automatically opens GitHub issues for any new SQL injection vulnerabilities found.
    </span>
    <button class="scan-btn" id="scanBtn" onclick="triggerScan()">Run Scan Now</button>
  </div>
  <div class="toast" id="toast"></div>
  <div class="metrics">
    <div class="card">
      <div class="label">Total Sessions</div>
      <div class="value">{total}</div>
    </div>
    <div class="card">
      <div class="label">Running</div>
      <div class="value" style="color:#3b82f6">{running}</div>
    </div>
    <div class="card">
      <div class="label">Completed</div>
      <div class="value" style="color:#22c55e">{success}</div>
    </div>
    <div class="card">
      <div class="label">Failed</div>
      <div class="value" style="color:#ef4444">{failed}</div>
    </div>
    <div class="card">
      <div class="label">PRs Opened</div>
      <div class="value" style="color:#a78bfa">{prs_opened}</div>
    </div>
    <div class="card">
      <div class="label">Success Rate</div>
      <div class="value">{success_rate}</div>
    </div>
  </div>
  <div class="section">
    <table>
      <thead>
        <tr>
          <th>Issue</th><th>Title</th><th>Severity</th><th>Status</th>
          <th>Devin Session</th><th>Pull Request</th><th>Started</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <script>
    function toggleDetails(id) {{
      const detailsRow = document.getElementById(id);
      const iconId = id.replace('details-', 'icon-');
      const icon = document.getElementById(iconId);

      if (detailsRow.classList.contains('expanded')) {{
        detailsRow.classList.remove('expanded');
        icon.classList.remove('expanded');
      }} else {{
        detailsRow.classList.add('expanded');
        icon.classList.add('expanded');
      }}
    }}

    async function triggerScan() {{
      const btn = document.getElementById('scanBtn');
      const toast = document.getElementById('toast');
      btn.disabled = true;
      btn.textContent = 'Scanning…';
      toast.style.display = 'none';
      try {{
        const res = await fetch('/scan/trigger', {{ method: 'POST' }});
        const data = await res.json();
        toast.textContent = data.message || 'Scan triggered successfully.';
        toast.style.background = '#166534';
        toast.style.borderColor = '#16a34a';
        toast.style.color = '#86efac';
      }} catch(e) {{
        toast.textContent = 'Failed to trigger scan: ' + e.message;
        toast.style.background = '#7f1d1d';
        toast.style.borderColor = '#dc2626';
        toast.style.color = '#fca5a5';
      }}
      toast.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Run Scan Now';
    }}
  </script>
</body>
</html>"""
