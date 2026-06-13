import os
import json
import urllib.request
from datetime import datetime
from rich.console import Console
import bedrock
import db
from config import SLACK_WEBHOOK, AUTO_REPORT_RISKS

console = Console()


def generate_reports(program_id: str, output_dir: str = "reports") -> list[str]:
    """
    Pull high/critical pending findings, draft reports, save as Markdown.
    Returns list of saved file paths.
    """
    os.makedirs(output_dir, exist_ok=True)

    findings = db.get_actionable_findings(program_id)
    if not findings:
        console.print("  [yellow]No high/critical pending findings to report.[/yellow]")
        return []

    console.print(f"  Drafting reports for [bold]{len(findings)}[/bold] finding(s)...")
    saved = []

    for finding in findings:
        risk  = finding.get("risk", "unknown")
        title = finding.get("title", "untitled")
        fid   = finding.get("id", "unknown")

        console.print(f"  [cyan]Drafting:[/cyan] [{risk.upper()}] {title}")

        draft = bedrock.draft_report(finding)
        if not draft:
            console.print(f"  [yellow]  Failed to draft report for {fid}[/yellow]")
            continue

        # Prepend metadata header
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        full_report = f"""---
id: {fid}
program_id: {program_id}
risk: {risk}
vuln_class: {finding.get('vuln_class', 'Unknown')}
endpoint: {finding.get('endpoint', 'N/A')}
status: draft
generated: {timestamp}
---

{draft}
"""

        # Safe filename
        safe = "".join(c if c.isalnum() or c in "-_" else "_"
                       for c in title.lower())[:60]
        fname = f"{risk}_{safe}_{fid[:8]}.md"
        fpath = os.path.join(output_dir, fname)

        with open(fpath, "w") as fp:
            fp.write(full_report)

        saved.append(fpath)
        console.print(f"  [green]  ✓ Saved:[/green] {fpath}")

        # Update DB with draft
        db.update_finding(fid, {"report_draft": draft[:8000]})

        # Slack alert for critical/high
        if risk in AUTO_REPORT_RISKS:
            _send_slack_alert(risk, title, finding.get("endpoint", ""), fid)

    console.print(f"  Reports: [bold green]{len(saved)}[/bold green] saved to {output_dir}/")
    return saved


def _send_slack_alert(risk: str, title: str, endpoint: str, finding_id: str) -> None:
    """Post a Slack notification for critical/high findings."""
    if not SLACK_WEBHOOK:
        return

    color = "#FF0000" if risk == "critical" else "#FFA500"
    payload = {
        "attachments": [{
            "color":  color,
            "title":  f"🔴 [{risk.upper()}] {title}",
            "fields": [
                {"title": "Endpoint",    "value": endpoint,    "short": True},
                {"title": "Finding ID",  "value": finding_id[:8], "short": True},
            ],
            "footer": "bb_pipeline | Bedrock AI",
        }]
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            SLACK_WEBHOOK,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
        console.print(f"  [green]  ✓ Slack alert sent[/green]")
    except Exception as e:
        console.print(f"  [yellow]  Slack alert failed: {e}[/yellow]")


def print_summary(program_id: str, program_name: str) -> None:
    """Print a final run summary table."""
    try:
        import db as _db
        client = _db.get_client()
        res = (client.table("bb_findings")
                     .select("risk")
                     .eq("program_id", program_id)
                     .execute())
        counts = {}
        for row in (res.data or []):
            r = row.get("risk", "unknown")
            counts[r] = counts.get(r, 0) + 1

        console.print()
        console.rule(f"[bold]Pipeline Summary — {program_name}[/bold]")
        for risk_level in ("critical", "high", "medium", "low", "info"):
            n = counts.get(risk_level, 0)
            if n:
                color = {"critical": "red", "high": "red",
                         "medium": "yellow", "low": "cyan", "info": "white"}.get(risk_level, "white")
                console.print(f"  [{color}]{risk_level.upper():10}[/{color}] {n}")
        console.rule()
    except Exception:
        pass
