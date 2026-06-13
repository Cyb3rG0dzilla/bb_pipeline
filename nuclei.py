import subprocess
import json
import shutil
import os
import tempfile
from rich.console import Console
import bedrock
import db
from config import NUCLEI_SEVERITY, NUCLEI_TEMPLATES

console = Console()


def _nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def run_nuclei(live_urls: list[str], program_id: str, target_id_map: dict = None) -> list[dict]:
    """
    Run nuclei against live hosts.
    target_id_map: {url: supabase_target_id} for DB linking.
    Returns list of findings.
    """
    if not live_urls:
        return []

    if not _nuclei_available():
        console.print("[yellow]  ⚠ nuclei not found — skipping nuclei phase[/yellow]")
        return []

    # Update templates silently first
    console.print("  [cyan]nuclei[/cyan] → updating templates")
    subprocess.run(["nuclei", "-update-templates", "-silent"],
                   capture_output=True, timeout=60)

    # Write targets to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(u for u in live_urls if u))
        tmp_targets = f.name

    # JSON output file
    tmp_out = tempfile.mktemp(suffix=".jsonl")

    console.print(f"  Running nuclei on [bold]{len(live_urls)}[/bold] targets "
                  f"(severity: {NUCLEI_SEVERITY})")
    try:
        subprocess.run([
            "nuclei",
            "-l", tmp_targets,
            "-t", NUCLEI_TEMPLATES,
            "-severity", NUCLEI_SEVERITY,
            "-json-export", tmp_out,
            "-silent",
            "-rate-limit", "100",
            "-bulk-size", "25",
            "-concurrency", "25",
            "-timeout", "10",
            "-retries", "1",
        ], capture_output=True, timeout=600)
    except subprocess.TimeoutExpired:
        console.print("[yellow]  nuclei timed out — parsing partial results[/yellow]")
    finally:
        os.unlink(tmp_targets)

    findings = _parse_nuclei_output(tmp_out, program_id, target_id_map or {})

    try:
        os.unlink(tmp_out)
    except Exception:
        pass

    return findings


def _parse_nuclei_output(jsonl_path: str, program_id: str, target_id_map: dict) -> list[dict]:
    """Parse nuclei JSONL output, store findings in DB."""
    findings = []

    if not os.path.exists(jsonl_path):
        return findings

    severity_map = {
        "critical": "critical",
        "high":     "high",
        "medium":   "medium",
        "low":      "low",
        "info":     "info",
    }

    with open(jsonl_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            sev     = severity_map.get(obj.get("info", {}).get("severity", "info"), "info")
            matched = obj.get("matched-at", obj.get("host", ""))
            name    = obj.get("info", {}).get("name", "Unknown")
            desc    = obj.get("info", {}).get("description", "")
            tmpl_id = obj.get("template-id", "")
            tags    = obj.get("info", {}).get("tags", [])

            target_id = target_id_map.get(obj.get("host")) or target_id_map.get(matched)

            finding = {
                "finding_type":       "nuclei",
                "vuln_class":         ",".join(tags[:3]) if tags else "misconfiguration",
                "risk":               sev,
                "title":              name,
                "description":        desc,
                "endpoint":           matched,
                "evidence":           json.dumps(obj.get("extracted-results", []))[:2000],
                "ai_reasoning":       obj.get("info", {}).get("remediation", ""),
                "nuclei_template_id": tmpl_id,
            }

            fid = db.store_finding(program_id, target_id, finding)
            findings.append({**finding, "id": fid})

            color = "red" if sev in ("critical", "high") else "yellow"
            console.print(f"  [[bold {color}]{sev.upper()}[/bold {color}]] [nuclei] {name} → {matched}")

    console.print(f"  Nuclei: [bold green]{len(findings)}[/bold green] findings")
    return findings


def generate_templates_for_findings(findings: list[dict], output_dir: str = "reports/templates") -> list[str]:
    """
    For high/critical findings without a known nuclei template,
    use Bedrock to generate a custom detection template.
    """
    os.makedirs(output_dir, exist_ok=True)
    generated = []

    for f in findings:
        if f.get("nuclei_template_id"):  # already has one
            continue
        if f.get("risk") not in ("critical", "high", "medium"):
            continue

        console.print(f"  [cyan]Generating template[/cyan] for: {f.get('title')}")
        yaml_content = bedrock.generate_nuclei_template(
            title=f.get("title", "Unknown"),
            endpoint=f.get("endpoint", "/"),
            description=f.get("description", "")
        )

        if not yaml_content or len(yaml_content) < 50:
            continue

        # Sanitize filename
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_"
                            for c in f.get("title", "finding").lower())[:50]
        path = os.path.join(output_dir, f"{safe_name}.yaml")
        with open(path, "w") as fp:
            fp.write(yaml_content)
        generated.append(path)
        console.print(f"  [green]  ✓ Saved:[/green] {path}")

    return generated
