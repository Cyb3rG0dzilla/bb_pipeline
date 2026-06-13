from supabase import create_client, Client
from rich.console import Console
from config import SUPABASE_URL, SUPABASE_KEY

console = Console()


def get_client() -> Client:
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in .env")
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def get_or_create_program(name: str, platform: str = None) -> str:
    """Return existing or newly created program UUID."""
    db = get_client()
    res = db.table("bb_programs").select("id").eq("name", name).execute()
    if res.data:
        return res.data[0]["id"]
    new = db.table("bb_programs").insert({"name": name, "platform": platform}).execute()
    return new.data[0]["id"]


def store_target(program_id: str, domain: str, subdomain: str = None,
                 url: str = None, status_code: int = None,
                 title: str = None, tech_stack: list = None) -> str | None:
    db = get_client()
    try:
        res = db.table("bb_targets").upsert({
            "program_id":   program_id,
            "domain":       domain,
            "subdomain":    subdomain or domain,
            "url":          url,
            "status_code":  status_code,
            "title":        title,
            "tech_stack":   tech_stack or [],
            "is_live":      True,
        }, on_conflict="subdomain,program_id").execute()
        return res.data[0]["id"] if res.data else None
    except Exception as e:
        console.print(f"[yellow]DB warn (target): {e}[/yellow]")
        return None


def store_js_finding(program_id: str, url: str, analysis: dict) -> None:
    db = get_client()
    try:
        db.table("bb_js_files").upsert({
            "program_id":      program_id,
            "url":             url,
            "analyzed":        True,
            "analysis_result": analysis,
        }, on_conflict="url").execute()
    except Exception as e:
        console.print(f"[yellow]DB warn (js_file): {e}[/yellow]")


def store_finding(program_id: str, target_id: str | None, finding: dict) -> str | None:
    db = get_client()
    try:
        res = db.table("bb_findings").insert({
            "program_id":         program_id,
            "target_id":          target_id,
            "finding_type":       finding.get("finding_type"),
            "vuln_class":         finding.get("vuln_class"),
            "risk":               finding.get("risk", "info"),
            "title":              finding.get("title"),
            "description":        finding.get("description"),
            "endpoint":           finding.get("endpoint"),
            "evidence":           finding.get("evidence", "")[:4000],
            "ai_reasoning":       finding.get("ai_reasoning", "")[:2000],
            "nuclei_template_id": finding.get("nuclei_template_id"),
            "status":             "pending",
        }).execute()
        return res.data[0]["id"] if res.data else None
    except Exception as e:
        console.print(f"[yellow]DB warn (finding): {e}[/yellow]")
        return None


def update_finding(finding_id: str, updates: dict) -> None:
    db = get_client()
    try:
        db.table("bb_findings").update(updates).eq("id", finding_id).execute()
    except Exception as e:
        console.print(f"[yellow]DB warn (update): {e}[/yellow]")


def get_actionable_findings(program_id: str) -> list:
    """Return high/critical pending findings ready for report drafting."""
    db = get_client()
    res = (db.table("bb_findings")
             .select("*")
             .eq("program_id", program_id)
             .eq("status", "pending")
             .in_("risk", ["critical", "high"])
             .execute())
    return res.data or []
