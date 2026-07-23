"""Tenable PCI ASV Scan Readiness — MCP server.

Exposes deterministic tools over the Tenable Vulnerability Management API for
assessing how set-up-for-success a PCI Quarterly External scan is before the
ASV attestation workflow: template resolution, scan listing, PCI-impacting
finding filtering (CVSS 4.0+/Medium+ plus automatic-fail conditions), an
advisory ASV Readiness Score, and a dispute-preparation worksheet.

Run: `python server.py` (stdio transport).
Requires TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY environment variables.
"""

from __future__ import annotations

from datetime import date, datetime

from mcp.server.fastmcp import FastMCP

from pci_asv_readiness.filtering import filter_pci_findings
from pci_asv_readiness.output_analysis import build_evidence_plan, parse_plugin_output
from pci_asv_readiness.scoring import readiness_score
from pci_asv_readiness.tenable_client import TenableClient
from pci_asv_readiness.worksheet import DISPUTE_GUIDES

mcp = FastMCP("tenable-pci-asv-readiness")

_client: TenableClient | None = None


def _get_client() -> TenableClient:
    global _client
    if _client is None:
        _client = TenableClient()
    return _client


@mcp.tool()
def resolve_pci_template() -> dict:
    """Resolve the 'PCI Quarterly External Scan' template UUID at runtime via
    GET /editor/scan/templates. UUIDs are looked up live rather than hardcoded."""
    template = _get_client().resolve_pci_template()
    if template is None:
        return {
            "found": False,
            "message": "No template titled 'PCI Quarterly External Scan' visible to this account. "
            "Check the account's license/permissions in Tenable VM.",
        }
    return {"found": True, **template}


@mcp.tool()
def list_pci_scans() -> dict:
    """List scans built on the PCI Quarterly External Scan template (matched by
    template UUID), with id, name, status, and last modification time."""
    client = _get_client()
    template = client.resolve_pci_template()
    if template is None:
        return {"scans": [], "message": "PCI template not found for this account."}
    uuid = template["uuid"]
    scans = [
        {
            "id": s.get("id"),
            "name": s.get("name"),
            "status": s.get("status"),
            "last_modification_date": s.get("last_modification_date"),
        }
        for s in client.list_scans()
        if s.get("template_uuid") == uuid
    ]
    return {"template_uuid": uuid, "scans": scans, "count": len(scans)}


@mcp.tool()
def get_pci_failing_findings(scan_id: int) -> dict:
    """Fetch a scan's aggregate results and return only PCI-impacting findings:
    severity Medium+ (the CVSS 4.0+ ASV fail line) plus automatic-fail
    conditions (malware/backdoors, unsupported software) regardless of severity.
    Info/Low findings that don't block compliance are stripped (count reported).
    Each finding is annotated with severity label, automatic-fail status,
    likely-false-positive pattern flag, and dispute category."""
    details = _get_client().scan_details(scan_id)
    result = filter_pci_findings(details.get("vulnerabilities", []))
    info = details.get("info", {}) or {}
    return {
        "scan_id": scan_id,
        "scan_name": info.get("name"),
        "scan_status": info.get("status"),
        "host_count": info.get("hostcount"),
        "failing_findings": result["failing"],
        "failing_count": len(result["failing"]),
        "stripped_info_low_count": result["stripped_count"],
        "note": "Severity here follows the PCI template's own scoring; recast rules do not apply "
        "to PCI template scans. Every failing finding must be remediated or disputed before "
        "attestation — an undisputed failure causes automatic rejection.",
    }


@mcp.tool()
def asv_readiness_score(scan_id: int, compliance_deadline: str | None = None) -> dict:
    """Compute the advisory ASV Readiness Score (0-100) for a PCI scan. Each
    dimension answers a question a security team asks on the way to a passing
    attestation, and carries concrete next_actions derived from the data:
    remediation_workload (40%) "how much must we fix?", dispute_leverage (15%)
    "what could clear via evidence-backed disputes?", attestation_blockers (20%)
    "does anything fail us regardless of CVSS?", scan_reliability (15%) "can we
    trust this scan as our basis?", deadline_runway (10%, only when
    compliance_deadline YYYY-MM-DD is provided) "do we have time for the review
    cycle?". Also returns an ordered action_plan from this scan to a
    submittable attestation. When presenting results to the user, lead with the
    action plan and next_actions — the numbers support the plan, not the other
    way around. Unassessable dimensions are reported as not_assessed and
    excluded with weights renormalized. Advisory only — the ASV review
    determines compliance."""
    details = _get_client().scan_details(scan_id)
    result = filter_pci_findings(details.get("vulnerabilities", []))

    days = None
    if compliance_deadline:
        try:
            deadline = datetime.strptime(compliance_deadline, "%Y-%m-%d").date()
            days = (deadline - date.today()).days
        except ValueError:
            return {"error": f"compliance_deadline must be YYYY-MM-DD, got {compliance_deadline!r}"}

    score = readiness_score(result["failing"], details.get("info", {}), days)
    score["scan_id"] = scan_id
    score["scan_name"] = (details.get("info") or {}).get("name")
    return score


# Categories where per-host plugin output materially strengthens the dispute
# case; config/info-disclosure findings mostly need remediation, not output text.
_SMART_ANALYSIS_CATEGORIES = {"banner_version", "ssl_tls", "automatic_fail", "pci_policy"}


@mcp.tool()
def prepare_dispute_worksheet(
    scan_id: int, analysis_depth: str = "smart", max_hosts_per_finding: int = 3
) -> dict:
    """Build a dispute-preparation worksheet for every PCI-impacting finding in
    a scan: the finding, its category, the plausible Workbench dispute reasons
    (of the three Tenable accepts: False Positive, Compensating Controls,
    Exception), the evidence a reviewer expects (with when/where/how provenance),
    and the questions the customer must answer before a dispute is drafted.

    analysis_depth controls per-host plugin-output analysis (the banner the
    scanner grabbed, detected vs fixed versions, negotiated weak ciphers):
    "smart" (default) analyzes only categories where output text materially
    strengthens a dispute (banner/version checks, SSL/TLS, automatic-fail, PCI
    policy plugins) — keeping API calls low on large scans; "full" analyzes
    every failing finding; "none" skips output fetches entirely. Fetches are
    cached and 429s retry with backoff, so re-running is cheap.
    max_hosts_per_finding bounds hosts analyzed per finding.
    Pairs with the pci-asv-dispute-assistant skill for drafting the actual text."""
    if analysis_depth not in ("smart", "full", "none"):
        return {"error": f"analysis_depth must be 'smart', 'full', or 'none', got {analysis_depth!r}"}
    client = _get_client()
    details = client.scan_details(scan_id)
    result = filter_pci_findings(details.get("vulnerabilities", []))
    worksheet = []
    for v in result["failing"]:
        guide = DISPUTE_GUIDES.get(v["dispute_category"], DISPUTE_GUIDES["other"])
        item = {
            "plugin_id": v.get("plugin_id"),
            "plugin_name": v.get("plugin_name"),
            "severity": v.get("severity_label"),
            "instances": v.get("count", 1),
            "category": guide["label"],
            "plausible_workbench_reasons": guide["plausible_workbench_reasons"],
            "evidence_expected": guide["evidence_expected"],
            "customer_questions": list(guide["customer_questions"]),
            "note": guide["note"],
        }
        if v["dispute_category"] == "other":
            item["research_recommended"] = True
            item["research_hint"] = (
                f"Unrecognized finding pattern — call research_finding(scan_id={scan_id}, "
                f"plugin_id={v.get('plugin_id')}) for Tenable's plugin metadata and a research "
                "brief, and spawn the pci-finding-researcher subagent (shipped in agents/) if "
                "available to close the remaining gaps."
            )
        analyze_this = analysis_depth == "full" or (
            analysis_depth == "smart" and v["dispute_category"] in _SMART_ANALYSIS_CATEGORIES
        )
        if analyze_this and v.get("plugin_id"):
            outputs = client.outputs_for_plugin(
                scan_id, v["plugin_id"], max_hosts=max_hosts_per_finding
            )
            per_host = []
            for out in outputs:
                parsed = parse_plugin_output(out.get("plugin_output", ""))
                plan = build_evidence_plan(
                    v["dispute_category"],
                    v.get("plugin_name", ""),
                    parsed,
                    hostname=out.get("hostname") or "affected host",
                    port=(out.get("ports") or [None])[0],
                )
                per_host.append(
                    {
                        "hostname": out.get("hostname"),
                        "ports": out.get("ports"),
                        "parsed_evidence": parsed,
                        **plan,
                    }
                )
            item["output_analysis"] = per_host
        worksheet.append(item)
    return {
        "scan_id": scan_id,
        "scan_name": (details.get("info") or {}).get("name"),
        "items": worksheet,
        "item_count": len(worksheet),
        "reminder": "Tenable requires every piece of dispute evidence to describe when, where, and "
        "how it was obtained. Undisputed failures cause automatic attestation rejection.",
    }


@mcp.tool()
def get_finding_evidence(scan_id: int, plugin_id: int, max_hosts: int = 5) -> dict:
    """Fetch and analyze the raw plugin output for one finding across affected
    hosts: the exact text the scanner recorded (banner, detected/fixed version,
    cipher tables), parsed into structured evidence, plus finding-specific
    verification commands and dispute questions built from that evidence."""
    client = _get_client()
    outputs = client.outputs_for_plugin(scan_id, plugin_id, max_hosts=max_hosts)
    if not outputs:
        return {
            "scan_id": scan_id,
            "plugin_id": plugin_id,
            "hosts": [],
            "message": "No plugin output found for this plugin on any host in the scan.",
        }
    # Reuse category logic off the first output's plugin context if available
    details = client.scan_details(scan_id)
    vuln = next(
        (v for v in details.get("vulnerabilities", []) or [] if v.get("plugin_id") == plugin_id),
        {},
    )
    from pci_asv_readiness.filtering import dispute_category

    category = dispute_category(vuln) if vuln else "other"
    hosts = []
    for out in outputs:
        parsed = parse_plugin_output(out.get("plugin_output", ""))
        plan = build_evidence_plan(
            category,
            vuln.get("plugin_name", ""),
            parsed,
            hostname=out.get("hostname") or "affected host",
            port=(out.get("ports") or [None])[0],
        )
        hosts.append(
            {
                "hostname": out.get("hostname"),
                "ports": out.get("ports"),
                "raw_plugin_output": out.get("plugin_output", "")[:4000],
                "parsed_evidence": parsed,
                **plan,
            }
        )
    return {
        "scan_id": scan_id,
        "plugin_id": plugin_id,
        "plugin_name": vuln.get("plugin_name"),
        "dispute_category": category,
        "hosts": hosts,
    }


@mcp.tool()
def generate_html_report(
    scan_id: int,
    output_path: str,
    compliance_deadline: str | None = None,
    analysis_depth: str = "smart",
    max_hosts_per_finding: int = 3,
) -> dict:
    """Generate a self-contained HTML readiness report for a PCI scan and write
    it to output_path. Includes the readiness score with subscore bars, the
    PCI-impacting findings table (auto-fail and likely-false-positive flags),
    and the dispute-preparation worksheet with per-host plugin-output analysis.
    No external assets — opens offline in any browser and prints cleanly to PDF
    for customer/QSA handoff."""
    from pci_asv_readiness.report import render_html_report

    client = _get_client()
    details = client.scan_details(scan_id)
    result = filter_pci_findings(details.get("vulnerabilities", []))

    days = None
    if compliance_deadline:
        try:
            deadline = datetime.strptime(compliance_deadline, "%Y-%m-%d").date()
            days = (deadline - date.today()).days
        except ValueError:
            return {"error": f"compliance_deadline must be YYYY-MM-DD, got {compliance_deadline!r}"}
    score = readiness_score(result["failing"], details.get("info", {}), days)

    worksheet_items = []
    for v in result["failing"]:
        guide = DISPUTE_GUIDES.get(v["dispute_category"], DISPUTE_GUIDES["other"])
        item = {
            "plugin_name": v.get("plugin_name"),
            "severity": v.get("severity_label"),
            "category": guide["label"],
            "plausible_workbench_reasons": guide["plausible_workbench_reasons"],
            "evidence_expected": guide["evidence_expected"],
            "customer_questions": guide["customer_questions"],
            "note": guide["note"],
        }
        analyze_this = analysis_depth == "full" or (
            analysis_depth == "smart" and v["dispute_category"] in _SMART_ANALYSIS_CATEGORIES
        )
        if analyze_this and v.get("plugin_id"):
            per_host = []
            for out in client.outputs_for_plugin(scan_id, v["plugin_id"], max_hosts=max_hosts_per_finding):
                parsed = parse_plugin_output(out.get("plugin_output", ""))
                plan = build_evidence_plan(
                    v["dispute_category"], v.get("plugin_name", ""), parsed,
                    hostname=out.get("hostname") or "affected host",
                    port=(out.get("ports") or [None])[0],
                )
                per_host.append({"hostname": out.get("hostname"), "ports": out.get("ports"), **plan})
            item["output_analysis"] = per_host
        worksheet_items.append(item)

    html_text = render_html_report(
        scan_name=(details.get("info") or {}).get("name") or f"scan {scan_id}",
        scan_id=scan_id,
        score=score,
        failing=result["failing"],
        stripped_count=result["stripped_count"],
        worksheet_items=worksheet_items,
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_text)
    return {
        "written_to": output_path,
        "asv_readiness_score": score["asv_readiness_score"],
        "failing_count": len(result["failing"]),
        "bytes": len(html_text),
    }


@mcp.tool()
def research_finding(scan_id: int, plugin_id: int, max_hosts: int = 3) -> dict:
    """Build a structured research brief for a finding the analysis layer
    doesn't recognize (dispute category 'other', or anything the user asks
    about). Pulls Tenable's full plugin metadata (synopsis, description,
    solution, CVEs, references) plus the scanner's actual per-host output, and
    returns: what is known, a deterministic first guess at the dispute angle,
    the research questions still open, suggested web-search queries, and
    instructions for spawning a research subagent (the pci-finding-researcher
    agent definition ships with this server in agents/). Use this whenever a
    finding is unfamiliar — every scan has different plugins and assets, and
    grounded research beats generic advice."""
    from pci_asv_readiness.research import build_research_brief

    client = _get_client()
    plugin_meta = client.plugin_details(plugin_id)
    details = client.scan_details(scan_id)
    finding = next(
        (v for v in details.get("vulnerabilities", []) or [] if v.get("plugin_id") == plugin_id),
        {"plugin_id": plugin_id},
    )
    parsed_outputs = []
    for out in client.outputs_for_plugin(scan_id, plugin_id, max_hosts=max_hosts):
        parsed = parse_plugin_output(out.get("plugin_output", ""))
        parsed["hostname"] = out.get("hostname")
        parsed["ports"] = out.get("ports")
        parsed_outputs.append(parsed)
    return build_research_brief(plugin_meta, finding, parsed_outputs)


@mcp.tool()
def list_asv_workbench_scans() -> dict:
    """List scans via the dedicated PCI ASV API (GET /pci-asv/scans). This
    endpoint is gated behind a Tenable support request even for valid ASV
    licenses; returns a clear message when access hasn't been granted."""
    return _get_client().list_asv_scans()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
