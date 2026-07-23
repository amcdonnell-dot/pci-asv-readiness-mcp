"""Research-brief builder for findings the deterministic layer doesn't recognize.

Every scan is different — new plugins, unusual assets, findings that don't fit
the known dispute patterns. Rather than shrugging with generic advice, this
module turns Tenable's own plugin metadata plus the scanner's observed output
into a structured research brief: what is known, what still needs answering,
and the exact web queries an agent (or human) should run to close the gaps.

Pure functions; no network access. The `research_finding` MCP tool feeds this
from the Tenable plugin-details endpoint, and the shipped
`pci-finding-researcher` subagent definition (agents/) consumes the brief.
"""

from __future__ import annotations


def normalize_plugin_attributes(plugin_meta: dict) -> dict:
    """Flatten GET /plugins/plugin/{id}'s attribute list into a simple dict.

    The endpoint returns {"attributes": [{"attribute_name": ..,
    "attribute_value": ..}, ...]} — repeated names (e.g. multiple cve/see_also
    entries) become lists.
    """
    out: dict = {
        "plugin_id": plugin_meta.get("id"),
        "plugin_name": plugin_meta.get("name"),
        "family": plugin_meta.get("family_name"),
    }
    multi = {"cve", "see_also", "xref", "bid"}
    for attr in plugin_meta.get("attributes", []) or []:
        name = attr.get("attribute_name")
        value = attr.get("attribute_value")
        if not name:
            continue
        if name in multi:
            out.setdefault(name, [])
            if value not in out[name]:
                out[name].append(value)
        elif name not in out:
            out[name] = value
    return out


def _dispute_angle(attrs: dict, parsed_outputs: list[dict]) -> str:
    """Deterministic first guess at the realistic path, from the metadata."""
    solution = (attrs.get("solution") or "").lower()
    has_cves = bool(attrs.get("cve"))
    distro_build = any(p.get("distro_packaged_build") for p in parsed_outputs)
    backport_note = any(p.get("backport_note_in_output") for p in parsed_outputs)

    if has_cves and (distro_build or backport_note):
        return (
            "Backport check first: CVE-based finding on a distro-packaged build. If the installed "
            "package post-dates the distro advisory fix, this is a False Positive dispute; "
            "otherwise remediation."
        )
    if "upgrade" in solution or "update" in solution:
        return (
            "Vendor solution is an upgrade — remediation + rescan is the likely path unless "
            "host-level evidence shows the fix is already present."
        )
    if any(w in solution for w in ("disable", "restrict", "filter", "configure", "remove")):
        return (
            "Vendor solution is a configuration change — usually faster to fix than to dispute. "
            "A dispute would need a specific reachability or compensating-control argument."
        )
    return (
        "No obvious pattern — research needed. Determine the actual risk mechanism before "
        "choosing between remediation, False Positive, Compensating Controls, or Exception."
    )


def build_research_brief(
    plugin_meta: dict,
    finding: dict,
    parsed_outputs: list[dict] | None = None,
) -> dict:
    """Assemble what's known + what needs research for one unrecognized finding."""
    attrs = normalize_plugin_attributes(plugin_meta)
    parsed_outputs = parsed_outputs or []
    cves = attrs.get("cve") or []

    web_queries = [f"Tenable plugin {attrs.get('plugin_id') or finding.get('plugin_id')} "
                   f"{attrs.get('plugin_name') or finding.get('plugin_name') or ''}".strip()]
    for cve in cves[:4]:
        web_queries.append(f"{cve} advisory fix")
    for p in parsed_outputs:
        if p.get("distro_packaged_build"):
            for cve in cves[:2]:
                web_queries.append(f"{cve} {p['distro_packaged_build'].split('-')[0]} security advisory")
            break
    if not cves:
        web_queries.append(
            f"{attrs.get('plugin_name') or finding.get('plugin_name')} PCI ASV dispute"
        )

    research_questions = [
        "What is the actual attack mechanism, and does it apply on the scanned network path?",
        "Is this finding version-inference (banner) based, or did the scanner confirm the "
        "condition directly? (Determines whether False Positive is even plausible.)",
    ]
    if cves:
        research_questions.append(
            "For each CVE: has the vendor/distro shipped a fix, and does the installed build "
            "include it?"
        )
    research_questions.append(
        "Per the PCI ASV Program Guide, is this finding category eligible for dispute at all "
        "(some conditions auto-fail regardless of evidence)?"
    )

    return {
        "known": {
            "plugin_id": attrs.get("plugin_id") or finding.get("plugin_id"),
            "plugin_name": attrs.get("plugin_name") or finding.get("plugin_name"),
            "family": attrs.get("family"),
            "synopsis": attrs.get("synopsis"),
            "description": (attrs.get("description") or "")[:1500],
            "solution": attrs.get("solution"),
            "cves": cves,
            "cvss3_base_score": attrs.get("cvss3_base_score"),
            "references": (attrs.get("see_also") or [])[:8],
            "scanner_observations": [
                {k: v for k, v in p.items()} for p in parsed_outputs
            ],
        },
        "dispute_angle_first_guess": _dispute_angle(attrs, parsed_outputs),
        "research_questions": research_questions,
        "suggested_web_queries": web_queries,
        "agent_instructions": (
            "If a research subagent is available (e.g. the pci-finding-researcher agent shipped "
            "with this server, or any web-search-capable agent), spawn it with this brief: have it "
            "run the suggested queries, answer the research questions, and return (1) a plain-"
            "language explanation of the finding, (2) the realistic disposition (remediate vs "
            "dispute, and under which Workbench reason), and (3) the evidence to gather. If no "
            "agent is available, answer the research questions yourself using the known facts "
            "above before advising the user."
        ),
    }
