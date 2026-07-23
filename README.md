# Tenable PCI ASV Scan Readiness — MCP Server

[![tests](https://github.com/amcdonnell-dot/pci-asv-readiness-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/amcdonnell-dot/pci-asv-readiness-mcp/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

An MCP server that sits between an AI assistant and Tenable's Vulnerability Management API and tells you whether a PCI Quarterly External scan is actually ready for ASV attestation — before you submit it and find out the hard way.

## Why this exists

Tenable's ASV Workbench doesn't forgive an undisputed failure: every finding at Medium severity or above needs a disposition — remediate it or dispute it — and a few conditions (malware/backdoor indicators, unsupported software) fail the scan outright no matter what their CVSS score says. Working that out by hand means trawling the raw scan output, cross-referencing the ASV Program Guide, and guessing at which findings are actually worth disputing versus just patching.

This server does that work for you. It pulls a scan, filters it down to what actually matters for PCI (Info/Low noise gets dropped, but automatic-fail conditions are kept regardless of their scored severity), computes a 0–100 readiness score, and builds a dispute-prep worksheet keyed to the three reasons Tenable's Workbench will actually accept: False Positive, Compensating Controls, Exception.

Everything the score and worksheet are based on lives in plain, unit-tested Python functions (no LLM calls, no guessing) — the AI assistant is there to drive the tools and explain the output, not to invent the analysis.

## Quick start

You'll need a Tenable VM account with a PCI ASV license and API keys, and Python 3.10+.

```bash
git clone https://github.com/amcdonnell-dot/pci-asv-readiness-mcp.git
cd pci-asv-readiness-mcp
```

**Recommended — run it with [uv](https://docs.astral.sh/uv/), no manual install step:**

```json
{
  "mcpServers": {
    "tenable-pci-asv-readiness": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/pci-asv-readiness-mcp", "pci-asv-readiness-mcp"],
      "env": {
        "TENABLE_ACCESS_KEY": "your-access-key",
        "TENABLE_SECRET_KEY": "your-secret-key"
      }
    }
  }
}
```

Drop that into Claude Desktop's or Claude Code's MCP config, swap in your real path and keys, and restart the client. The first launch builds a virtual environment and installs dependencies automatically — there's nothing to activate and nothing to remember.

**Or with pip, if you'd rather manage the venv yourself:**

```bash
pip install -e .
```

```json
{
  "mcpServers": {
    "tenable-pci-asv-readiness": {
      "command": "pci-asv-readiness-mcp",
      "env": {
        "TENABLE_ACCESS_KEY": "your-access-key",
        "TENABLE_SECRET_KEY": "your-secret-key"
      }
    }
  }
}
```

(`pci-asv-readiness-mcp` is the console script installed by the package — no need to point at a file path.)

**Sanity-check it without an MCP client:**

```bash
export TENABLE_ACCESS_KEY=your-access-key
export TENABLE_SECRET_KEY=your-secret-key
python smoke_test.py            # resolves the template, lists your PCI scans
python smoke_test.py <scan_id>  # full analysis of one scan
```

It only issues GET requests, so it's safe to point at a live account.

**Run the tests** (pure functions — no network, no credentials):

```bash
pip install -e ".[dev]"
pytest
```

## Tools

| Tool | What it returns |
|---|---|
| `resolve_pci_template` | The live UUID of the "PCI Quarterly External Scan" template for this account |
| `list_pci_scans` | Scans built on that template (id, name, status, last modified) |
| `get_pci_failing_findings` | PCI-impacting findings only, annotated with severity, auto-fail status, likely-false-positive pattern, and dispute category; Info/Low stripped with a count |
| `asv_readiness_score` | Advisory 0–100 composite with subscores: finding burden (40%), disputability (15%), automatic-fail exposure (20%), scan health (15%), timing (10%, only when a `compliance_deadline` is supplied). Unassessable dimensions are reported as `not_assessed` and excluded, with weights renormalized |
| `prepare_dispute_worksheet` | Per-finding evidence expectations, plausible Workbench dispute reasons, and customer questions. By default (`analysis_depth="smart"`) also fetches per-host plugin output for the categories where it strengthens a dispute, parses what the scanner actually observed (banner, detected vs fixed version, negotiated weak ciphers), and generates finding-specific verification commands and dispute questions from it |
| `get_finding_evidence` | Deep-dive on one finding: raw plugin output across affected hosts, parsed evidence fields, and an evidence plan (verification commands + dispute questions) grounded in what the scanner actually saw |
| `generate_html_report` | Self-contained HTML readiness report — score with subscore bars, action plan, "what moves the score" table, findings, dispute worksheet. Opens offline, prints cleanly to PDF |
| `research_finding` | Research brief for an unfamiliar finding: Tenable's full plugin metadata plus scanner observations plus a deterministic first guess at the dispute angle, open research questions, and suggested web queries — built for handoff to the shipped research subagent |
| `list_asv_workbench_scans` | Scans via the dedicated `GET /pci-asv/scans` endpoint, with a clear message if Tenable support hasn't enabled it for your account |

## When a finding doesn't fit a known pattern

Every scan turns up something the deterministic layer hasn't seen before — a new plugin, an unusual asset, a finding outside the known dispute categories. When the worksheet flags one (`research_recommended: true`), call `research_finding` to pull everything Tenable knows about the plugin (`GET /plugins/plugin/{id}`) plus the parsed scanner output, then spawn the `pci-finding-researcher` subagent shipped in `agents/pci-finding-researcher.md` (copy it into your project's `.claude/agents/` directory). It runs targeted web research against primary sources — vendor advisories, distro security notices, the ASV Program Guide — and comes back with a grounded call: what the finding actually is, whether to remediate or dispute it (and under which Workbench reason), what evidence to gather, and its confidence level with the gaps stated plainly. Note that the web research happens in your MCP client's agent runtime, not in this server — the server itself only ever talks to the Tenable API.

## How the score works

Each dimension is framed as a question a security team is actually asking on the way to a passing attestation, and each subscore comes back with concrete `next_actions` derived from the scan data — the number is there to support the plan, not the other way around. The composite also returns an ordered `action_plan` from wherever the scan currently stands to a submittable attestation (incident response first if there are compromise indicators, then non-disputable critical/high remediation, dispute evidence gathering in parallel, medium cleanup, rescan, then submit with 30+ days of buffer).

| Dimension (weight) | Question it answers |
|---|---|
| `remediation_workload` (40%) | How much remediation work stands between this scan and a passing attestation? Decays from 100 by severity-weighted penalties, sub-linear in instance count |
| `dispute_leverage` (15%) | How much of the failure burden could clear via evidence-backed disputes instead of patching? Names the candidate findings and the evidence to gather |
| `attestation_blockers` (20%) | Is anything present that fails the attestation regardless of CVSS? Malware/backdoor indicators zero it out (and route to IR); unsupported software caps it at 40 |
| `scan_reliability` (15%) | Can this scan be trusted as the attestation basis? Scan status and host coverage |
| `deadline_runway` (10%) | Is there time left for the ASV review/dispute cycle? Only assessed when a deadline is provided, compared against the recommended 30-day buffer |

All of it lives in pure functions in `pci_asv_readiness/scoring.py` — deterministic, unit-tested, and easy to read end to end if you want to check the math yourself.

**The score is advisory.** It's a readiness estimate built from the same data an ASV would see, not a compliance determination — only the actual ASV review of a submitted attestation decides that.

## What data leaves your machine

This server makes outbound calls to exactly one place: the Tenable API base URL (`https://cloud.tenable.com` by default, overridable via `TENABLE_BASE_URL`). No telemetry, no other endpoints. API keys come from environment variables and are never logged or written to disk.

## Rate limits

Tenable rate-limits per endpoint, and fetching per-host plugin output across a scan full of findings can trip it fast. Three things keep it under control: responses are cached in-process for the life of the server (so a score → worksheet → report sequence reuses one fetch instead of three), a per-scan host→plugin map means output is only fetched where a finding actually exists (roughly hosts + relevant-outputs calls, not hosts × findings), and 429s retry automatically with `Retry-After`/exponential backoff. The default `analysis_depth="smart"` also limits deep output analysis to categories where it actually strengthens a dispute (banner/version, SSL/TLS, automatic-fail, PCI policy); pass `"full"` for everything or `"none"` to skip it.

## Known limitations

- The score is advisory — see above. The grade bands describe readiness shape, not a compliance outcome.
- Severity filtering uses the PCI template's own severity assignments from the scan results (which map the CVSS 4.0+ fail line to Medium+). It doesn't recompute CVSS from vectors, and recast rules don't apply to PCI template scans anyway.
- Automatic-fail and false-positive-pattern detection are name/family heuristics (see `pci_asv_readiness/filtering.py`). They're intentionally conservative but can miss unusual plugin naming.
- Plugin-output parsing (`pci_asv_readiness/output_analysis.py`) recognizes common Nessus evidence formats — installed/fixed version lines, banners, cipher tables. Unusual output formats fall back to category-level guidance, and output retrieval is capped per finding (`max_hosts_per_finding`) to bound API calls on large scans.
- The dispute worksheet prepares evidence questions; it doesn't draft dispute text for you. Pair it with the `pci-asv-dispute-assistant` skill for drafting, and `pci-asv-attestation-preflight` for the pre-submission check.
- `GET /pci-asv/scans` requires access granted by Tenable support, separate from just holding a valid ASV license.

## License

MIT — see [LICENSE](LICENSE).
