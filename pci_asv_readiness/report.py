"""Self-contained HTML report renderer for PCI ASV scan readiness.

Design principles applied deliberately:
- Visual hierarchy: readiness verdict first, blockers before detail, worksheet last.
- Severity is never encoded by color alone (text labels + badges) — WCAG 1.4.1.
- System font stack, 65-75ch measure, generous whitespace, consistent spacing scale.
- Semantic HTML (headings, tables, native <details> accordions — zero JavaScript).
- Self-contained: no CDN fonts/scripts, works offline and attaches cleanly to email.
- Print stylesheet so the report exports to PDF sensibly for QSA/customer handoff.

Pure function over already-computed data; no network access.
"""

from __future__ import annotations

import html
from datetime import date

_SEV_STYLES = {
    "critical": ("#7f1d1d", "#fef2f2"),
    "high": ("#9a3412", "#fff7ed"),
    "medium": ("#92400e", "#fffbeb"),
    "low": ("#374151", "#f9fafb"),
    "info": ("#374151", "#f9fafb"),
}


def _e(text) -> str:
    return html.escape(str(text if text is not None else ""))


def _sev_badge(label: str) -> str:
    fg, bg = _SEV_STYLES.get(label, ("#374151", "#f9fafb"))
    return (
        f'<span style="color:{fg};background:{bg};border:1px solid {fg}33;" '
        f'class="badge">{_e(label.upper())}</span>'
    )


def _score_band(score: float) -> tuple[str, str]:
    if score >= 90:
        return "#166534", "#f0fdf4"
    if score >= 70:
        return "#92400e", "#fffbeb"
    if score >= 40:
        return "#9a3412", "#fff7ed"
    return "#7f1d1d", "#fef2f2"


def render_html_report(
    scan_name: str,
    scan_id: int,
    score: dict,
    failing: list[dict],
    stripped_count: int,
    worksheet_items: list[dict] | None = None,
    generated_on: str | None = None,
) -> str:
    """Render the full readiness analysis as a single self-contained HTML page."""
    generated_on = generated_on or date.today().isoformat()
    composite = score.get("asv_readiness_score", 0)
    grade = score.get("grade", "")
    fg, bg = _score_band(composite)

    subscore_rows = ""
    for name, sub in (score.get("subscores") or {}).items():
        pct = max(0, min(100, sub.get("score", 0)))
        question = sub.get("question", "")
        actions = "".join(f"<li>{_e(a)}</li>" for a in sub.get("next_actions", []))
        subscore_rows += f"""
        <div class="sub">
          <div class="sub-head"><span>{_e(name.replace('_', ' ').title())}</span><span>{pct:g}</span></div>
          <div class="bar" role="img" aria-label="{_e(name)} subscore {pct:g} out of 100">
            <div class="bar-fill" style="width:{pct}%;background:{fg};"></div>
          </div>
          {f'<p class="sub-q">{_e(question)}</p>' if question else ''}
          {f'<ul class="sub-actions">{actions}</ul>' if actions else ''}
        </div>"""

    action_plan = score.get("action_plan") or []
    plan_html = ""
    if action_plan:
        steps = "".join(f"<li>{_e(s.split('. ', 1)[-1])}</li>" for s in action_plan)
        impact_html = ""
        impacts = score.get("score_impact") or []
        if impacts:
            rows = "".join(
                f"<tr><td>{_e(i['action'])}</td><td class='num'>{_e(i['findings_resolved'])}</td>"
                f"<td class='num'>{i['projected_score']:g}</td>"
                f"<td class='num'>+{i['score_gain']:g}</td></tr>"
                for i in impacts
            )
            impact_html = f"""
  <h2>What moves the score</h2>
  <table>
    <thead><tr><th>If you…</th><th class="num">Findings resolved</th>
    <th class="num">Projected score</th><th class="num">Gain</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>"""
        plan_html = f"""
  <h2>Your path to a submittable attestation</h2>
  <div class="card"><ol class="plan">{steps}</ol></div>{impact_html}"""
    not_assessed = score.get("not_assessed") or []
    na_html = (
        f'<p class="muted">Not assessed (excluded, weights renormalized): '
        f"{_e(', '.join(n.replace('_', ' ') for n in not_assessed))}</p>"
        if not_assessed
        else ""
    )

    auto_fails = [f for f in failing if f.get("auto_fail")]
    finding_rows = ""
    for f in failing:
        flags = []
        if f.get("auto_fail"):
            flags.append('<span class="badge badge-auto">AUTO-FAIL</span>')
        if f.get("likely_fp_pattern"):
            flags.append('<span class="badge badge-fp">Likely FP pattern</span>')
        finding_rows += f"""
        <tr>
          <td>{_sev_badge(f.get('severity_label', 'medium'))}</td>
          <td class="finding-name">{_e(f.get('plugin_name'))}</td>
          <td class="num">{_e(f.get('count', 1))}</td>
          <td>{' '.join(flags)}</td>
        </tr>"""

    worksheet_html = ""
    for item in worksheet_items or []:
        qs = "".join(f"<li>{_e(q)}</li>" for q in item.get("customer_questions", []))
        ev = "".join(f"<li>{_e(e)}</li>" for e in item.get("evidence_expected", []))
        reasons = _e(", ".join(item.get("plausible_workbench_reasons", [])))
        output_html = ""
        for oh in item.get("output_analysis", []) or []:
            observed = "".join(f"<li><code>{_e(s)}</code></li>" for s in oh.get("scanner_observed", []))
            cmds = "".join(f"<li><code>{_e(c)}</code></li>" for c in oh.get("verification_commands", []))
            oqs = "".join(f"<li>{_e(q)}</li>" for q in oh.get("dispute_questions", []))
            output_html += f"""
            <div class="host-block">
              <p class="host-name">{_e(oh.get('hostname') or 'affected host')}
                 {('· port ' + _e(', '.join(map(str, oh.get('ports') or [])))) if oh.get('ports') else ''}</p>
              {f'<p class="k">Scanner observed</p><ul>{observed}</ul>' if observed else ''}
              {f'<p class="k">Verify with</p><ul>{cmds}</ul>' if cmds else ''}
              {f'<p class="k">Questions to answer</p><ul>{oqs}</ul>' if oqs else ''}
            </div>"""
        worksheet_html += f"""
        <details>
          <summary><strong>{_e(item.get('plugin_name'))}</strong>
            &nbsp;{_sev_badge(item.get('severity', 'medium'))}</summary>
          <div class="detail-body">
            <p><span class="k">Category:</span> {_e(item.get('category'))}</p>
            <p><span class="k">Plausible Workbench reasons:</span> {reasons}</p>
            {f'<p class="k">Evidence a reviewer expects</p><ul>{ev}</ul>' if ev else ''}
            {f'<p class="k">Customer questions</p><ul>{qs}</ul>' if qs else ''}
            <p class="muted">{_e(item.get('note', ''))}</p>
            {output_html}
          </div>
        </details>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PCI ASV Readiness — {_e(scan_name)}</title>
<style>
  :root {{ --ink:#111827; --muted:#6b7280; --line:#e5e7eb; --paper:#ffffff; --wash:#f9fafb; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:var(--wash); color:var(--ink);
         font:16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
  .page {{ max-width: 860px; margin: 0 auto; padding: 32px 24px 64px; }}
  header {{ margin-bottom: 24px; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 4px; }}
  h2 {{ font-size: 1.125rem; margin: 32px 0 12px; }}
  .muted {{ color: var(--muted); font-size: .875rem; }}
  .card {{ background:var(--paper); border:1px solid var(--line); border-radius:12px; padding:20px 24px; }}
  .hero {{ display:flex; gap:24px; align-items:center; flex-wrap:wrap; }}
  .score {{ min-width:130px; text-align:center; padding:16px; border-radius:12px; }}
  .score .n {{ font-size:2.5rem; font-weight:700; line-height:1; }}
  .score .d {{ font-size:.75rem; letter-spacing:.05em; }}
  .grade {{ flex:1 1 300px; font-size:1.05rem; }}
  .sub {{ margin: 14px 0; }}
  .sub-head {{ display:flex; justify-content:space-between; font-size:.875rem; margin-bottom:4px; font-weight:600; }}
  .sub-q {{ margin:6px 0 2px; font-size:.8125rem; color:var(--muted); font-style:italic; }}
  .sub-actions {{ margin:2px 0 0; padding-left:18px; font-size:.8125rem; }}
  .plan li {{ margin:8px 0; }}
  .bar {{ height:8px; background:var(--line); border-radius:4px; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:4px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--paper);
           border:1px solid var(--line); border-radius:12px; overflow:hidden; }}
  th {{ text-align:left; font-size:.75rem; letter-spacing:.05em; text-transform:uppercase;
        color:var(--muted); padding:10px 14px; border-bottom:1px solid var(--line); }}
  td {{ padding:10px 14px; border-bottom:1px solid var(--line); vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  .num {{ text-align:right; font-variant-numeric: tabular-nums; }}
  .finding-name {{ max-width: 46ch; }}
  .badge {{ display:inline-block; font-size:.6875rem; font-weight:600; letter-spacing:.03em;
            padding:2px 8px; border-radius:999px; white-space:nowrap; }}
  .badge-auto {{ color:#7f1d1d; background:#fef2f2; border:1px solid #7f1d1d33; }}
  .badge-fp {{ color:#1e40af; background:#eff6ff; border:1px solid #1e40af33; }}
  details {{ background:var(--paper); border:1px solid var(--line); border-radius:12px;
             margin:10px 0; padding:0; }}
  summary {{ cursor:pointer; padding:14px 18px; }}
  summary:hover {{ background:var(--wash); }}
  .detail-body {{ padding: 4px 18px 16px; border-top:1px solid var(--line); }}
  .k {{ font-weight:600; }}
  .host-block {{ background:var(--wash); border-radius:8px; padding:12px 16px; margin-top:12px; }}
  .host-name {{ font-weight:600; margin:0 0 6px; }}
  code {{ font: .8125rem/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
          background:#f3f4f6; padding:1px 5px; border-radius:4px; }}
  ul {{ margin:4px 0 12px; padding-left:20px; }}
  li {{ margin:2px 0; }}
  .callout {{ border-left:4px solid #7f1d1d; background:#fef2f2; color:#7f1d1d;
              padding:12px 16px; border-radius:0 8px 8px 0; margin:12px 0; }}
  footer {{ margin-top:40px; font-size:.8125rem; color:var(--muted);
            border-top:1px solid var(--line); padding-top:16px; }}
  @media print {{
    body {{ background:#fff; }}
    .page {{ max-width:none; padding:0; }}
    details {{ page-break-inside: avoid; }}
    details[open] summary ~ * {{ display: block; }}
  }}
</style>
</head>
<body>
<div class="page">
  <header>
    <h1>PCI ASV Scan Readiness Report</h1>
    <p class="muted">Scan: <strong>{_e(scan_name)}</strong> (id {_e(scan_id)}) · Generated {_e(generated_on)} ·
       Advisory only — ASV review determines compliance</p>
  </header>

  <section class="card hero" aria-label="Readiness score">
    <div class="score" style="color:{fg};background:{bg};border:1px solid {fg}33;">
      <div class="n">{composite:g}</div>
      <div class="d">/ 100</div>
    </div>
    <div class="grade">
      <p><strong>{_e(grade)}</strong></p>
      {subscore_rows}
      {na_html}
    </div>
  </section>

  {f'<div class="callout"><strong>{len(auto_fails)} automatic-fail condition(s) detected.</strong> These fail the scan regardless of CVSS score and are rarely disputable — address them first.</div>' if auto_fails else ''}
  {plan_html}

  <h2>PCI-impacting findings ({len(failing)})</h2>
  <p class="muted">Severity Medium+ (the CVSS 4.0+ ASV fail line) plus automatic-fail conditions.
     {stripped_count} Info/Low finding(s) that don't affect compliance were excluded.</p>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th class="num">Instances</th><th>Flags</th></tr></thead>
    <tbody>{finding_rows if finding_rows else '<tr><td colspan="4">No PCI-impacting findings — clean scan.</td></tr>'}</tbody>
  </table>

  {f'<h2>Dispute preparation worksheet</h2><p class="muted">Every failing finding needs a disposition — an undisputed failure causes automatic attestation rejection. Tenable requires all evidence to state when, where, and how it was obtained.</p>{worksheet_html}' if worksheet_html else ''}

  <footer>
    Generated by the Tenable PCI ASV Scan Readiness MCP server. This report is advisory and does not
    determine PCI DSS compliance; only the ASV review of a submitted attestation does. Verify all
    evidence before filing disputes in the ASV Workbench.
  </footer>
</div>
</body>
</html>"""
