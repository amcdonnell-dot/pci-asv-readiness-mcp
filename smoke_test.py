#!/usr/bin/env python3
"""Live smoke test against your Tenable VM account — no MCP client needed.

Usage:
    export TENABLE_ACCESS_KEY=...
    export TENABLE_SECRET_KEY=...
    python smoke_test.py              # resolve template + list PCI scans
    python smoke_test.py <scan_id>    # full analysis of one scan

Read-only: only GET requests are made.
"""

import json
import sys

from pci_asv_readiness.filtering import filter_pci_findings
from pci_asv_readiness.output_analysis import build_evidence_plan, parse_plugin_output
from pci_asv_readiness.scoring import readiness_score
from pci_asv_readiness.tenable_client import TenableAuthError, TenableClient


def main() -> int:
    try:
        client = TenableClient()
    except TenableAuthError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print("=" * 60)
    print("1. Resolving PCI Quarterly External Scan template...")
    template = client.resolve_pci_template()
    if not template:
        print("   NOT FOUND — check the account's PCI ASV license/permissions.")
        return 1
    print(f"   OK: uuid={template['uuid']}")

    print("\n2. Listing scans built on that template...")
    scans = [s for s in client.list_scans() if s.get("template_uuid") == template["uuid"]]
    for s in scans:
        print(f"   [{s.get('id')}] {s.get('name')} — status: {s.get('status')}")
    if not scans:
        print("   No PCI scans found on this account.")
        return 0

    scan_id = None
    for arg in sys.argv[1:]:
        if arg.isdigit():
            scan_id = int(arg)
            break
    if scan_id is None:
        print("\nRe-run with a scan id for full analysis: python smoke_test.py <scan_id>")
        return 0
    print(f"\n3. Fetching scan {scan_id} and filtering PCI-impacting findings...")
    details = client.scan_details(scan_id)
    result = filter_pci_findings(details.get("vulnerabilities", []))
    print(f"   failing: {len(result['failing'])}, stripped info/low: {result['stripped_count']}")
    for f in result["failing"][:10]:
        flags = []
        if f["auto_fail"]:
            flags.append("AUTO-FAIL")
        if f["likely_fp_pattern"]:
            flags.append("likely-FP-pattern")
        print(f"   [{f['severity_label']:>8}] {f['plugin_name']}"
              + (f"  <{', '.join(flags)}>" if flags else ""))

    print("\n4. ASV Readiness Score...")
    score = readiness_score(result["failing"], details.get("info", {}))
    print(f"   {score['asv_readiness_score']} — {score['grade']}")
    for name, sub in score["subscores"].items():
        print(f"   - {name}: {sub['score']}")
    if score["not_assessed"]:
        print(f"   not assessed: {', '.join(score['not_assessed'])}")

    if result["failing"]:
        top = result["failing"][0]
        print(f"\n5. Plugin-output analysis for top finding: {top['plugin_name']}...")
        outputs = client.outputs_for_plugin(scan_id, top["plugin_id"], max_hosts=2)
        if not outputs:
            print("   No plugin output retrievable for this finding.")
        for out in outputs:
            parsed = parse_plugin_output(out.get("plugin_output", ""))
            plan = build_evidence_plan(
                top["dispute_category"], top["plugin_name"], parsed,
                hostname=out.get("hostname") or "host", port=(out.get("ports") or [None])[0],
            )
            print(f"   host: {out.get('hostname')} ports: {out.get('ports')}")
            print(f"   parsed evidence: {json.dumps(parsed, indent=2)[:600]}")
            print(f"   scanner observed: {plan['scanner_observed']}")
            for q in plan["dispute_questions"][:3]:
                print(f"   Q: {q}")

    print("\nSmoke test complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
