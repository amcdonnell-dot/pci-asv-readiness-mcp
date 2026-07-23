"""Dispute-preparation content per finding category.

Tenable's ASV Workbench accepts exactly three dispute reasons: False Positive,
Compensating Controls, and Exception. Every entry here maps a finding category
to the plausible Workbench reason(s), the evidence a reviewer expects, and the
questions a customer must answer before drafting a dispute. Evidence must be
accompanied by a description of when, where, and how it was obtained.
"""

DISPUTE_GUIDES = {
    "banner_version": {
        "label": "Banner/version-check finding (backport-prone service)",
        "plausible_workbench_reasons": ["False Positive"],
        "evidence_expected": [
            "Package manager output from the affected host (rpm -q / dpkg -l) showing the installed build",
            "Vendor security advisory (ALAS/RHSA/USN/DSA) mapping the CVE to that fixed build",
            "For each item: when, where, and how it was obtained (who ran it, on which host, on what date)",
        ],
        "customer_questions": [
            "Can you run the package-manager query on the affected host right now and capture the output?",
            "Which vendor advisory covers this CVE for your exact distro/release, and does the installed build post-date it?",
            "Did the relevant update actually include this package, or was it excluded/held?",
        ],
        "note": "If the installed build does NOT include the fix, this is remediation + rescan, not a dispute.",
    },
    "ssl_tls": {
        "label": "SSL/TLS configuration finding",
        "plausible_workbench_reasons": ["Compensating Controls (narrow)", "rarely False Positive"],
        "evidence_expected": [
            "Usually none suffices — these detections negotiate the actual handshake and are rarely wrong",
            "For a reachability argument: network diagram + ACL/firewall rules for the exact scanned path",
        ],
        "customer_questions": [
            "Is remediation (disabling the weak protocol/cipher) genuinely infeasible? If not, fix and rescan instead",
            "What device terminates TLS on the exact hostname:port the scanner hit?",
            "Is there a documented technical or business constraint preventing remediation (required for Compensating Controls)?",
        ],
        "note": "Generic 'we have a firewall/WAF' claims are the most commonly rejected dispute language.",
    },
    "default_credentials": {
        "label": "Default credentials / anonymous access",
        "plausible_workbench_reasons": ["Compensating Controls (narrow)"],
        "evidence_expected": [
            "Remediation is almost always faster than dispute — change the credential, disable the service",
            "If disputing: network diagram + firewall ruleset proving isolation from the CDE",
        ],
        "customer_questions": [
            "Why can't the credential simply be changed or the service disabled?",
            "Is the service reachable from any CDE-adjacent network path?",
        ],
        "note": "Some default-access findings are automatic failures under the ASV Program Guide.",
    },
    "exposure_smb_rpc_anon": {
        "label": "SMB/RPC/anonymous service exposure",
        "plausible_workbench_reasons": ["Exception", "Compensating Controls"],
        "evidence_expected": [
            "Reachability evidence: what path did the scanner use, and is that path internet-facing by design?",
            "If the asset shouldn't have been scanned at all: that's an out-of-scope marking, not a dispute",
        ],
        "customer_questions": [
            "Should this asset be in scope at all? (Out-of-scope marking is a separate Workbench action)",
            "If in scope: what specific control limits access on this path, and can you evidence it?",
        ],
        "note": "Distinguish disputing a finding (vulnerability isn't real/exploitable) from marking an asset out of scope (not part of the CDE).",
    },
    "automatic_fail": {
        "label": "Automatic-fail condition (malware/backdoor/unsupported software)",
        "plausible_workbench_reasons": [
            "Malware/backdoor: none — investigate the host immediately",
            "Unsupported software: Compensating Controls (carefully evidenced) or upgrade + rescan",
        ],
        "evidence_expected": [
            "Unsupported software: documented constraint, plus specific controls meeting the intent of the original requirement",
        ],
        "customer_questions": [
            "For unsupported software: is an upgrade path genuinely unavailable before the deadline?",
            "For malware/backdoor indicators: has incident response reviewed this host?",
        ],
        "note": "These fail regardless of CVSS score. A false-positive claim needs exceptionally strong evidence.",
    },
    "pci_policy": {
        "label": "Tenable PCI policy plugin (rollup verdict or PCI-specific check)",
        "plausible_workbench_reasons": [
            "'PCI DSS compliance' rollup (plugin 33929): not independently disputable — it clears "
            "automatically when the underlying findings clear",
            "PCI-specific checks (e.g. remote access software detected): Compensating Controls or "
            "Exception with documented business justification",
        ],
        "evidence_expected": [
            "For the rollup: nothing — work the underlying findings; this plugin is the scan's own verdict",
            "For remote-access/policy checks: documented business need, access controls (MFA, source "
            "restriction), and monitoring for the flagged software",
        ],
        "customer_questions": [
            "For a rollup failure: which underlying findings is it aggregating, and what's their disposition?",
            "For a policy check (e.g. remote access software): is there a documented business justification, "
            "and what controls (MFA, IP allowlisting, logging) restrict its use?",
        ],
        "note": "Don't file a dispute against the rollup plugin itself — reviewers expect the underlying "
        "findings to carry the dispositions.",
    },
    "other": {
        "label": "Other failing finding",
        "plausible_workbench_reasons": ["False Positive", "Compensating Controls", "Exception"],
        "evidence_expected": [
            "Depends on the claim: host-level verification for false positives, named specific controls "
            "on the scanned path for compensating controls, risk evidence for exceptions",
        ],
        "customer_questions": [
            "What exactly do you believe is wrong about this finding, and what can you show to prove it?",
            "Has the underlying issue been remediated since the scan? If so, rescan instead of disputing.",
        ],
        "note": "Undisputed failures cause automatic attestation rejection — every failing finding needs a disposition.",
    },
}
