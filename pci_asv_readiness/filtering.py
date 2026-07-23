"""Pure functions for classifying Tenable PCI scan findings.

No network access, no side effects — everything here is deterministic and unit-testable.

Severity mapping (Tenable aggregate scan results):
    0 = Info, 1 = Low, 2 = Medium, 3 = High, 4 = Critical

Under the PCI ASV Program Guide, a finding fails compliance when its CVSS base
score is 4.0 or higher — which Tenable's PCI Quarterly External Scan template
surfaces as severity Medium (2) and above. Some conditions are automatic
failures regardless of score (malware/backdoors, unsupported software), so a
naive severity filter would silently drop the most fatal findings. The filter
here is: (severity >= Medium) OR (automatic-fail category).
"""

from __future__ import annotations

SEVERITY_LABELS = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

# Plugin-name fragments that indicate ASV automatic-fail conditions
# (fail regardless of CVSS score, per the PCI ASV Program Guide).
_AUTO_FAIL_NAME_HINTS = (
    "backdoor",
    "malware",
    "trojan",
    "unsupported",
    "seol",
    "security end of life",
    "end-of-life",
)
_AUTO_FAIL_FAMILIES = ("backdoors",)

# Services whose Linux-distro packages commonly receive backported security
# fixes without a version-string bump — the classic banner-check false positive.
_BACKPORT_PRONE_SERVICES = (
    "openssh",
    "apache",
    "nginx",
    "openssl",
    "php",
    "mysql",
    "mariadb",
    "postgresql",
    "postfix",
    "exim",
    "bind",
    "tomcat",
)


def is_automatic_fail(plugin_name: str, plugin_family: str = "") -> bool:
    """Heuristic: does this finding match an ASV automatic-fail category?"""
    name = (plugin_name or "").lower()
    family = (plugin_family or "").lower()
    if family in _AUTO_FAIL_FAMILIES:
        return True
    return any(hint in name for hint in _AUTO_FAIL_NAME_HINTS)


def is_pci_impacting(vuln: dict) -> bool:
    """True when a finding blocks (or can block) a PCI ASV attestation.

    ``vuln`` is one entry from the ``vulnerabilities`` array of
    ``GET /scans/{scan_id}`` (needs ``severity``; ``plugin_name`` and
    ``plugin_family`` improve automatic-fail detection).
    """
    severity = int(vuln.get("severity", 0))
    if severity >= 2:
        return True
    return is_automatic_fail(vuln.get("plugin_name", ""), vuln.get("plugin_family", ""))


def is_likely_false_positive_pattern(plugin_name: str) -> bool:
    """Heuristic: finding matches a commonly-disputed banner/version-check pattern.

    Version-comparison plugins are named like ``OpenSSH < 9.3p2 Multiple
    Vulnerabilities`` — the ``<`` plus a backport-prone service name is a strong
    signal the detection is banner-based and may be a backport false positive.
    This flags *dispute-worthiness to investigate*, not an actual false positive.
    """
    name = (plugin_name or "").lower()
    if "<" not in name:
        return False
    return any(svc in name for svc in _BACKPORT_PRONE_SERVICES)


def dispute_category(vuln: dict) -> str:
    """Bucket a failing finding into a dispute-preparation category."""
    name = (vuln.get("plugin_name") or "").lower()
    family = (vuln.get("plugin_family") or "").lower()

    # Tenable's PCI policy plugins (e.g. 33929 "PCI DSS compliance" — the
    # scan's own rollup verdict, and "PCI DSS: ..." policy checks) are not
    # ordinary vulnerabilities and need their own handling.
    if name.startswith("pci dss") or family == "policy compliance":
        return "pci_policy"
    if is_automatic_fail(vuln.get("plugin_name", ""), vuln.get("plugin_family", "")):
        return "automatic_fail"
    if "ssl" in name or "tls" in name or family == "general" and "cipher" in name:
        return "ssl_tls"
    if is_likely_false_positive_pattern(vuln.get("plugin_name", "")):
        return "banner_version"
    if "default" in name and ("password" in name or "credential" in name or "account" in name):
        return "default_credentials"
    if "anonymous" in name or ("smb" in name or "rpc" in name):
        return "exposure_smb_rpc_anon"
    return "other"


def filter_pci_findings(vulnerabilities: list[dict]) -> dict:
    """Split a scan's aggregate vulnerabilities into PCI-impacting vs stripped.

    Returns a dict with ``failing`` (severity >= Medium or automatic-fail,
    enriched with ``severity_label``, ``auto_fail``, ``likely_fp_pattern``,
    ``dispute_category``) and ``stripped_count`` (info/low findings that do not
    block compliance).
    """
    failing: list[dict] = []
    stripped = 0
    for v in vulnerabilities or []:
        if is_pci_impacting(v):
            enriched = dict(v)
            enriched["severity_label"] = SEVERITY_LABELS.get(int(v.get("severity", 0)), "unknown")
            enriched["auto_fail"] = is_automatic_fail(
                v.get("plugin_name", ""), v.get("plugin_family", "")
            )
            enriched["likely_fp_pattern"] = is_likely_false_positive_pattern(
                v.get("plugin_name", "")
            )
            enriched["dispute_category"] = dispute_category(v)
            failing.append(enriched)
        else:
            stripped += 1
    failing.sort(key=lambda x: (-int(x.get("severity", 0)), x.get("plugin_name", "")))
    return {"failing": failing, "stripped_count": stripped}
