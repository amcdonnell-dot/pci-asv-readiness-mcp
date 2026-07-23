"""Unit tests for PCI finding filtering — pure functions, no network."""

from pci_asv_readiness.filtering import (
    dispute_category,
    filter_pci_findings,
    is_automatic_fail,
    is_likely_false_positive_pattern,
    is_pci_impacting,
)

# Realistic aggregate-vulnerabilities shapes from GET /scans/{id}
SWEET32 = {
    "plugin_id": 42873,
    "plugin_name": "SSL Medium Strength Cipher Suites Supported (SWEET32)",
    "plugin_family": "General",
    "severity": 2,
    "count": 3,
}
OPENSSH = {
    "plugin_id": 178012,
    "plugin_name": "OpenSSH < 9.3p2 Multiple Vulnerabilities",
    "plugin_family": "Misc.",
    "severity": 4,
    "count": 1,
}
INFO_FINDING = {
    "plugin_id": 19506,
    "plugin_name": "Nessus Scan Information",
    "plugin_family": "Settings",
    "severity": 0,
    "count": 5,
}
LOW_FINDING = {
    "plugin_id": 70658,
    "plugin_name": "SSH Server CBC Mode Ciphers Enabled",
    "plugin_family": "Misc.",
    "severity": 1,
    "count": 2,
}
UNSUPPORTED_LOW = {
    "plugin_id": 33850,
    "plugin_name": "Unix Operating System Unsupported Version Detection",
    "plugin_family": "General",
    "severity": 1,  # deliberately low-severity: auto-fail must still be kept
    "count": 1,
}
BACKDOOR = {
    "plugin_id": 51988,
    "plugin_name": "Bind Shell Backdoor Detection",
    "plugin_family": "Backdoors",
    "severity": 4,
    "count": 1,
}
DEFAULT_CREDS = {
    "plugin_id": 41028,
    "plugin_name": "SNMP Agent Default Community Name (public)",
    "plugin_family": "SNMP",
    "severity": 3,
    "count": 1,
}


def test_medium_plus_is_pci_impacting():
    assert is_pci_impacting(SWEET32)
    assert is_pci_impacting(OPENSSH)


def test_info_and_low_are_stripped():
    assert not is_pci_impacting(INFO_FINDING)
    assert not is_pci_impacting(LOW_FINDING)


def test_auto_fail_kept_even_at_low_severity():
    # The critical case: a naive severity filter would drop this.
    assert is_pci_impacting(UNSUPPORTED_LOW)
    assert is_automatic_fail(UNSUPPORTED_LOW["plugin_name"], UNSUPPORTED_LOW["plugin_family"])


def test_backdoor_family_is_auto_fail():
    assert is_automatic_fail(BACKDOOR["plugin_name"], BACKDOOR["plugin_family"])


def test_banner_version_pattern_detection():
    assert is_likely_false_positive_pattern(OPENSSH["plugin_name"])
    assert not is_likely_false_positive_pattern(SWEET32["plugin_name"])
    # '<' alone isn't enough without a backport-prone service
    assert not is_likely_false_positive_pattern("SomeVendor Widget < 2.0 RCE")


def test_dispute_categories():
    assert dispute_category(SWEET32) == "ssl_tls"
    assert dispute_category(OPENSSH) == "banner_version"
    assert dispute_category(BACKDOOR) == "automatic_fail"
    assert dispute_category(UNSUPPORTED_LOW) == "automatic_fail"


def test_pci_policy_plugins_get_own_category():
    # Plugin 33929 is the scan's own PCI rollup verdict — not disputable itself
    rollup = {"plugin_id": 33929, "plugin_name": "PCI DSS compliance",
              "plugin_family": "Policy Compliance", "severity": 3, "count": 1}
    remote_access = {"plugin_id": 56209, "plugin_name": "PCI DSS: Remote Access Software Detected",
                     "plugin_family": "Policy Compliance", "severity": 2, "count": 4}
    assert dispute_category(rollup) == "pci_policy"
    assert dispute_category(remote_access) == "pci_policy"


def test_filter_pci_findings_end_to_end():
    vulns = [SWEET32, OPENSSH, INFO_FINDING, LOW_FINDING, UNSUPPORTED_LOW, BACKDOOR, DEFAULT_CREDS]
    result = filter_pci_findings(vulns)
    failing_names = [f["plugin_name"] for f in result["failing"]]

    assert len(result["failing"]) == 5
    assert result["stripped_count"] == 2
    # Sorted by severity descending: criticals first
    assert result["failing"][0]["severity"] == 4
    # Auto-fail low-severity finding survived the filter
    assert UNSUPPORTED_LOW["plugin_name"] in failing_names
    # Enrichment fields present
    for f in result["failing"]:
        assert "severity_label" in f and "auto_fail" in f and "dispute_category" in f


def test_empty_input():
    result = filter_pci_findings([])
    assert result == {"failing": [], "stripped_count": 0}
