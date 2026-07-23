"""Unit tests for plugin-output parsing and evidence-plan generation."""

from pci_asv_readiness.output_analysis import build_evidence_plan, parse_plugin_output

OPENSSH_OUTPUT = """
  Version source    : SSH-2.0-OpenSSH_8.7
  Installed version : 8.7
  Fixed version     : 9.3p2
"""

SWEET32_OUTPUT = """
Medium Strength Ciphers (> 64-bit and < 112-bit key, or 3DES)

    DES-CBC3-SHA                 Kx=RSA         Au=RSA      Enc=3DES-CBC(168)     Mac=SHA1
    ECDHE-RSA-DES-CBC3-SHA       Kx=ECDH        Au=RSA      Enc=3DES-CBC(168)     Mac=SHA1

The fields above are :
  {Tenable ciphername}
"""

UNSUPPORTED_OUTPUT = """
  Installed version : CentOS 6
  End of support date : 2020-11-30
"""

EMPTY_OUTPUT = "The remote host responded."


def test_parse_openssh_banner_output():
    parsed = parse_plugin_output(OPENSSH_OUTPUT)
    assert parsed["installed_version"] == "8.7"
    assert parsed["fixed_version"] == "9.3p2"
    assert "SSH-2.0-OpenSSH_8.7" in parsed["banner"]


def test_parse_sweet32_ciphers():
    parsed = parse_plugin_output(SWEET32_OUTPUT)
    assert "DES-CBC3-SHA" in parsed["weak_ciphers_or_protocols"]
    assert "ECDHE-RSA-DES-CBC3-SHA" in parsed["weak_ciphers_or_protocols"]


def test_parse_empty_output_returns_empty():
    assert parse_plugin_output(EMPTY_OUTPUT) == {}
    assert parse_plugin_output("") == {}


def test_banner_version_plan_uses_actual_versions():
    parsed = parse_plugin_output(OPENSSH_OUTPUT)
    plan = build_evidence_plan(
        "banner_version", "OpenSSH < 9.3p2 Multiple Vulnerabilities", parsed,
        hostname="bastion-prod", port=22,
    )
    # Verification commands are service-specific, not generic
    assert any("openssh-server" in c for c in plan["verification_commands"])
    assert any("bastion-prod" in c for c in plan["verification_commands"])
    # Questions reference what the scanner actually saw
    joined = " ".join(plan["dispute_questions"])
    assert "9.3p2" in joined and "bastion-prod:22" in joined
    # Provenance requirement always present for banner disputes
    assert any("when/where/how" in q for q in plan["dispute_questions"])


def test_ssl_plan_references_negotiated_ciphers():
    parsed = parse_plugin_output(SWEET32_OUTPUT)
    plan = build_evidence_plan(
        "ssl_tls", "SSL Medium Strength Cipher Suites Supported (SWEET32)", parsed,
        hostname="shop.acme.com", port=443,
    )
    assert any("ssl-enum-ciphers" in c for c in plan["verification_commands"])
    joined = " ".join(plan["dispute_questions"])
    # Live-handshake observation should steer toward remediation
    assert "live" in joined.lower() or "remediation" in joined.lower()
    assert any("DES-CBC3-SHA" in s for s in plan["scanner_observed"])


def test_auto_fail_plan_mentions_support_status():
    parsed = parse_plugin_output(UNSUPPORTED_OUTPUT)
    plan = build_evidence_plan(
        "automatic_fail", "Unix Operating System Unsupported Version Detection", parsed,
        hostname="legacy.acme.com",
    )
    joined = " ".join(plan["dispute_questions"])
    assert "regardless of CVSS" in joined
    assert "CentOS 6" in joined


def test_plan_with_no_parsed_evidence_still_produces_questions():
    plan = build_evidence_plan("other", "Some Unusual Finding", {}, hostname="host-x")
    assert plan["scanner_observed"] == ["(no structured evidence lines found in plugin output)"]
    assert plan["dispute_questions"]


UBUNTU_BACKPORT_OUTPUT = """
  Version source    : SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18
  Installed version : 9.6p1
  Fixed version     : 10.4

  Note: Potential Vulnerability: Backported security fix may be present.
"""


def test_backport_signals_detected():
    parsed = parse_plugin_output(UBUNTU_BACKPORT_OUTPUT)
    assert parsed["backport_note_in_output"] is True
    assert parsed["distro_packaged_build"] == "Ubuntu-3ubuntu13.18"


def test_backport_signals_strengthen_dispute_plan():
    parsed = parse_plugin_output(UBUNTU_BACKPORT_OUTPUT)
    plan = build_evidence_plan(
        "banner_version", "OpenSSH < 10.4 Multiple Vulnerabilities", parsed,
        hostname="target2", port=22,
    )
    joined = " ".join(plan["dispute_questions"])
    assert "scanner's own output" in joined  # Nessus backport note surfaced
    assert "Ubuntu-3ubuntu13.18" in joined  # distro suffix surfaced
    assert "USN" in joined or "advisory" in joined.lower()


def test_no_false_backport_signal_on_plain_banner():
    parsed = parse_plugin_output(OPENSSH_OUTPUT)
    assert "backport_note_in_output" not in parsed
    assert "distro_packaged_build" not in parsed
