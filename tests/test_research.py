"""Unit tests for the research-brief builder — pure functions, no network."""

from pci_asv_readiness.research import build_research_brief, normalize_plugin_attributes

PLUGIN_META = {
    "id": 17705,
    "name": "OPIE w/ OpenSSH Account Enumeration",
    "family_name": "Misc.",
    "attributes": [
        {"attribute_name": "synopsis", "attribute_value": "Remote host allows account enumeration."},
        {"attribute_name": "description", "attribute_value": "Timing differences in OPIE challenges reveal valid accounts."},
        {"attribute_name": "solution", "attribute_value": "Disable OPIE support or restrict SSH access."},
        {"attribute_name": "cve", "attribute_value": "CVE-2007-2243"},
        {"attribute_name": "see_also", "attribute_value": "https://example.org/advisory"},
        {"attribute_name": "cvss3_base_score", "attribute_value": "5.3"},
    ],
}

CVE_BACKPORT_META = {
    "id": 326244,
    "name": "OpenSSH < 10.4 Multiple Vulnerabilities",
    "family_name": "Misc.",
    "attributes": [
        {"attribute_name": "solution", "attribute_value": "Upgrade to OpenSSH 10.4 or later."},
        {"attribute_name": "cve", "attribute_value": "CVE-2025-1234"},
        {"attribute_name": "cve", "attribute_value": "CVE-2025-5678"},
    ],
}


def test_normalize_attributes():
    attrs = normalize_plugin_attributes(PLUGIN_META)
    assert attrs["plugin_id"] == 17705
    assert attrs["synopsis"].startswith("Remote host")
    assert attrs["cve"] == ["CVE-2007-2243"]
    assert attrs["see_also"] == ["https://example.org/advisory"]


def test_config_solution_yields_config_angle():
    brief = build_research_brief(PLUGIN_META, {"plugin_id": 17705}, [])
    assert "configuration change" in brief["dispute_angle_first_guess"]
    assert brief["known"]["solution"].startswith("Disable")
    # Plugin lookup query always present
    assert any("Tenable plugin 17705" in q for q in brief["suggested_web_queries"])
    # CVE queries present
    assert any("CVE-2007-2243" in q for q in brief["suggested_web_queries"])


def test_distro_build_yields_backport_angle():
    parsed = [{"distro_packaged_build": "Ubuntu-3ubuntu13.18", "hostname": "target2"}]
    brief = build_research_brief(CVE_BACKPORT_META, {"plugin_id": 326244}, parsed)
    assert "Backport check first" in brief["dispute_angle_first_guess"]
    # Distro-targeted advisory query generated
    assert any("Ubuntu" in q and "CVE-2025-1234" in q for q in brief["suggested_web_queries"])


def test_brief_always_carries_agent_instructions_and_questions():
    brief = build_research_brief({}, {"plugin_id": 999, "plugin_name": "Mystery Finding"}, [])
    assert "pci-finding-researcher" in brief["agent_instructions"]
    assert len(brief["research_questions"]) >= 3
    # ASV eligibility question always asked
    assert any("Program Guide" in q for q in brief["research_questions"])
    # Without CVEs, falls back to a dispute-focused query
    assert any("PCI ASV dispute" in q for q in brief["suggested_web_queries"])
