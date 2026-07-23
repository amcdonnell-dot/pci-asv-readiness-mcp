"""Unit tests for the ASV Readiness Score — deterministic, no network."""

from pci_asv_readiness.filtering import filter_pci_findings
from pci_asv_readiness.scoring import readiness_score

CLEAN_INFO = {"status": "completed", "hostcount": 4, "name": "Q3 PCI External"}


def _failing(vulns):
    return filter_pci_findings(vulns)["failing"]


def test_clean_scan_scores_high():
    score = readiness_score([], CLEAN_INFO)
    assert score["asv_readiness_score"] >= 90
    assert "dispute_leverage" in score["not_assessed"]  # nothing to dispute
    assert "deadline_runway" in score["not_assessed"]  # no deadline given


def test_heavy_criticals_score_low():
    vulns = [
        {"plugin_id": i, "plugin_name": f"Critical Thing {i}", "plugin_family": "Misc.",
         "severity": 4, "count": 10}
        for i in range(6)
    ]
    score = readiness_score(_failing(vulns), CLEAN_INFO)
    assert score["asv_readiness_score"] < 45
    assert score["subscores"]["remediation_workload"]["score"] < 5


def test_workload_decays_instead_of_flatlining():
    # 12 medium config findings vs 50 heavy criticals must NOT both read ~0 —
    # teams need visible progress as they clear findings.
    mediums = [{"plugin_id": i, "plugin_name": f"Config Thing {i}", "plugin_family": "Web Servers",
                "severity": 2, "count": 3} for i in range(12)]
    criticals = [{"plugin_id": i, "plugin_name": f"Critical {i}", "plugin_family": "Misc.",
                  "severity": 4, "count": 10} for i in range(50)]
    med_score = readiness_score(_failing(mediums), CLEAN_INFO)
    crit_score = readiness_score(_failing(criticals), CLEAN_INFO)
    med_w = med_score["subscores"]["remediation_workload"]["score"]
    crit_w = crit_score["subscores"]["remediation_workload"]["score"]
    assert med_w > crit_w
    assert med_w > 10  # mediums-heavy scan retains visible signal


def test_score_impact_projections():
    vulns = [
        {"plugin_id": 1, "plugin_name": "OpenSSH < 9.3p2 Multiple Vulnerabilities",
         "plugin_family": "Misc.", "severity": 4, "count": 1},
        {"plugin_id": 2, "plugin_name": "Web Server HTTP Header Info Disclosure",
         "plugin_family": "Web Servers", "severity": 2, "count": 4},
    ]
    score = readiness_score(_failing(vulns), CLEAN_INFO)
    impacts = score["score_impact"]
    assert impacts, "score_impact should be present when findings exist"
    # 'Resolve everything' must project the best score and appear ranked by gain
    best = max(impacts, key=lambda i: i["score_gain"])
    assert best is impacts[0]
    clean = next(i for i in impacts if "everything" in i["action"])
    assert clean["projected_score"] > score["asv_readiness_score"]
    # Projections are absent on a clean scan
    assert "score_impact" not in readiness_score([], CLEAN_INFO)


def test_malware_zeroes_blockers_and_leads_action_plan():
    vulns = [{"plugin_id": 51988, "plugin_name": "Bind Shell Backdoor Detection",
              "plugin_family": "Backdoors", "severity": 4, "count": 1}]
    score = readiness_score(_failing(vulns), CLEAN_INFO)
    blockers = score["subscores"]["attestation_blockers"]
    assert blockers["score"] == 0.0
    assert blockers["malware_backdoor_findings"] == 1
    # IR comes first in the plan and in next_actions
    assert "ncident response" in score["action_plan"][0]
    assert any("STOP" in a for a in blockers["next_actions"])


def test_unsupported_software_caps_blockers_at_40():
    vulns = [{"plugin_id": 33850, "plugin_name": "Unix Operating System Unsupported Version Detection",
              "plugin_family": "General", "severity": 3, "count": 1}]
    score = readiness_score(_failing(vulns), CLEAN_INFO)
    assert score["subscores"]["attestation_blockers"]["score"] == 40.0


def test_dispute_leverage_names_the_candidates():
    vulns = [
        {"plugin_id": 1, "plugin_name": "OpenSSH < 9.3p2 Multiple Vulnerabilities",
         "plugin_family": "Misc.", "severity": 4, "count": 1},
        {"plugin_id": 2, "plugin_name": "PHP < 8.1.29 Multiple Vulnerabilities",
         "plugin_family": "CGI abuses", "severity": 3, "count": 1},
        {"plugin_id": 3, "plugin_name": "SSL Medium Strength Cipher Suites Supported (SWEET32)",
         "plugin_family": "General", "severity": 2, "count": 1},
    ]
    score = readiness_score(_failing(vulns), CLEAN_INFO)
    lev = score["subscores"]["dispute_leverage"]
    # 2 of 3 failing findings match banner/backport patterns
    assert lev["score"] == round(2 / 3 * 100, 1)
    assert lev["dispute_candidates"] == 2
    # Next actions name the actual findings, not generic advice
    joined = " ".join(lev["next_actions"])
    assert "OpenSSH" in joined and "PHP" in joined
    # Provenance requirement surfaces
    assert "when/where/how" in joined


def test_deadline_runway_only_assessed_with_deadline():
    no_deadline = readiness_score([], CLEAN_INFO, days_to_deadline=None)
    assert "deadline_runway" in no_deadline["not_assessed"]

    comfy = readiness_score([], CLEAN_INFO, days_to_deadline=45)
    assert comfy["subscores"]["deadline_runway"]["score"] == 100.0

    tight = readiness_score([], CLEAN_INFO, days_to_deadline=15)
    assert tight["subscores"]["deadline_runway"]["score"] == 50.0
    assert any("15 days" in a for a in tight["subscores"]["deadline_runway"]["next_actions"])

    late = readiness_score([], CLEAN_INFO, days_to_deadline=-3)
    assert late["subscores"]["deadline_runway"]["score"] == 0.0


def test_aborted_scan_tanks_reliability_with_rerun_action():
    score = readiness_score([], {"status": "aborted", "hostcount": 0})
    rel = score["subscores"]["scan_reliability"]
    assert rel["score"] == 0.0
    assert any("re-run" in a.lower() for a in rel["next_actions"])


def test_missing_dimensions_renormalize_not_guess():
    score = readiness_score([], None)
    assert set(score["not_assessed"]) == {"dispute_leverage", "scan_reliability", "deadline_runway"}
    assert score["asv_readiness_score"] == 100.0


def test_every_subscore_has_question_and_next_actions():
    vulns = [{"plugin_id": 1, "plugin_name": "OpenSSH < 9.3p2 Multiple Vulnerabilities",
              "plugin_family": "Misc.", "severity": 4, "count": 2}]
    score = readiness_score(_failing(vulns), CLEAN_INFO, days_to_deadline=20)
    for name, sub in score["subscores"].items():
        assert sub.get("question"), f"{name} missing question"
        assert sub.get("next_actions"), f"{name} missing next_actions"


def test_action_plan_orders_work_sensibly():
    vulns = [
        {"plugin_id": 1, "plugin_name": "OpenSSH < 9.3p2 Multiple Vulnerabilities",
         "plugin_family": "Misc.", "severity": 4, "count": 1},   # FP pattern -> dispute track
        {"plugin_id": 2, "plugin_name": "Apache Tomcat RCE", "plugin_family": "Web Servers",
         "severity": 4, "count": 1},                              # real critical -> remediate.  NB: 'tomcat' svc + no '<' => not FP
        {"plugin_id": 3, "plugin_name": "TLS Version 1.0 Protocol Detection",
         "plugin_family": "Service detection", "severity": 2, "count": 1},
    ]
    score = readiness_score(_failing(vulns), CLEAN_INFO)
    plan = " || ".join(score["action_plan"])
    # Remediation of non-FP critical/high comes before medium cleanup; rescan and submit close it out
    assert "critical/high" in plan
    assert "dispute evidence" in plan
    assert "Re-run" in plan or "rescan" in plan.lower()
    assert "30+ days" in plan


def test_clean_scan_action_plan_says_submit():
    score = readiness_score([], CLEAN_INFO)
    assert any("submit" in s.lower() for s in score["action_plan"])


def test_disclaimer_always_present():
    assert "does not determine PCI" in readiness_score([], CLEAN_INFO)["disclaimer"]
