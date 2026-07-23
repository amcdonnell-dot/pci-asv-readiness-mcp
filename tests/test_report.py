"""Unit tests for the HTML report renderer."""

from pci_asv_readiness.filtering import filter_pci_findings
from pci_asv_readiness.report import render_html_report
from pci_asv_readiness.scoring import readiness_score

VULNS = [
    {"plugin_id": 178012, "plugin_name": "OpenSSH < 9.3p2 Multiple Vulnerabilities",
     "plugin_family": "Misc.", "severity": 4, "count": 1},
    {"plugin_id": 42873, "plugin_name": "SSL Medium Strength Cipher Suites Supported (SWEET32)",
     "plugin_family": "General", "severity": 2, "count": 3},
    {"plugin_id": 33850, "plugin_name": "Unix Operating System Unsupported Version Detection",
     "plugin_family": "General", "severity": 1, "count": 1},
    {"plugin_id": 19506, "plugin_name": "Nessus Scan Information",
     "plugin_family": "Settings", "severity": 0, "count": 5},
]


def _render():
    result = filter_pci_findings(VULNS)
    score = readiness_score(result["failing"], {"status": "completed", "hostcount": 3})
    worksheet = [{
        "plugin_name": "OpenSSH < 9.3p2 Multiple Vulnerabilities",
        "severity": "critical",
        "category": "Banner/version-check finding (backport-prone service)",
        "plausible_workbench_reasons": ["False Positive"],
        "evidence_expected": ["Package manager output"],
        "customer_questions": ["Can you run rpm -q on the host?"],
        "note": "If not actually patched, remediate instead.",
        "output_analysis": [{
            "hostname": "bastion-prod", "ports": ["22"],
            "scanner_observed": ["banner: SSH-2.0-OpenSSH_8.7"],
            "verification_commands": ["On bastion-prod: rpm -q openssh-server"],
            "dispute_questions": ["Does the changelog show the backport?"],
        }],
    }]
    return render_html_report("Q3 PCI External", 101, score, result["failing"],
                              result["stripped_count"], worksheet, generated_on="2026-07-22")


def test_report_contains_core_sections():
    html_text = _render()
    assert "<!DOCTYPE html>" in html_text
    assert "PCI ASV Scan Readiness Report" in html_text
    assert "Q3 PCI External" in html_text
    assert "automatic-fail condition" in html_text  # callout for unsupported OS
    assert "OpenSSH &lt; 9.3p2" in html_text  # escaped finding name
    assert "AUTO-FAIL" in html_text
    assert "Likely FP pattern" in html_text
    assert "Dispute preparation worksheet" in html_text
    assert "bastion-prod" in html_text
    assert "rpm -q openssh-server" in html_text


def test_report_is_self_contained():
    html_text = _render()
    # No external assets: nothing loaded over http(s)
    assert 'src="http' not in html_text and 'href="http' not in html_text
    assert "<script" not in html_text  # zero JS by design


def test_report_escapes_html_in_data():
    score = readiness_score([], {"status": "completed"})
    html_text = render_html_report('<img src=x onerror=alert(1)>', 1, score, [], 0, [])
    assert "<img src=x" not in html_text
    assert "&lt;img" in html_text


def test_clean_scan_report():
    score = readiness_score([], {"status": "completed", "hostcount": 2})
    html_text = render_html_report("Clean Scan", 7, score, [], 12, [])
    assert "clean scan" in html_text.lower()
    assert "12 Info/Low" in html_text
    assert "Dispute preparation worksheet" not in html_text
