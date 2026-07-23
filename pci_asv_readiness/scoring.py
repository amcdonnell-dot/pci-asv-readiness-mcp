"""ASV Readiness Score — customer-focused, deterministic, advisory.

Every dimension is framed as the question a security team actually asks on the
way to a successful PCI ASV attestation, and every subscore carries concrete
``next_actions`` derived from the scan data — not just a number. The composite
comes with an ordered ``action_plan``: the sequence a team should work in to
get from this scan to a submittable attestation.

Dimensions:
  remediation_workload  — "How much do we have to fix?"
  dispute_leverage      — "How much could clear via evidence-backed disputes instead of patching?"
  attestation_blockers  — "Is anything present that fails us regardless of CVSS?"
  scan_reliability      — "Can we trust this scan as our attestation basis?"
  deadline_runway       — "Do we have time for the ASV review/dispute cycle?"

Dimensions that can't be assessed from available data are listed in
``not_assessed`` and excluded from the composite (weights renormalized) rather
than guessed at. The score is advisory: only the ASV review of a submitted
attestation determines PCI compliance.
"""

from __future__ import annotations

WEIGHTS = {
    "remediation_workload": 0.40,
    "dispute_leverage": 0.15,
    "attestation_blockers": 0.20,
    "scan_reliability": 0.15,
    "deadline_runway": 0.10,
}

# Severity weights for the workload penalty (per unique failing finding).
_SEV_PENALTY = {2: 8, 3: 15, 4: 25}
_SEV_NAMES = {2: "medium", 3: "high", 4: "critical"}


def _workload_penalty(failing: list[dict]) -> float:
    penalty = 0.0
    for v in failing:
        sev = int(v.get("severity", 2))
        instances = max(1, int(v.get("count", 1)))
        penalty += _SEV_PENALTY.get(sev, 8) * (instances ** 0.5)
    return penalty


def _workload_score(failing: list[dict]) -> float:
    """Exponential decay (half-life at 80 penalty points) instead of a hard
    floor: a scan with 15 medium config findings and one with 50 criticals
    should not both read 0.0 — teams need to see progress reflected as they
    clear findings, or the number stops motivating anything."""
    return round(100.0 * (0.5 ** (_workload_penalty(failing) / 80.0)), 1)


def remediation_workload_subscore(failing: list[dict]) -> dict:
    """How much must be fixed (or defensibly disputed) before attestation.

    100 = clean scan. Decays per failing finding, weighted by severity and
    sub-linearly by instance count (sqrt) so one noisy plugin doesn't dominate.
    """
    by_sev: dict[str, int] = {}
    for v in failing:
        label = _SEV_NAMES.get(int(v.get("severity", 2)), "medium")
        by_sev[label] = by_sev.get(label, 0) + 1
    score = _workload_score(failing)

    next_actions = []
    if by_sev:
        breakdown = ", ".join(f"{n} {s}" for s, n in sorted(by_sev.items(), key=lambda x: x[0]))
        next_actions.append(
            f"Resolve {len(failing)} failing finding(s) ({breakdown}): patch/reconfigure, or "
            "prepare an evidence-backed dispute for each — every one needs a disposition before "
            "submission (undisputed failures cause automatic rejection)."
        )
        next_actions.append(
            "Start with critical/high findings on CDE-facing assets — they carry the most "
            "reviewer scrutiny and the largest score penalty."
        )
    else:
        next_actions.append("Nothing to remediate — this scan is clean at the PCI fail line.")

    return {
        "score": round(score, 1),
        "question": "How much remediation work stands between this scan and a passing attestation?",
        "failing_findings": len(failing),
        "by_severity": by_sev,
        "next_actions": next_actions,
    }


def dispute_leverage_subscore(failing: list[dict]) -> dict | None:
    """How much of the failure burden may clear through disputes, not patching.

    Measures the share of failing findings matching banner/version-check
    patterns on backport-prone services — the classic evidence-backed False
    Positive dispute. Names the findings so the team knows exactly where to
    gather evidence. None (not assessed) when nothing is failing.
    """
    if not failing:
        return None
    fp_findings = [v for v in failing if v.get("likely_fp_pattern")]
    share = len(fp_findings) / len(failing)

    next_actions = []
    if fp_findings:
        names = "; ".join((v.get("plugin_name") or "?") for v in fp_findings[:5])
        next_actions.append(
            f"Gather host-level evidence (package-manager output + vendor advisory) for: {names}"
            + ("…" if len(fp_findings) > 5 else "")
            + " — these match the banner/backport pattern that commonly clears as a False Positive "
            "dispute with proper evidence."
        )
        next_actions.append(
            "For each: capture when/where/how the evidence was obtained — Tenable requires this "
            "provenance on every dispute attachment."
        )
    else:
        next_actions.append(
            "No findings match common false-positive patterns — plan for remediation rather than "
            "disputes, which is usually the faster path anyway."
        )

    return {
        "score": round(share * 100, 1),
        "question": "How much of the failure burden could clear via evidence-backed disputes instead of patching?",
        "dispute_candidates": len(fp_findings),
        "next_actions": next_actions,
        "note": "A high score means dispute *opportunity*, not confirmed false positives — "
        "evidence must still be gathered and verified per finding.",
    }


def attestation_blockers_subscore(failing: list[dict]) -> dict:
    """Conditions that fail the attestation regardless of CVSS score.

    Malware/backdoor indicators zero this subscore (and should trigger incident
    response, not compliance workflow). Unsupported software caps it at 40 —
    disputable only via carefully evidenced compensating controls, or resolved
    by upgrading.
    """
    malware = [
        v for v in failing
        if v.get("auto_fail") and any(
            h in (v.get("plugin_name") or "").lower() for h in ("backdoor", "malware", "trojan")
        )
    ]
    unsupported = [v for v in failing if v.get("auto_fail") and v not in malware]

    next_actions = []
    if malware:
        score = 0.0
        names = "; ".join((v.get("plugin_name") or "?") for v in malware[:3])
        next_actions.append(
            f"STOP — possible compromise indicators ({names}). Route to incident response before "
            "any attestation work; these cannot be disputed away."
        )
    elif unsupported:
        score = 40.0
        names = "; ".join((v.get("plugin_name") or "?") for v in unsupported[:3])
        next_actions.append(
            f"Unsupported software detected ({names}): build an upgrade plan, or prepare a "
            "carefully evidenced Compensating Controls dispute — generic claims get rejected."
        )
    else:
        score = 100.0
        next_actions.append("No automatic-fail conditions detected — nothing here blocks attestation outright.")

    return {
        "score": score,
        "question": "Is anything present that fails the attestation regardless of CVSS score?",
        "malware_backdoor_findings": len(malware),
        "unsupported_software_findings": len(unsupported),
        "next_actions": next_actions,
    }


def scan_reliability_subscore(scan_info: dict) -> dict | None:
    """Whether this scan run can serve as the attestation basis at all."""
    if not scan_info:
        return None
    status = (scan_info.get("status") or "").lower()
    status_score = {"completed": 100.0, "imported": 100.0, "partial": 50.0}.get(status, 0.0)
    host_count = scan_info.get("hostcount")

    next_actions = []
    if status_score == 100.0:
        next_actions.append("Scan completed — usable as the attestation basis.")
    elif status_score == 50.0:
        next_actions.append(
            "Scan is partial — confirm all in-scope CDE assets were actually covered, or re-run "
            "before building an attestation on it."
        )
    else:
        next_actions.append(
            f"Scan status is '{status or 'unknown'}' — re-run the scan; an aborted/incomplete scan "
            "can't support an attestation."
        )
    if isinstance(host_count, int) and host_count == 0:
        status_score = 0.0
        next_actions.append("Zero hosts scanned — check targets, network reachability, and scanner placement.")

    return {
        "score": status_score,
        "question": "Can this scan be trusted as the basis for an attestation submission?",
        "status": status,
        "host_count": host_count,
        "next_actions": next_actions,
    }


def deadline_runway_subscore(days_to_deadline: int | None) -> dict | None:
    """Whether enough time remains for the ASV review/dispute round-trip.
    Tenable recommends submitting 30+ days before the compliance deadline.
    Only assessed when the caller supplies a deadline."""
    if days_to_deadline is None:
        return None
    if days_to_deadline < 0:
        score = 0.0
        next_actions = [
            "The deadline has already passed — align with your acquirer/QSA on the remediation "
            "story before submitting; the conversation is now about the plan, not just the scan."
        ]
    elif days_to_deadline >= 30:
        score = 100.0
        next_actions = [
            f"{days_to_deadline} days remain — comfortably beyond the recommended 30-day buffer. "
            "Submit as soon as findings have dispositions; don't spend the buffer."
        ]
    else:
        score = round(days_to_deadline / 30 * 100, 1)
        next_actions = [
            f"Only {days_to_deadline} days remain (inside the 30-day buffer Tenable recommends). "
            "Prioritize remediation over disputes where possible — a rejected dispute may not "
            "leave time for a second review cycle."
        ]
    return {
        "score": score,
        "question": "Is there enough time left for the ASV review and dispute cycle before the deadline?",
        "days_to_deadline": days_to_deadline,
        "next_actions": next_actions,
    }


def _grade(composite: float) -> str:
    if composite >= 90:
        return "READY-SHAPE: little standing between this scan and a submittable attestation"
    if composite >= 70:
        return "MINOR WORK: a small number of findings/dispositions to resolve first"
    if composite >= 40:
        return "AT RISK: meaningful remediation or dispute work required before attestation"
    return "NOT READY: submitting an attestation from this scan would very likely fail"


def _action_plan(subscores: dict, failing: list[dict]) -> list[str]:
    """Ordered, deterministic path from this scan to a submittable attestation."""
    plan: list[str] = []
    blockers = subscores.get("attestation_blockers", {})
    if blockers.get("malware_backdoor_findings"):
        plan.append("1. Incident response first: investigate possible-compromise indicators before any compliance work.")
    if blockers.get("unsupported_software_findings"):
        plan.append(f"{len(plan) + 1}. Resolve unsupported software: upgrade, or build an evidenced Compensating Controls dispute.")
    sev_crit_high = [v for v in failing if int(v.get("severity", 0)) >= 3 and not v.get("likely_fp_pattern")]
    if sev_crit_high:
        plan.append(f"{len(plan) + 1}. Remediate the {len(sev_crit_high)} critical/high finding(s) without a false-positive pattern — patching is faster and safer than arguing these.")
    fp = [v for v in failing if v.get("likely_fp_pattern")]
    if fp:
        plan.append(f"{len(plan) + 1}. In parallel, gather dispute evidence for the {len(fp)} likely-false-positive finding(s): package-manager output + vendor advisory, with when/where/how provenance.")
    sev_med = [v for v in failing if int(v.get("severity", 0)) == 2 and not v.get("likely_fp_pattern")]
    if sev_med:
        plan.append(f"{len(plan) + 1}. Clear the {len(sev_med)} medium finding(s) — often quick config changes (ciphers, protocols).")
    if failing:
        plan.append(f"{len(plan) + 1}. Re-run the PCI scan until it's as clean as possible — a clean rescan beats any dispute.")
        plan.append(f"{len(plan) + 1}. Import to the ASV Workbench, attach dispute evidence for anything remaining, verify every failure has a disposition, and submit 30+ days before your deadline.")
    else:
        plan.append("1. Import this clean scan to the ASV Workbench, mark any out-of-scope assets with real justifications, and submit.")
    return plan


def _score_impact(failing, scan_info, days_to_deadline, current: float) -> list[dict]:
    """Project the composite score after each major class of work — so a team
    sees which effort actually moves the needle before choosing where to start."""
    scenarios = [
        ("Remediate all critical/high findings",
         [v for v in failing if int(v.get("severity", 0)) < 3]),
        ("Clear the likely-false-positive findings via accepted disputes",
         [v for v in failing if not v.get("likely_fp_pattern")]),
        ("Clear all medium findings",
         [v for v in failing if int(v.get("severity", 0)) != 2]),
        ("Resolve everything (clean rescan)", []),
    ]
    impacts = []
    for label, remaining in scenarios:
        if len(remaining) == len(failing):
            continue  # scenario removes nothing — skip
        projected = readiness_score(remaining, scan_info, days_to_deadline, _project=False)
        impacts.append(
            {
                "action": label,
                "findings_resolved": len(failing) - len(remaining),
                "projected_score": projected["asv_readiness_score"],
                "score_gain": round(projected["asv_readiness_score"] - current, 1),
            }
        )
    impacts.sort(key=lambda x: -x["score_gain"])
    return impacts


def readiness_score(
    failing: list[dict],
    scan_info: dict | None = None,
    days_to_deadline: int | None = None,
    _project: bool = True,
) -> dict:
    """Compose the ASV Readiness Score from available customer-focused subscores."""
    subscores: dict[str, dict] = {}
    not_assessed: list[str] = []

    candidates = {
        "remediation_workload": remediation_workload_subscore(failing),
        "dispute_leverage": dispute_leverage_subscore(failing),
        "attestation_blockers": attestation_blockers_subscore(failing),
        "scan_reliability": scan_reliability_subscore(scan_info or {}),
        "deadline_runway": deadline_runway_subscore(days_to_deadline),
    }
    for name, result in candidates.items():
        if result is None:
            not_assessed.append(name)
        else:
            subscores[name] = result

    total_weight = sum(WEIGHTS[n] for n in subscores)
    composite = (
        sum(subscores[n]["score"] * WEIGHTS[n] for n in subscores) / total_weight
        if total_weight
        else 0.0
    )
    composite = round(composite, 1)

    result = {
        "asv_readiness_score": composite,
        "grade": _grade(composite),
        "subscores": subscores,
        "action_plan": _action_plan(subscores, failing),
        "not_assessed": not_assessed,
        "disclaimer": (
            "Advisory metric computed from Tenable VM API data. It does not determine PCI "
            "compliance — only the ASV review of a submitted attestation does."
        ),
    }
    if _project and failing:
        result["score_impact"] = _score_impact(failing, scan_info, days_to_deadline, composite)
    return result
