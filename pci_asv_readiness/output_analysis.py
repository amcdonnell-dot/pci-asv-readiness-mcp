"""Parse Nessus/Tenable plugin outputs into structured dispute evidence.

Plugin output text is where the scanner records what it actually observed —
the banner it grabbed, the version it inferred, the fixed version it compared
against, the ciphers it negotiated. Disputes live or die on this detail, so
these pure functions extract it and turn it into finding-specific verification
commands and customer questions, instead of generic category advice.

All functions are deterministic and unit-testable; no network access.
"""

from __future__ import annotations

import re

# Common "key : value" evidence lines Nessus plugins emit in output text.
_FIELD_PATTERNS = {
    "installed_version": r"(?:Installed|Reported|Remote|Detected)\s+version\s*:\s*(.+)",
    "fixed_version": r"Fixed\s+version\s*:\s*(.+)",
    "banner": r"(?:Banner|Version\s+source|Source)\s*:\s*(.+)",
    "path": r"(?:Path|Filename|File)\s*:\s*(.+)",
    "url": r"URL\s*:\s*(.+)",
}

# Raw service banners that sometimes appear on their own line.
_BANNER_LINE = re.compile(r"^\s*((?:SSH-\d[\d.]*-|Server:\s|220[ -]).{0,120})$", re.MULTILINE)

# Cipher/protocol table rows in SSL/TLS plugin outputs.
_CIPHER_LINE = re.compile(
    r"^\s{2,}((?:TLS|SSL|EXP-|DES-|RC4-|AES|ECDHE-|DHE-)[A-Z0-9_\-]{3,60})\s", re.MULTILINE
)

# Package-manager verification commands per backport-prone service.
_VERIFY_COMMANDS = {
    "openssh": "rpm -q openssh-server || dpkg -l openssh-server",
    "apache": "rpm -q httpd || dpkg -l apache2",
    "nginx": "rpm -q nginx || dpkg -l nginx",
    "openssl": "rpm -q openssl || dpkg -l openssl",
    "php": "rpm -q php || dpkg -l php* | grep -i '^ii'",
    "mysql": "rpm -q mysql-server || dpkg -l mysql-server",
    "mariadb": "rpm -q mariadb-server || dpkg -l mariadb-server",
    "postgresql": "rpm -q postgresql-server || dpkg -l postgresql*",
    "bind": "rpm -q bind || dpkg -l bind9",
    "tomcat": "rpm -q tomcat || dpkg -l tomcat*",
}


# Distro package suffixes in banners: "OpenSSH_9.6p1 Ubuntu-3ubuntu13.18",
# "8.9p1 Debian-10+deb12u3", ".el8", ".amzn2023" — the tell that the binary is
# a distro build that receives backported CVE fixes without a version bump.
_DISTRO_SUFFIX = re.compile(
    r"(Ubuntu-[\w.+]+|Debian-[\w.+]+|\.el\d+[\w.]*|\.amzn[\w.]*|FreeBSD-[\w.]+)", re.IGNORECASE
)


def parse_plugin_output(output_text: str) -> dict:
    """Extract structured evidence fields from a plugin's output text."""
    text = output_text or ""
    parsed: dict = {}
    for field, pattern in _FIELD_PATTERNS.items():
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            parsed[field] = m.group(1).strip()
    banners = [b.strip() for b in _BANNER_LINE.findall(text)]
    if banners and "banner" not in parsed:
        parsed["banner"] = banners[0]
    ciphers = _CIPHER_LINE.findall(text)
    if ciphers:
        parsed["weak_ciphers_or_protocols"] = sorted(set(ciphers))[:25]
    # Backport signals: Nessus sometimes prints "Potential Vulnerability:
    # Backported" (or similar) directly, and distro package suffixes in the
    # banner are the classic marker of backported builds.
    if re.search(r"backport", text, re.IGNORECASE):
        parsed["backport_note_in_output"] = True
    suffix = _DISTRO_SUFFIX.search(parsed.get("banner", "") or text)
    if suffix:
        parsed["distro_packaged_build"] = suffix.group(1)
    return parsed


def _service_hint(plugin_name: str) -> str | None:
    name = (plugin_name or "").lower()
    for svc in _VERIFY_COMMANDS:
        if svc in name:
            return svc
    return None


def build_evidence_plan(
    category: str,
    plugin_name: str,
    parsed: dict,
    hostname: str = "the affected host",
    port: str | int | None = None,
) -> dict:
    """Turn parsed plugin-output evidence into finding-specific dispute prep:
    what the scanner saw, targeted verification commands, and the questions the
    customer must answer — grounded in this finding's actual output rather than
    generic category advice."""
    where = f"{hostname}" + (f":{port}" if port else "")
    scanner_saw = []
    for key in ("banner", "installed_version", "fixed_version", "path", "url"):
        if key in parsed:
            scanner_saw.append(f"{key.replace('_', ' ')}: {parsed[key]}")
    if "weak_ciphers_or_protocols" in parsed:
        scanner_saw.append(
            "negotiated weak ciphers/protocols: " + ", ".join(parsed["weak_ciphers_or_protocols"][:8])
            + ("…" if len(parsed["weak_ciphers_or_protocols"]) > 8 else "")
        )

    commands: list[str] = []
    questions: list[str] = []

    if category == "banner_version":
        svc = _service_hint(plugin_name)
        if svc:
            commands.append(f"On {hostname}: {_VERIFY_COMMANDS[svc]}")
            commands.append(f"On {hostname}: rpm -q --changelog {svc}* 2>/dev/null | head -40")
        detected = parsed.get("installed_version") or parsed.get("banner")
        fixed = parsed.get("fixed_version")
        if detected and fixed:
            questions.append(
                f"The scanner inferred version '{detected}' against fixed version '{fixed}' from a "
                f"banner on {where}. Does the installed package's build/changelog show the fix was "
                f"backported despite the banner?"
            )
        if parsed.get("backport_note_in_output"):
            questions.append(
                "The scanner's own output notes this may be a backported build — strong signal for "
                "a False Positive dispute, but the reviewer still needs the host-level package proof."
            )
        if parsed.get("distro_packaged_build"):
            questions.append(
                f"The banner carries a distro package suffix ('{parsed['distro_packaged_build']}') — "
                "this is a distro-maintained build that receives backported CVE fixes without version "
                "bumps. Check the distro's security advisory (USN/DSA/RHSA/ALAS) for the CVEs this "
                "plugin cites and confirm the installed build number post-dates the fix."
            )
        questions.append(
            "Which vendor advisory (ALAS/RHSA/USN/DSA) maps this plugin's CVEs to a fixed build "
            "for your exact distro release, and does the installed build post-date it?"
        )
        questions.append(
            "Capture the command output with provenance: who ran it, on which host, on what date, "
            "via what access method (Tenable requires when/where/how for all evidence)."
        )
    elif category == "ssl_tls":
        commands.append(f"nmap --script ssl-enum-ciphers -p {port or 443} {hostname}")
        commands.append(f"openssl s_client -connect {where if port else hostname + ':443'} -tls1 </dev/null")
        if "weak_ciphers_or_protocols" in parsed:
            questions.append(
                "The scanner actually negotiated the listed weak ciphers/protocols — this is a live "
                "handshake observation, not a banner guess. Can these be disabled on the TLS "
                "terminator instead of disputed? Remediation + rescan is almost always the faster path."
            )
        questions.append(f"What device terminates TLS for {where} — origin, load balancer, or WAF?")
        questions.append(
            "If remediation is genuinely infeasible: what documented technical/business constraint "
            "applies, and what specific control on this exact path offsets the risk?"
        )
    elif category == "automatic_fail":
        questions.append(
            "This is an automatic-fail category (fails regardless of CVSS). For unsupported "
            "software: is an upgrade path genuinely unavailable before the deadline? For "
            "malware/backdoor indicators: has incident response reviewed this host?"
        )
        if parsed.get("installed_version"):
            questions.append(
                f"Scanner identified '{parsed['installed_version']}' on {where} — confirm the "
                "exact product/OS version and its vendor support status with documentation."
            )
    elif category == "default_credentials":
        questions.append(
            f"The scanner authenticated (or accessed anonymously) on {where}. Why can't the "
            "credential be changed or the service disabled? Remediation is nearly always faster "
            "than a dispute here."
        )
    else:
        if scanner_saw:
            questions.append(
                f"The scanner recorded: {'; '.join(scanner_saw[:3])}. What specifically is wrong "
                "about this observation, and what host-level evidence proves it?"
            )
        questions.append(
            "Has this been remediated since the scan ran? If yes, rescan rather than dispute."
        )

    return {
        "scanner_observed": scanner_saw or ["(no structured evidence lines found in plugin output)"],
        "verification_commands": commands,
        "dispute_questions": questions,
    }
