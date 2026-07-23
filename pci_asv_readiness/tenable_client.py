"""Thin httpx wrapper for the Tenable Vulnerability Management API.

Auth via standard Tenable API keys in the ``X-ApiKeys`` header, read from
``TENABLE_ACCESS_KEY`` / ``TENABLE_SECRET_KEY`` environment variables.

Only documented, generally-available VM endpoints are used for the core flow:
  - GET /editor/scan/templates   (resolve the PCI template UUID at runtime)
  - GET /scans                   (list scans; match template_uuid)
  - GET /scans/{scan_id}         (aggregate results: info, hosts, vulnerabilities)

The dedicated PCI ASV endpoints (GET /pci-asv/scans etc.) are support-gated
even with a valid ASV license, so they are optional: ``list_asv_scans`` will
surface a clear message if access hasn't been granted.

Outbound calls: this module talks ONLY to the configured Tenable API base URL
(default https://cloud.tenable.com). No other network destinations.
"""

from __future__ import annotations

import os
import time

import httpx

DEFAULT_BASE_URL = "https://cloud.tenable.com"
PCI_TEMPLATE_TITLE = "PCI Quarterly External Scan"
_MAX_RETRIES = 4


class TenableAuthError(RuntimeError):
    pass


class TenableClient:
    def __init__(self, base_url: str | None = None, timeout: float = 60.0):
        access = os.environ.get("TENABLE_ACCESS_KEY", "")
        secret = os.environ.get("TENABLE_SECRET_KEY", "")
        if not access or not secret:
            raise TenableAuthError(
                "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY environment variables are required."
            )
        self._client = httpx.Client(
            base_url=base_url or os.environ.get("TENABLE_BASE_URL", DEFAULT_BASE_URL),
            headers={
                "X-ApiKeys": f"accessKey={access}; secretKey={secret}",
                "Accept": "application/json",
            },
            timeout=timeout,
        )
        # In-process caches — the MCP server is long-lived within a session, so
        # a worksheet followed by a report reuses data instead of re-fetching
        # (and re-triggering Tenable's rate limits).
        self._cache: dict[tuple, dict] = {}

    def _get(self, path: str, **params) -> dict:
        """GET with 429-aware retry: honors Retry-After, falls back to
        exponential backoff (2, 4, 8, 16s). Tenable rate-limits per-endpoint,
        and plugin-output fetches across many findings hit it quickly."""
        delay = 2.0
        for attempt in range(_MAX_RETRIES + 1):
            resp = self._client.get(path, params=params or None)
            if resp.status_code == 429 and attempt < _MAX_RETRIES:
                retry_after = resp.headers.get("Retry-After")
                wait = float(retry_after) if retry_after and retry_after.isdigit() else delay
                time.sleep(min(wait, 30.0))
                delay *= 2
                continue
            resp.raise_for_status()
            return resp.json()
        resp.raise_for_status()  # pragma: no cover
        return resp.json()  # pragma: no cover

    def _cached(self, key: tuple, fetch) -> dict:
        if key not in self._cache:
            self._cache[key] = fetch()
        return self._cache[key]

    # --- core endpoints -------------------------------------------------

    def list_scan_templates(self) -> list[dict]:
        return self._get("/editor/scan/templates").get("templates", [])

    def resolve_pci_template(self) -> dict | None:
        """Find the PCI Quarterly External Scan template by title at runtime.

        Template UUIDs shouldn't be treated as stable constants, so we look the
        template up live rather than hardcoding a UUID.
        """
        for t in self.list_scan_templates():
            if (t.get("title") or "").strip().lower() == PCI_TEMPLATE_TITLE.lower():
                return {"uuid": t.get("uuid"), "title": t.get("title"), "name": t.get("name")}
        return None

    def list_scans(self) -> list[dict]:
        return self._get("/scans").get("scans", []) or []

    def scan_details(self, scan_id: int) -> dict:
        """Aggregate scan results. Cached for the life of the server process so
        score → worksheet → report reuse one fetch."""
        return self._cached(("scan", scan_id), lambda: self._get(f"/scans/{scan_id}"))

    def host_details(self, scan_id: int, host_id: int) -> dict:
        """GET /scans/{scan_id}/hosts/{host_id} — per-host vulnerability list. Cached."""
        return self._cached(
            ("host", scan_id, host_id), lambda: self._get(f"/scans/{scan_id}/hosts/{host_id}")
        )

    def plugin_output(self, scan_id: int, host_id: int, plugin_id: int) -> dict:
        """GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id} — the
        actual plugin output text (banners, detected/fixed versions, cipher
        tables) the scanner recorded for this host/finding. Cached."""
        return self._cached(
            ("output", scan_id, host_id, plugin_id),
            lambda: self._get(f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}"),
        )

    def host_plugin_map(self, scan_id: int) -> dict[int, list[dict]]:
        """Build {plugin_id: [host, ...]} for a scan with ONE host_details call
        per host (cached), instead of re-walking every host for every plugin.
        This is what keeps a 15-finding worksheet at ~(hosts + relevant
        outputs) API calls instead of hosts x findings."""
        key = ("hostmap", scan_id)
        if key in self._cache:
            return self._cache[key]  # type: ignore[return-value]
        details = self.scan_details(scan_id)
        mapping: dict[int, list[dict]] = {}
        for host in details.get("hosts", []) or []:
            host_id = host.get("host_id")
            if host_id is None:
                continue
            hd = self.host_details(scan_id, host_id)
            for v in hd.get("vulnerabilities", []) or []:
                pid = v.get("plugin_id")
                if pid is not None:
                    mapping.setdefault(pid, []).append(host)
        self._cache[key] = mapping  # type: ignore[assignment]
        return mapping

    def outputs_for_plugin(self, scan_id: int, plugin_id: int, max_hosts: int = 5) -> list[dict]:
        """Collect plugin output text across up to ``max_hosts`` affected hosts,
        using the cached host-plugin map to fetch output only where the finding
        actually exists. A small delay between output fetches keeps bursts
        under Tenable's per-endpoint rate limits; 429s retry with backoff."""
        collected: list[dict] = []
        for host in self.host_plugin_map(scan_id).get(plugin_id, [])[:max_hosts]:
            host_id = host.get("host_id")
            if collected:
                time.sleep(0.25)  # politeness gap between output fetches
            po = self.plugin_output(scan_id, host_id, plugin_id)
            for out in po.get("outputs", []) or []:
                ports = list((out.get("ports") or {}).keys())
                collected.append(
                    {
                        "hostname": host.get("hostname"),
                        "host_id": host_id,
                        "ports": ports,
                        "plugin_output": out.get("plugin_output", ""),
                    }
                )
        return collected

    def plugin_details(self, plugin_id: int) -> dict:
        """GET /plugins/plugin/{plugin_id} — Tenable's full plugin metadata:
        synopsis, description, solution, CVEs, CVSS, references. This is the
        first stop for a finding the analysis layer doesn't recognize. Cached."""
        return self._cached(
            ("plugin_meta", plugin_id), lambda: self._get(f"/plugins/plugin/{plugin_id}")
        )

    # --- optional, support-gated PCI ASV endpoints ----------------------

    def list_asv_scans(self) -> dict:
        """GET /pci-asv/scans — requires access granted by Tenable support."""
        try:
            return {"available": True, "data": self._get("/pci-asv/scans")}
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403, 404):
                return {
                    "available": False,
                    "message": (
                        "The /pci-asv/scans endpoint is not accessible. Tenable gates this "
                        "endpoint behind a support request even for valid PCI ASV licenses — "
                        "contact Tenable support to enable it. Core tools in this server use "
                        "generally-available VM endpoints and are unaffected."
                    ),
                }
            raise

    def close(self) -> None:
        self._client.close()
