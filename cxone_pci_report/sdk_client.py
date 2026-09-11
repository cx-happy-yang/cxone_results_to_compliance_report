"""CheckmarxPythonSDK access layer.

This is the ONLY module that imports CheckmarxPythonSDK. Everything above
it works on normalized models, so the pipeline is testable offline.

Authentication is delegated to the SDK: it reads ``[CxOne]`` from
``~/.Checkmarx/config.ini``, the ``checkmarx_config_path`` env var / CLI
option, or ``cxone_*`` environment variables.
"""

import logging

import httpx

from .config import ProjectConfig, ReportConfig
from .filter import apply_sca_ignored_filter
from .models import ProjectScan
from .normalize import from_apisec, from_kics, from_sast, from_sca

log = logging.getLogger(__name__)

MAX_PAGES = 500  # safety guard against runaway pagination


class CxOneError(Exception):
    pass


class CxOneClient:
    """Thin wrapper around the SDK's CxOne functions."""

    def __init__(self):
        # Imported lazily so importing this module never fails offline.
        from CheckmarxPythonSDK.CxOne.apisecAPI import ApiSecAPI
        from CheckmarxPythonSDK.CxOne.applicationsAPI import (
            get_application_id_by_name,
        )
        from CheckmarxPythonSDK.CxOne.kicsResultsAPI import (
            get_kics_results_by_scan_id,
        )
        from CheckmarxPythonSDK.CxOne.projectsAPI import (
            get_last_scan_info,
            get_project_id_by_name,
            get_projects_for_a_specific_application,
        )
        from CheckmarxPythonSDK.CxOne.resultsSummaryAPI import (
            get_summary_for_many_scans,
        )
        from CheckmarxPythonSDK.CxOne.sastResultsAPI import (
            get_sast_results_by_scan_id,
        )
        from CheckmarxPythonSDK.CxOne.scaAPI import ScaAPI

        self._get_project_id_by_name = get_project_id_by_name
        self._get_last_scan_info = get_last_scan_info
        self._get_sast_results = get_sast_results_by_scan_id
        self._get_kics_results = get_kics_results_by_scan_id
        self._apisec = ApiSecAPI()
        self._get_apisec_risks = self._apisec.get_api_security_risks_by_scan_id
        self._get_summary = get_summary_for_many_scans
        self._sca = ScaAPI()
        self._get_application_id_by_name = get_application_id_by_name
        self._get_projects_for_application = get_projects_for_a_specific_application

    # --------------------------------------------------------- applications
    def get_application_id_by_name(self, name: str) -> str | None:
        return self._get_application_id_by_name(name)

    def get_projects_for_application(self, application_id: str) -> list:
        """Return the Project DTOs belonging to an application."""
        collection = self._get_projects_for_application(application_id)
        return collection.projects or []

    # ------------------------------------------------------------- projects
    def resolve_project_id(self, name: str) -> str:
        project_id = self._get_project_id_by_name(name)
        if not project_id:
            raise CxOneError(f"Project not found by name: {name!r}")
        return project_id

    def get_last_scan(self, project_id: str, use_main_branch: bool = False):
        """Return the SubsetScan for a project's latest scan, or None.

        With ``use_main_branch=True`` only scans of the project's
        configured main (protected) branch are considered — projects
        without a configured main branch then return None.
        """
        scan_map = self._get_last_scan_info(
            project_ids=[project_id], use_main_branch=use_main_branch
        )
        return scan_map.get(project_id)

    # ------------------------------------------------------------- fetch
    def fetch_sast(self, scan_id: str, page_size: int) -> list:
        results = []
        offset = 0
        total = None
        for page in range(MAX_PAGES):
            resp = self._get_sast_results(
                scan_id, offset=offset, limit=page_size
            )
            results.extend(resp["results"])
            total = resp.get("totalCount") or 0
            offset += page_size
            log.info("SAST page %d: %d/%d", page + 1, offset, total)
            if offset >= total:
                break
        else:
            raise CxOneError(
                f"SAST pagination exceeded {MAX_PAGES} pages for scan {scan_id}"
            )
        return results

    def fetch_kics(self, scan_id: str, page_size: int) -> list:
        results = []
        offset = 0
        total = None
        for page in range(MAX_PAGES):
            resp = self._get_kics_results(
                scan_id, offset=offset, limit=page_size
            )
            results.extend(resp.results)
            total = resp.total_count or 0
            offset += page_size
            log.info("KICS page %d: %d/%d", page + 1, offset, total)
            if offset >= total:
                break
        else:
            raise CxOneError(
                f"KICS pagination exceeded {MAX_PAGES} pages for scan {scan_id}"
            )
        return results

    def fetch_sca(self, scan_id: str) -> list:
        # NOTE: Sca.get_vulnerabilities_of_a_scan (SDK 1.9.1) builds its URL
        # without the /api/sca prefix; nginx rejects that path with a
        # misleading "Request Header Or Cookie Too Large" 400. Call the
        # correct endpoint directly through the SDK's own client.
        base = self._sca.api_client.configuration.server_base_url
        url = f"{base}/api/sca/risk-management/risk-reports/{scan_id}/vulnerabilities"
        response = self._sca.api_client.call_api("GET", url)
        return response.json()

    def fetch_apisec(self, scan_id: str, per_page: int) -> list:
        risks = []
        page = 1
        for _ in range(MAX_PAGES):
            resp = self._get_apisec_risks(
                scan_id, page=page, per_page=per_page
            )
            risks.extend(resp.entries or [])
            log.info(
                "APISec page %d: %s records of %s",
                page, len(risks), resp.total_records,
            )
            if not resp.has_next:
                break
            page = resp.next_page_number or page + 1
        else:
            raise CxOneError(
                f"APISec pagination exceeded {MAX_PAGES} pages for scan {scan_id}"
            )
        return risks

    def fetch_summaries(self, scan_ids: list[str]) -> dict:
        return self._get_summary(scan_ids)

    # ------------------------------------------------------------- pipeline
    def fetch_project_scan(
        self,
        project_cfg: ProjectConfig,
        cfg: ReportConfig,
    ) -> tuple[ProjectScan, int, list[str]]:
        """Resolve a project config entry to (ProjectScan, ignored, notes).

        ``ignored`` is the number of SCA vulnerabilities excluded by the
        CxOne SCA 'ignored' flag (0 when include_ignored is true).
        ``notes`` lists data-completeness caveats (engine not run in the
        scan, endpoint failure, ...) — shown in the report methodology.
        """
        if project_cfg.id:
            project_id = project_cfg.id
            project_name = project_cfg.display_name or project_cfg.id
        else:
            project_id = self.resolve_project_id(project_cfg.name)
            project_name = project_cfg.name

        scan = None
        scan_id = project_cfg.scan_id
        if scan_id:
            log.info(
                "Using scan id override %s for project %s", scan_id, project_name
            )
        else:
            scan = self.get_last_scan(
                project_id, use_main_branch=project_cfg.use_main_branch
            )
            if scan is None:
                branch_note = (
                    " (no scan on the configured main branch)"
                    if project_cfg.use_main_branch
                    else ""
                )
                raise CxOneError(
                    f"No scan found for project {project_name!r}{branch_note}."
                )
            scan_id = scan.id
            status = scan.status or ""
            if status.lower() not in ("completed",):
                log.warning(
                    "Latest scan %s for %s has status %r (expected Completed).",
                    scan_id, project_name, status,
                )

        page_size = cfg.api.page_size
        notes: list[str] = []

        def fetch_scanner(key: str, fetcher, scanner_label: str) -> list:
            """Fetch one scanner's results; degrade to [] with a note.

            Transient transport errors (timeouts, proxy disconnects) are
            retried once; a persistent failure yields an empty result set
            plus a data-completeness note instead of aborting the report.
            """
            if engines and key not in engines:
                notes.append(
                    f"{scanner_label} was not part of this scan "
                    f"(engines: {', '.join(sorted(engines))})."
                )
                return []
            attempt = 0
            while True:
                attempt += 1
                try:
                    return fetcher()
                except httpx.TimeoutException as exc:
                    kind = "timed out"
                    error = exc
                except httpx.TransportError as exc:
                    kind = "connection error"
                    error = exc
                except ValueError as exc:
                    # SDK check_response raises ValueError on non-2xx.
                    notes.append(
                        f"{scanner_label} data unavailable for this scan "
                        f"(endpoint error)."
                    )
                    log.warning(
                        "%s endpoint error for %s: %s",
                        scanner_label, scan_id, exc,
                    )
                    return []
                if attempt < 2:
                    log.info(
                        "Retrying %s for %s (attempt %d: %s)",
                        scanner_label, scan_id, attempt, error,
                    )
                    continue
                notes.append(
                    f"{scanner_label} data unavailable for this scan "
                    f"(request {kind})."
                )
                log.warning(
                    "%s %s for %s: %s", scanner_label, kind, scan_id, error
                )
                return []

        engines = {str(e).lower() for e in (getattr(scan, "engines", None) or [])}
        raw = {
            "sast": fetch_scanner(
                "sast", lambda: self.fetch_sast(scan_id, page_size), "SAST"
            ),
            "kics": fetch_scanner(
                "kics", lambda: self.fetch_kics(scan_id, page_size), "KICS"
            ),
            "apisec": fetch_scanner(
                "apisec",
                lambda: self.fetch_apisec(scan_id, page_size),
                "API Security",
            ),
        }
        sca_raw = fetch_scanner("sca", lambda: self.fetch_sca(scan_id), "SCA")
        sca_raw, ignored = apply_sca_ignored_filter(
            sca_raw, include_ignored=cfg.filters.sca_include_ignored
        )
        raw["sca"] = sca_raw

        findings = []
        findings.extend(
            from_sast(
                item, project_id=project_id, project_name=project_name,
                scan_id=scan_id,
            )
            for item in raw["sast"]
        )
        findings.extend(
            from_sca(
                item, project_id=project_id, project_name=project_name,
                scan_id=scan_id,
            )
            for item in raw["sca"]
        )
        findings.extend(
            from_kics(
                item, project_id=project_id, project_name=project_name,
                scan_id=scan_id,
            )
            for item in raw["kics"]
        )
        findings.extend(
            from_apisec(
                item, project_id=project_id, project_name=project_name,
                scan_id=scan_id,
            )
            for item in raw["apisec"]
        )

        return (
            ProjectScan(
                project_id=project_id,
                project_name=project_name,
                display_name=project_cfg.display_name or project_name,
                scan_id=scan_id,
                scan_created_at=getattr(scan, "created_at", None) if scan else None,
                scan_status=getattr(scan, "status", None) if scan else None,
                branch=project_cfg.branch or (getattr(scan, "branch", None) if scan else None),
                engines=list(getattr(scan, "engines", None) or []),
                findings=findings,
            ),
            ignored,
            notes,
        )
