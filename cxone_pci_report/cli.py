"""Command-line entrypoint: config -> fetch/demo -> filter -> map -> PDF."""

import argparse
import logging
import sys

import httpx

from . import __version__, TOOL_NAME
from .aggregate import build_report_data
from .config import ConfigError, load_config
from .filter import apply_filters
from .models import ProjectScan
from .pci_map import MappingError, load_rules, map_finding
from .report.builder import build_pdf

log = logging.getLogger(__name__)


class ToolError(Exception):
    """Fatal pipeline error; main() prints it and exits 1."""


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Consolidate Checkmarx One scan results (SAST, SCA, IaC/KICS, "
            "API Security) into a PCI DSS v4.0.1 compliance PDF report."
        ),
    )
    parser.add_argument(
        "--config",
        help="Path to the report config JSON file (required unless --demo).",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate the report from bundled synthetic scan data (no API access).",
    )
    parser.add_argument(
        "--application",
        help=(
            "CxOne application name: include every project of this "
            "application in the report scope (requires --config for report "
            "metadata). Mutually exclusive with --demo."
        ),
    )
    parser.add_argument(
        "--main-branch-only",
        action="store_true",
        help=(
            "For every project in scope, use only the latest scan of the "
            "configured main (protected) branch. Projects without a "
            "configured main branch are skipped and listed in the report."
        ),
    )
    parser.add_argument(
        "--output",
        help="Output PDF path (overrides config output.pdf_path).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose logging (API pagination progress, warnings).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {__version__}",
    )
    return parser


def _fetch_projects(cfg) -> tuple[list[ProjectScan], int, list[dict], list[str]]:
    """Live path: fetch each configured project via the SDK.

    Projects without a scan are skipped (reported in the PDF methodology)
    so one empty project cannot abort an application-wide run. Per-scanner
    caveats (engine not run, endpoint failure) are collected as data notes.
    """
    from .sdk_client import CxOneClient, CxOneError

    client = CxOneClient()
    projects: list[ProjectScan] = []
    skipped: list[dict] = []
    data_notes: list[str] = []
    ignored_total = 0
    for project_cfg in cfg.projects:
        label = project_cfg.name or project_cfg.display_name or project_cfg.id
        log.info("Fetching project %s", label)
        project = None
        for attempt in (1, 2):
            try:
                project, ignored, notes = client.fetch_project_scan(
                    project_cfg, cfg
                )
                break
            except CxOneError as exc:
                message = str(exc)
                if message.startswith("No scan found"):
                    log.warning("Skipping project %s: %s", label, message)
                    skipped.append({"project": label, "reason": message})
                    break
                raise ToolError(f"ERROR: {exc}") from exc
            except httpx.TransportError as exc:
                if attempt == 1:
                    log.info(
                        "Retrying project %s (attempt %d: %s)",
                        label, attempt, exc,
                    )
                    continue
                message = (
                    f"request failed after retries: {exc.__class__.__name__}"
                )
                log.warning("Skipping project %s: %s", label, message)
                skipped.append({"project": label, "reason": message})
                break
            except Exception as exc:  # other httpx / SDK errors
                raise ToolError(
                    f"ERROR: failed to fetch project {label!r}: {exc}"
                ) from exc
        if project is None:
            continue
        projects.append(project)
        ignored_total += ignored
        for note in notes:
            data_notes.append(f"{label}: {note}")
        log.info(
            "Project %s: %d findings fetched",
            project.display_name, len(project.findings),
        )
    return projects, ignored_total, skipped, data_notes


def _demo_projects(cfg):
    """Demo path: normalize the bundled synthetic payloads."""
    from .demo.fixtures import build_demo_projects
    from .filter import apply_sca_ignored_filter
    from .normalize import from_apisec, from_kics, from_sast, from_sca

    demo_projects = build_demo_projects()
    projects: list[ProjectScan] = []
    ignored_total = 0
    for demo in demo_projects:
        sca_raw, ignored = apply_sca_ignored_filter(
            demo.sca, include_ignored=cfg.filters.sca_include_ignored
        )
        ignored_total += ignored
        findings = []
        ctx = dict(
            project_id=demo.project_id,
            project_name=demo.project_name,
            scan_id=demo.scan_id,
        )
        findings.extend(from_sast(item, **ctx) for item in demo.sast)
        findings.extend(from_sca(item, **ctx) for item in sca_raw)
        findings.extend(from_kics(item, **ctx) for item in demo.kics)
        findings.extend(from_apisec(item, **ctx) for item in demo.apisec)
        projects.append(
            ProjectScan(
                project_id=demo.project_id,
                project_name=demo.project_name,
                display_name=demo.project_name,
                scan_id=demo.scan_id,
                scan_created_at=demo.scan_created_at,
                scan_status=demo.scan_status,
                branch=demo.branch,
                engines=demo.engines,
                findings=findings,
            )
        )
    return projects, ignored_total


def run(cfg, demo: bool = False) -> str:
    """Execute the full pipeline and return the output PDF path."""
    try:
        rules = load_rules(cfg.mapping.rules_override_path)
    except MappingError as exc:
        raise ToolError(f"ERROR: {exc}") from exc

    if demo:
        log.info("Demo mode: using synthetic scan data.")
        projects, ignored_total = _demo_projects(cfg)
        skipped = []
        data_notes = []
    else:
        projects, ignored_total, skipped, data_notes = _fetch_projects(cfg)

    if not projects:
        raise ToolError(
            "ERROR: no projects with scan results in scope; "
            "nothing to report."
        )

    # Client-side filtering (single pipeline for demo and live).
    all_findings = [f for p in projects for f in p.findings]
    filter_result = apply_filters(all_findings, cfg.filters)
    if ignored_total:
        filter_result.filtered_out["by_sca_ignored"] = ignored_total

    # PCI mapping.
    mapped = [
        map_finding(
            finding,
            rules,
            default_requirement=cfg.mapping.default_requirement,
        )
        for finding in filter_result.kept
    ]

    # Put mapped findings back on their projects and aggregate.
    mapped_by_id = {
        (f.project_id, f.finding_id): f for f in mapped
    }
    for project in projects:
        project.findings = [
            mapped_by_id[(f.project_id, f.finding_id)]
            for f in filter_result.kept
            if f.project_id == project.project_id
        ]

    summaries = None
    if not demo and cfg.api.include_summary:
        from .sdk_client import CxOneClient

        summaries = CxOneClient().fetch_summaries(
            [p.scan_id for p in projects]
        )

    data = build_report_data(
        projects,
        cfg,
        filtered_out=filter_result.filtered_out,
        summary_crosscheck=summaries,
        skipped_projects=skipped,
        data_notes=data_notes,
    )

    out_path = cfg.output.pdf_path
    pdf_path = build_pdf(data, cfg, out_path)
    log.info(
        "Report written: %s (%d findings, %d projects, %d skipped)",
        pdf_path, data.totals["kept"], data.totals["projects"],
        len(skipped),
    )
    return str(pdf_path)


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.demo and args.application:
        print(
            "ERROR: --application and --demo are mutually exclusive.",
            file=sys.stderr,
        )
        return 2

    if args.demo and not args.config:
        from .demo.demo_config import build_demo_config

        cfg = build_demo_config(args.output or "out/demo_report.pdf")
    else:
        if not args.config:
            print(
                "ERROR: --config is required (or use --demo for a "
                "synthetic report).",
                file=sys.stderr,
            )
            return 2
        try:
            cfg = load_config(
                args.config,
                require_projects=args.application is None,
            )
        except ConfigError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    if args.application:
        from .config import ProjectConfig
        from .sdk_client import CxOneClient

        client = CxOneClient()
        application_id = client.get_application_id_by_name(args.application)
        if not application_id:
            print(
                f"ERROR: application not found: {args.application!r}",
                file=sys.stderr,
            )
            return 2
        app_projects = client.get_projects_for_application(application_id)
        existing_ids = {p.id for p in cfg.projects if p.id}
        for project in app_projects:
            if project.id and project.id not in existing_ids:
                cfg.projects.append(
                    ProjectConfig(id=project.id, display_name=project.name)
                )
                existing_ids.add(project.id)
        print(
            f"Application {args.application!r}: "
            f"{len(app_projects)} project(s) in scope."
        )

    if args.main_branch_only:
        for project_cfg in cfg.projects:
            project_cfg.use_main_branch = True
        print("Restricting scope to main (protected) branch scans.")

    if args.output:
        cfg.output.pdf_path = args.output

    try:
        out = run(cfg, demo=args.demo)
    except ToolError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Report written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
