"""Command-line entrypoint: config -> fetch/demo -> filter -> map -> PDF."""

import argparse
import logging
import sys

from . import __version__, TOOL_NAME
from .aggregate import build_report_data
from .config import ConfigError, load_config
from .filter import apply_filters
from .models import ProjectScan
from .pci_map import MappingError, load_rules, map_finding
from .report.builder import build_pdf

log = logging.getLogger(__name__)


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


def _fetch_projects(cfg):
    """Live path: fetch each configured project via the SDK."""
    from .sdk_client import CxOneClient, CxOneError

    client = CxOneClient()
    projects: list[ProjectScan] = []
    ignored_total = 0
    for project_cfg in cfg.projects:
        log.info(
            "Fetching project %s", project_cfg.name or project_cfg.id
        )
        try:
            project, ignored = client.fetch_project_scan(project_cfg, cfg)
        except CxOneError as exc:
            raise SystemExit(f"ERROR: {exc}") from exc
        except Exception as exc:  # httpx / SDK errors
            raise SystemExit(
                f"ERROR: failed to fetch project "
                f"{project_cfg.name or project_cfg.id!r}: {exc}"
            ) from exc
        projects.append(project)
        ignored_total += ignored
        log.info(
            "Project %s: %d findings fetched",
            project.display_name, len(project.findings),
        )
    return projects, ignored_total


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
        raise SystemExit(f"ERROR: {exc}") from exc

    if demo:
        log.info("Demo mode: using synthetic scan data.")
        projects, ignored_total = _demo_projects(cfg)
    else:
        projects, ignored_total = _fetch_projects(cfg)

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
    )

    out_path = cfg.output.pdf_path
    pdf_path = build_pdf(data, cfg, out_path)
    log.info(
        "Report written: %s (%d findings, %d projects)",
        pdf_path, data.totals["kept"], data.totals["projects"],
    )
    return str(pdf_path)


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

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
            cfg = load_config(args.config)
        except ConfigError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    if args.output:
        cfg.output.pdf_path = args.output

    try:
        out = run(cfg, demo=args.demo)
    except SystemExit as exc:
        return int(exc.code or 1)
    print(f"Report written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
