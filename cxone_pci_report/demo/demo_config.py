"""Demo ReportConfig (no logo, three fake projects)."""

from ..config import (
    ApiConfigSection,
    AppearanceConfigSection,
    FilterConfigSection,
    MappingConfigSection,
    OutputConfigSection,
    ProjectConfig,
    ReportConfig,
    ReportConfigSection,
)


def build_demo_config(output_pdf_path: str) -> ReportConfig:
    return ReportConfig(
        report=ReportConfigSection(
            title="PCI DSS v4.0.1 Application Security Gap Assessment",
            company_name="ACME Retail (Demo Data)",
            auditor="Security Engineering Team",
            prepared_date="2026-09-11",
            assessment_period="2026-08-01 to 2026-09-10",
            confidentiality="Confidential",
            logo_path=None,
            language="en",
        ),
        output=OutputConfigSection(pdf_path=output_pdf_path),
        filters=FilterConfigSection(),
        projects=[
            ProjectConfig(name="web-shop"),
            ProjectConfig(name="payment-gateway"),
            ProjectConfig(name="admin-portal"),
        ],
        mapping=MappingConfigSection(),
        appearance=AppearanceConfigSection(),
        api=ApiConfigSection(),
    )
