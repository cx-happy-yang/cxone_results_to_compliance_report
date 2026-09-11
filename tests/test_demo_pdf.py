"""End-to-end test: demo pipeline must produce a real multi-page PDF."""

from cxone_pci_report.cli import run
from cxone_pci_report.demo.demo_config import build_demo_config


def test_demo_pipeline_builds_pdf(tmp_path):
    out = tmp_path / "demo_report.pdf"
    cfg = build_demo_config(str(out))
    result = run(cfg, demo=True)
    assert result == str(out)

    raw = out.read_bytes()
    assert raw[:5] == b"%PDF-"
    assert len(raw) > 20_000

    # Page count via the /Type /Page marker (compressed object streams may
    # hide some, so use a generous floor: the report has well over 15 pages).
    page_markers = raw.count(b"/Type /Page")
    assert page_markers > 15
    assert b"PCI DSS" in raw or b"PCI" in raw
