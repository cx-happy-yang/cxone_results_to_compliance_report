"""Unit tests for the SDK access layer (no network: internal SDK functions
are replaced with fakes)."""

from types import SimpleNamespace

import pytest

from cxone_pci_report.config import ApiConfigSection, ReportConfig
from cxone_pci_report.sdk_client import CxOneClient, CxOneError


class FakeSastResp(dict):
    """Mimics the SDK's dict response: {'results': [...], 'totalCount': n}."""

    def __init__(self, results, total):
        super().__init__(results=results, totalCount=total)


class FakeKicsResp:
    def __init__(self, results, total):
        self.results = results
        self.total_count = total


class FakeRiskResp:
    def __init__(self, entries, has_next, next_page):
        self.entries = entries
        self.has_next = has_next
        self.next_page_number = next_page
        self.total_records = 0


class FakeSca:
    """Stands in for ScaAPI: exposes api_client + the legacy method."""

    def __init__(self, vulns):
        self.vulns = vulns
        self.called_urls = []
        self.api_client = SimpleNamespace(
            configuration=SimpleNamespace(
                server_base_url="https://fake.ast.checkmarx.net"
            ),
            call_api=self._call_api,
        )

    def _call_api(self, method, url):
        self.called_urls.append((method, url))
        return SimpleNamespace(json=lambda: self.vulns)

    def get_vulnerabilities_of_a_scan(self, scan_id):
        return self.vulns


class FakeSubsetScan:
    id = "scan-9"
    created_at = "2026-09-10T08:00:00Z"
    status = "Completed"
    branch = "main"
    engines = ["sast", "sca", "kics", "apisec"]


def _client(**overrides) -> CxOneClient:
    client = CxOneClient.__new__(CxOneClient)
    client._get_project_id_by_name = lambda name: {"proj": "pid-1"}.get(name)

    def fake_last_scan(project_ids, use_main_branch=False):
        return {pid: FakeSubsetScan() for pid in project_ids}

    client._get_last_scan_info = fake_last_scan
    client._get_sast_results = lambda scan_id, offset, limit: FakeSastResp(
        [], 0
    )
    client._get_kics_results = lambda scan_id, offset, limit: FakeKicsResp(
        [], 0
    )
    client._get_apisec_risks = lambda scan_id, page, per_page: FakeRiskResp(
        [], False, None
    )
    client._get_summary = lambda scan_ids: {}
    client._sca = FakeSca([])
    for key, value in overrides.items():
        setattr(client, key, value)
    return client


def _cfg() -> ReportConfig:
    return ReportConfig(api=ApiConfigSection(page_size=2))


def test_sast_pagination_loops_over_pages():
    calls = []

    def fake_sast(scan_id, offset, limit):
        calls.append(offset)
        if offset == 0:
            return FakeSastResp(["a", "b"], 5)
        if offset == 2:
            return FakeSastResp(["c", "d"], 5)
        return FakeSastResp(["e"], 5)

    client = _client(_get_sast_results=fake_sast)
    results = client.fetch_sast("scan-1", page_size=2)
    assert results == ["a", "b", "c", "d", "e"]
    assert calls == [0, 2, 4]


def test_kics_pagination_loops_over_pages():
    def fake_kics(scan_id, offset, limit):
        if offset == 0:
            return FakeKicsResp(["x", "y"], 3)
        return FakeKicsResp(["z"], 3)

    client = _client(_get_kics_results=fake_kics)
    assert client.fetch_kics("scan-1", page_size=2) == ["x", "y", "z"]


def test_apisec_pagination_follows_next_page():
    def fake_apisec(scan_id, page, per_page):
        if page == 1:
            return FakeRiskResp(["r1"], has_next=True, next_page=2)
        return FakeRiskResp(["r2"], has_next=False, next_page=None)

    client = _client(_get_apisec_risks=fake_apisec)
    assert client.fetch_apisec("scan-1", per_page=1) == ["r1", "r2"]


def test_resolve_project_id_missing_raises():
    client = _client()
    with pytest.raises(CxOneError, match="Project not found"):
        client.resolve_project_id("nope")


def test_get_last_scan_passes_use_main_branch():
    calls = []

    def fake_last_scan(project_ids, use_main_branch):
        calls.append((project_ids, use_main_branch))
        return {pid: FakeSubsetScan() for pid in project_ids}

    client = _client(_get_last_scan_info=fake_last_scan)
    assert client.get_last_scan("pid-1", use_main_branch=True) is not None
    assert calls == [(["pid-1"], True)]


def test_fetch_sca_uses_api_sca_prefixed_url():
    """Regression: the SDK's Sca.get_vulnerabilities_of_a_scan omits the
    /api/sca prefix (nginx 400); our fetch must call the correct path."""
    sca = FakeSca([{"id": "CVE-2020-1111"}])
    client = _client(_sca=sca)
    result = client.fetch_sca("scan-1")
    assert result == [{"id": "CVE-2020-1111"}]
    method, url = sca.called_urls[0]
    assert method == "GET"
    assert url == (
        "https://fake.ast.checkmarx.net/api/sca/risk-management/"
        "risk-reports/scan-1/vulnerabilities"
    )


def test_application_helpers():
    class FakeProject:
        id = "p-1"
        name = "proj-a"

    class FakeCollection:
        projects = [FakeProject()]

    client = _client(
        _get_application_id_by_name=lambda name: "app-1" if name == "happy" else None,
        _get_projects_for_application=lambda app_id: FakeCollection(),
    )
    assert client.get_application_id_by_name("happy") == "app-1"
    assert client.get_application_id_by_name("nope") is None
    projects = client.get_projects_for_application("app-1")
    assert projects[0].name == "proj-a"


def test_resolve_project_id_found():
    client = _client()
    assert client.resolve_project_id("proj") == "pid-1"


def test_fetch_project_scan_by_name():
    from cxone_pci_report.config import ProjectConfig
    from tests.conftest import FakeSastResult

    sast = FakeSastResult(
        id="r-1", query_name="SQL_Injection", cwe_id=89,
        severity="HIGH", state="TO_VERIFY", status="NEW",
        nodes=[],
    )
    client = _client(
        _get_sast_results=lambda scan_id, offset, limit: FakeSastResp([sast], 1)
    )
    project, ignored, notes = client.fetch_project_scan(
        ProjectConfig(name="proj"), _cfg()
    )
    assert project.project_id == "pid-1"
    assert project.project_name == "proj"
    assert project.scan_id == "scan-9"
    assert project.scan_status == "Completed"
    assert len(project.findings) == 1
    assert project.findings[0].title == "SQL_Injection"
    assert ignored == 0


def test_fetch_project_scan_with_scan_id_override():
    from cxone_pci_report.config import ProjectConfig

    client = _client()
    project, _, notes = client.fetch_project_scan(
        ProjectConfig(id="pid-x", scan_id="scan-override"), _cfg()
    )
    assert project.scan_id == "scan-override"


def test_fetch_project_scan_excludes_ignored_sca():
    from cxone_pci_report.config import ProjectConfig

    client = _client(
        _sca=FakeSca(
            [
                {
                    "id": "CVE-2020-1111",
                    "cveName": "CVE-2020-1111",
                    "severity": "High",
                    "packageId": "Maven-a:b-1.0",
                    "isIgnored": True,
                },
                {
                    "id": "CVE-2020-2222",
                    "cveName": "CVE-2020-2222",
                    "severity": "High",
                    "packageId": "Maven-a:c-1.0",
                    "isIgnored": False,
                },
            ]
        )
    )
    project, ignored, notes = client.fetch_project_scan(
        ProjectConfig(id="pid-x"), _cfg()
    )
    assert ignored == 1
    cves = [f.cve for f in project.findings if f.scanner.value == "sca"]
    assert cves == ["CVE-2020-2222"]
