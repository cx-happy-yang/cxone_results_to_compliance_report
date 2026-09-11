"""Shared fixtures: raw payloads shaped exactly like the SDK DTO output."""

from dataclasses import dataclass, field
from typing import List

import pytest


@dataclass
class FakeNode:
    column: int = None
    file_name: str = None
    full_name: str = None
    length: int = None
    line: int = None
    method_line: int = None
    method: str = None
    name: str = None
    dom_type: str = None
    node_hash: str = None


@dataclass
class FakeSastResult:
    id: str = None
    result_hash: str = None
    query_id: int = None
    query_name: str = None
    language_name: str = None
    query_group: str = None
    cwe_id: int = None
    severity: str = None
    similarity_id: int = None
    confidence_level: int = None
    compliances: List[str] = None
    first_scan_id: str = None
    first_found_at: str = None
    status: str = None
    found_at: str = None
    nodes: List[FakeNode] = field(default_factory=list)
    state: str = None
    description: str = None


@dataclass
class FakeKicsResult:
    kics_result_id: str = None
    similarity_id: int = None
    severity: str = None
    first_scan_id: str = None
    first_found_at: str = None
    found_at: str = None
    status: str = None
    state: str = None
    query_id: int = None
    query_name: str = None
    file_name: str = None
    line: int = None
    expected_value: str = None
    actual_value: str = None
    description: str = None


@dataclass
class FakeRisk:
    id: str = None
    riskName: str = None
    status: str = None
    state: str = None
    severity: str = None
    firstDetectionDate: str = None
    assetName: str = None
    assetType: str = None
    groupId: str = None


CTX = {"project_id": "proj-1", "project_name": "web-shop", "scan_id": "scan-1"}


@pytest.fixture
def sast_sql() -> FakeSastResult:
    return FakeSastResult(
        id="r-sast-1",
        result_hash="r-sast-1",
        query_id=999,
        query_name="SQL_Injection",
        cwe_id=89,
        severity="HIGH",
        similarity_id=1001,
        confidence_level=4,
        compliances=["PCI DSS", "OWASP TOP 10"],
        first_found_at="2026-08-01T10:00:00Z",
        status="NEW",
        state="TO_VERIFY",
        nodes=[FakeNode(file_name="src/api/users.py", line=42)],
    )


@pytest.fixture
def sast_malformed() -> FakeSastResult:
    return FakeSastResult(
        id=None,
        query_name=None,
        cwe_id=None,
        severity="BOGUS",
        nodes=[],
        compliances=None,
    )


@pytest.fixture
def sca_log4j() -> dict:
    return {
        "id": "CVE-2021-44228",
        "cveName": "CVE-2021-44228",
        "score": 10.0,
        "severity": "Critical",
        "publishDate": "2021-12-10T00:00:00Z",
        "description": "Log4Shell RCE in log4j-core.",
        "recommendations": "Upgrade to 2.17.1.",
        "packageId": "Maven-org.apache.logging.log4j:log4j-core-2.14.1",
        "similarityId": "simi-5",
        "fixResolutionText": "2.17.1",
        "isIgnored": False,
        "cwe": "CWE-502",
    }


@pytest.fixture
def sca_ignored() -> dict:
    return {
        "id": "CVE-2020-1234",
        "cveName": "CVE-2020-1234",
        "score": 7.5,
        "severity": "High",
        "packageId": "Maven-com.example:lib-1.0",
        "isIgnored": True,
        "cwe": "CWE-79",
    }


@pytest.fixture
def sca_malformed() -> dict:
    return {"id": None, "cveName": "", "severity": None, "packageId": ":::::"}


@pytest.fixture
def kics_open_port() -> FakeKicsResult:
    return FakeKicsResult(
        kics_result_id="r-kics-1",
        similarity_id=2001,
        severity="MEDIUM",
        status="NEW",
        state="TO_VERIFY",
        query_name="Security Group Allows Unrestricted Ingress",
        file_name="infra/terraform/main.tf",
        line=17,
        expected_value="Port 22 restricted",
        actual_value="0.0.0.0/0 open",
        first_found_at="2026-08-01T10:05:00Z",
    )


@pytest.fixture
def kics_malformed() -> FakeKicsResult:
    return FakeKicsResult(
        kics_result_id=None,
        severity=None,
        query_name=None,
        file_name=None,
        line="not-a-number",
    )


@pytest.fixture
def apisec_bola() -> FakeRisk:
    return FakeRisk(
        id="r-api-1",
        riskName="Broken Object Level Authorization (BOLA)",
        severity="CRITICAL",
        state="CONFIRMED",
        status="RECURRENT",
        firstDetectionDate="2026-07-15T09:00:00Z",
        assetName="/api/v1/orders/{id}",
        assetType="ENDPOINT",
        groupId="g-77",
    )


@pytest.fixture
def apisec_malformed() -> FakeRisk:
    return FakeRisk(id=None, riskName=None, severity="")
