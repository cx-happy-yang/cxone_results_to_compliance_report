"""Synthetic scan payloads for --demo mode.

Shaped exactly like the real SDK payloads (SastResult / KicsResult /
APISec Risk attribute names, SCA vulnerability dicts) so the demo exercises
the same normalize -> filter -> map -> PDF pipeline as a live run.
"""

from dataclasses import dataclass, field
from types import SimpleNamespace

from ..models import ProjectScan


@dataclass
class DemoProject:
    """Raw payloads for one fake project."""

    project_id: str
    project_name: str
    scan_id: str
    scan_created_at: str
    scan_status: str
    branch: str
    engines: list[str]
    sast: list = field(default_factory=list)
    sca: list = field(default_factory=list)
    kics: list = field(default_factory=list)
    apisec: list = field(default_factory=list)


def _node(file_name: str, line: int):
    return SimpleNamespace(
        column=1, file_name=file_name, full_name=None, length=0,
        line=line, method_line=None, method=None, name=None,
        dom_type=None, node_hash=None,
    )


def _sast(
    result_id: str,
    query_name: str,
    cwe_id: int,
    severity: str,
    file_name: str,
    line: int,
    *,
    state: str = "TO_VERIFY",
    status: str = "NEW",
    similarity_id: int = 0,
    compliances: list | None = None,
    description: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=result_id, result_hash=result_id, query_id=0,
        query_name=query_name, language_name=None, query_group=None,
        cwe_id=cwe_id, severity=severity, similarity_id=similarity_id,
        confidence_level=4, compliances=compliances,
        first_scan_id="scan-1", first_found_at="2026-08-01T10:00:00Z",
        status=status, found_at="2026-08-01T10:00:00Z",
        nodes=[_node(file_name, line)], state=state,
        description=description,
    )


def _kics(
    result_id: str,
    query_name: str,
    severity: str,
    file_name: str,
    line: int,
    *,
    state: str = "TO_VERIFY",
    status: str = "NEW",
    expected: str | None = None,
    actual: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        kics_result_id=result_id, similarity_id=0, severity=severity,
        first_scan_id="scan-1", first_found_at="2026-08-01T10:05:00Z",
        found_at="2026-08-01T10:05:00Z", status=status, state=state,
        query_id=0, query_name=query_name, file_name=file_name, line=line,
        expected_value=expected, actual_value=actual, description=None,
    )


def _risk(
    risk_id: str,
    risk_name: str,
    severity: str,
    asset_name: str,
    *,
    state: str = "TO_VERIFY",
    status: str = "NEW",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=risk_id, riskName=risk_name, status=status, state=state,
        severity=severity, firstDetectionDate="2026-07-20T09:00:00Z",
        origin="PR Webhook", source="github", assetName=asset_name,
        subAssetName=None, projectId=None, scanId=None, engine="SAST",
        groupId=None, assetType="ENDPOINT", stateChangedBy="MANUAL",
    )


def _sca(
    cve: str,
    severity: str,
    score: float,
    package_id: str,
    *,
    cwe: str | None = None,
    description: str | None = None,
    recommendation: str | None = None,
    fix: str | None = None,
    is_ignored: bool = False,
) -> dict:
    return {
        "id": cve,
        "cveName": cve,
        "score": score,
        "severity": severity,
        "publishDate": "2026-06-01T00:00:00Z",
        "references": [],
        "description": description or f"{cve} vulnerability.",
        "cvss": {"version": 3.1},
        "recommendations": recommendation,
        "packageId": package_id,
        "similarityId": None,
        "fixResolutionText": fix,
        "isIgnored": is_ignored,
        "exploitableMethods": [],
        "cwe": cwe,
    }


def build_demo_projects() -> list[DemoProject]:
    web_shop = DemoProject(
        project_id="demo-proj-1",
        project_name="web-shop",
        scan_id="demo-scan-1",
        scan_created_at="2026-09-10T08:00:00Z",
        scan_status="Completed",
        branch="main",
        engines=["sast", "sca", "kics", "apisec"],
        sast=[
            _sast("ws-s1", "SQL_Injection", 89, "HIGH",
                  "src/api/orders.py", 42,
                  similarity_id=101, compliances=["PCI DSS", "OWASP TOP 10"],
                  description="User input flows into an SQL query without parameterization."),
            _sast("ws-s2", "Reflected_XSS_All_Clients", 79, "HIGH",
                  "src/web/search.py", 88, similarity_id=102,
                  compliances=["PCI DSS"]),
            _sast("ws-s3", "Hardcoded_Password_in_Connection_String", 798, "CRITICAL",
                  "src/config/db.py", 12, similarity_id=103),
            _sast("ws-s4", "Command_Injection", 78, "HIGH",
                  "src/tools/backup.py", 55, similarity_id=104),
            _sast("ws-s5", "Stored_XSS", 79, "MEDIUM",
                  "src/web/reviews.py", 121, similarity_id=105),
            _sast("ws-s6", "CSRF", 352, "MEDIUM",
                  "src/web/checkout.py", 33, similarity_id=106,
                  compliances=["PCI DSS"]),
            _sast("ws-s7", "Weak_Cryptographic_Hash_MD5", 327, "MEDIUM",
                  "src/util/hash.py", 9, similarity_id=107),
            _sast("ws-s8", "Verbose_Error_Message", 209, "LOW",
                  "src/web/errors.py", 71, similarity_id=108),
            _sast("ws-s9", "XXE_Xml_External_Entity", 611, "HIGH",
                  "src/import/parser.py", 15, similarity_id=109),
            _sast("ws-s10", "Insecure_Random", 330, "LOW",
                  "src/util/token.py", 44, similarity_id=110,
                  state="NOT_EXPLOITABLE"),
            _sast("ws-s11", "Unchecked_Buffer_Access", 120, "HIGH",
                  "src/native/parser.c", 203, similarity_id=111),
            _sast("ws-s12", "Deserialization_of_Untrusted_Data", 502, "HIGH",
                  "src/api/imports.py", 27, similarity_id=112),
        ],
        sca=[
            _sca("CVE-2021-44228", "Critical", 10.0,
                 "Maven-org.apache.logging.log4j:log4j-core-2.14.1",
                 cwe="CWE-502",
                 description="Log4Shell: remote code execution via JNDI lookup in log4j-core.",
                 recommendation="Upgrade to 2.17.1 or later.",
                 fix="2.17.1"),
            _sca("CVE-2021-45046", "Critical", 9.0,
                 "Maven-org.apache.logging.log4j:log4j-core-2.14.1",
                 cwe="CWE-917"),
            _sca("CVE-2015-7501", "High", 9.8,
                 "Maven-commons-collections:commons-collections-3.2.1",
                 cwe="CWE-502", fix="3.2.2"),
            _sca("CVE-2022-22965", "Critical", 9.8,
                 "Maven-org.springframework:spring-beans-5.3.6",
                 cwe="CWE-470",
                 recommendation="Upgrade Spring Framework to 5.3.18+/5.2.20+."),
            _sca("CVE-2020-13956", "Medium", 5.3,
                 "Maven-org.apache.httpcomponents:httpclient-4.5.10",
                 cwe="CWE-444"),
            _sca("CVE-2021-37136", "High", 7.5,
                 "Maven-io.netty:netty-codec-4.1.59.Final",
                 cwe="CWE-400"),
            _sca("CVE-2021-37137", "High", 7.5,
                 "Maven-io.netty:netty-codec-4.1.59.Final",
                 cwe="CWE-400"),
            _sca("CVE-2019-11358", "Medium", 6.1,
                 "Npm-jquery:jquery-3.3.1",
                 cwe="CWE-79"),
            _sca("CVE-2020-8908", "Low", 4.3,
                 "Maven-com.google.guava:guava-29.0-jre",
                 cwe="CWE-200"),
            _sca("CVE-2021-2135", "Low", 3.7,
                 "Maven-com.fasterxml.jackson.core:jackson-databind-2.11.0",
                 cwe=None, is_ignored=True),
        ],
        kics=[
            _kics("ws-k1", "S3 Bucket Allows Public ACL", "HIGH",
                  "infra/terraform/s3.tf", 3, expected="No public ACL",
                  actual="public-read ACL"),
            _kics("ws-k2", "Security Group Allows Unrestricted Ingress", "MEDIUM",
                  "infra/terraform/sg.tf", 17, expected="Restricted CIDR",
                  actual="0.0.0.0/0"),
            _kics("ws-k3", "IAM Policy Grants Full Administrative Privileges", "HIGH",
                  "infra/terraform/iam.tf", 9),
            _kics("ws-k4", "Plain Text Credential In Terraform State", "HIGH",
                  "infra/terraform/vars.tf", 5),
            _kics("ws-k5", "CloudFront Distribution Allows HTTP", "LOW",
                  "infra/terraform/cdn.tf", 21),
            _kics("ws-k6", "Container Runs With Privileged Flag", "MEDIUM",
                  "deploy/docker-compose.yml", 8),
            _kics("ws-k7", "Outdated TLS Version In Load Balancer", "MEDIUM",
                  "infra/terraform/alb.tf", 31, expected="TLS 1.2+",
                  actual="TLS 1.0"),
        ],
        apisec=[
            _risk("ws-a1", "Broken Object Level Authorization (BOLA)",
                  "CRITICAL", "/api/v1/orders/{id}", state="CONFIRMED",
                  status="RECURRENT"),
            _risk("ws-a2", "SQL Injection", "HIGH", "/api/v1/search"),
            _risk("ws-a3", "Excessive Data Exposure (PII)", "MEDIUM",
                  "/api/v1/users/me"),
            _risk("ws-a4", "Mass Assignment", "HIGH", "/api/v1/register"),
            _risk("ws-a5", "Missing Authentication", "CRITICAL",
                  "/api/v1/admin/reports", state="CONFIRMED"),
            _risk("ws-a6", "Improper Error Handling", "LOW",
                  "/api/v1/checkout"),
        ],
    )

    payment_gateway = DemoProject(
        project_id="demo-proj-2",
        project_name="payment-gateway",
        scan_id="demo-scan-2",
        scan_created_at="2026-09-09T14:30:00Z",
        scan_status="Completed",
        branch="main",
        engines=["sast", "sca", "kics", "apisec"],
        sast=[
            _sast("pg-s1", "Hardcoded_API_Key", 798, "CRITICAL",
                  "src/auth/keys.py", 8, similarity_id=201),
            _sast("pg-s2", "Insecure_TLS_Configuration", 295, "HIGH",
                  "src/net/client.py", 61, similarity_id=202),
            _sast("pg-s3", "SQL_Injection", 89, "MEDIUM",
                  "src/db/ledger.py", 118, similarity_id=203),
            _sast("pg-s4", "Race_Condition_Double_Spend", 362, "MEDIUM",
                  "src/tx/apply.py", 52, similarity_id=204,
                  state="CONFIRMED"),
            _sast("pg-s5", "Cleartext_Transmission_of_PAN", 319, "CRITICAL",
                  "src/net/gateway.py", 24, similarity_id=205),
            _sast("pg-s6", "Missing_Certificate_Validation", 295, "HIGH",
                  "src/net/conn.py", 77, similarity_id=206,
                  state="NOT_EXPLOITABLE"),
        ],
        sca=[
            _sca("CVE-2021-45105", "Critical", 7.5,
                 "Maven-org.apache.logging.log4j:log4j-core-2.14.1",
                 cwe="CWE-400"),
            _sca("CVE-2020-28052", "High", 8.1,
                 "Maven-org.bouncycastle:bcprov-jdk15on-1.65",
                 cwe="CWE-327", fix="1.67"),
            _sca("CVE-2021-28169", "Medium", 5.3,
                 "Maven-org.eclipse.jetty:jetty-util-9.4.38",
                 cwe=None),
        ],
        kics=[
            _kics("pg-k1", "Passwords And Secrets In Infrastructure Code", "HIGH",
                  "infra/ansible/secrets.yml", 2),
            _kics("pg-k2", "Security Group Allows Unrestricted Ingress", "HIGH",
                  "infra/terraform/pci-sg.tf", 11),
            _kics("pg-k3", "IAM User With Privileged Policy", "MEDIUM",
                  "infra/terraform/iam.tf", 4),
            _kics("pg-k4", "S3 Bucket Access Control List Allows Read To All", "HIGH",
                  "infra/terraform/backup.tf", 7),
        ],
        apisec=[
            _risk("pg-a1", "Broken Authentication (JWT Flaw)", "CRITICAL",
                  "/api/v1/token", state="CONFIRMED"),
            _risk("pg-a2", "Insecure Transport (HTTP Endpoint)", "HIGH",
                  "/api/v1/payments"),
            _risk("pg-a3", "Server Side Request Forgery", "HIGH",
                  "/api/v1/callbacks"),
        ],
    )

    admin_portal = DemoProject(
        project_id="demo-proj-3",
        project_name="admin-portal",
        scan_id="demo-scan-3",
        scan_created_at="2026-09-08T11:00:00Z",
        scan_status="Completed",
        branch="develop",
        engines=["sast", "sca", "kics", "apisec"],
        sast=[
            _sast("ap-s1", "Reflected_XSS_All_Clients", 79, "HIGH",
                  "src/web/users.py", 34, similarity_id=301),
            _sast("ap-s2", "Privilege_Escalation", 269, "HIGH",
                  "src/rbac/roles.py", 15, similarity_id=302),
            _sast("ap-s3", "Weak_Password_Hash_SHA1", 328, "MEDIUM",
                  "src/auth/passwords.py", 21, similarity_id=303),
            _sast("ap-s4", "Open_Redirect", 601, "MEDIUM",
                  "src/web/redirect.py", 40, similarity_id=304,
                  status="FIXED"),
        ],
        sca=[
            _sca("CVE-2021-44228", "Critical", 10.0,
                 "Maven-org.apache.logging.log4j:log4j-core-2.13.2",
                 cwe="CWE-502", fix="2.17.1"),
            _sca("CVE-2021-29425", "Medium", 6.1,
                 "Maven-commons-io:commons-io-2.6",
                 cwe="CWE-22"),
        ],
        kics=[
            _kics("ap-k1", "Kubernetes Pod Runs As Root", "MEDIUM",
                  "deploy/k8s/pod.yaml", 6),
            _kics("ap-k2", "CloudFormation Stack Allows Public SSH", "MEDIUM",
                  "infra/cfn/stack.yaml", 13),
        ],
        apisec=[
            _risk("ap-a1", "Unrestricted Access To Sensitive Endpoint", "MEDIUM",
                  "/api/v1/audit-log", state="NOT_EXPLOITABLE"),
            _risk("ap-a2", "Stored XSS Via Input", "LOW", "/api/v1/notes"),
        ],
    )

    return [web_shop, payment_gateway, admin_portal]
