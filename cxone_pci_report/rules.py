"""Built-in mapping rules: findings -> PCI DSS v4.0.1 requirements.

Rules are evaluated in table order; a finding accumulates every matching
requirement and its primary requirement is the lowest-priority match.
Priorities are 10..90 in steps of 10 (lower = stronger primary).
"""

from dataclasses import dataclass

from .models import Scanner

# Match types understood by pci_map.map_finding:
#   query_name_regex     - SAST finding title (query name)
#   kics_query_name_regex- KICS finding title (query name)
#   apisec_risk_type     - APISec finding title (risk name)
#   cwe                  - finding cwe (prefix-normalized, "CWE-89" == "89")
#   cve_regex            - finding cve
#   package_regex        - SCA package name
#   description_regex    - finding description
MATCH_TYPES = frozenset(
    {
        "query_name_regex",
        "kics_query_name_regex",
        "apisec_risk_type",
        "cwe",
        "cve_regex",
        "package_regex",
        "description_regex",
    }
)


@dataclass(frozen=True)
class MappingRule:
    rule_id: str
    requirement: str
    scanners: tuple[Scanner, ...] | None  # None = any scanner
    match_type: str
    pattern: str
    priority: int = 30


SAST = (Scanner.SAST,)
SCA = (Scanner.SCA,)
KICS = (Scanner.KICS,)
APISEC = (Scanner.APISEC,)


BUILT_IN_RULES: tuple[MappingRule, ...] = (
    # ---------------------------------------------------------------- 6.5.1
    MappingRule("sast-sql-inj", "6.5.1", SAST, "query_name_regex",
                r"(?i)(sql|second_order_sql|blind_sql|hql)_injection", 10),
    MappingRule("sast-cmd-inj", "6.5.1", SAST, "query_name_regex",
                r"(?i)(command|os_command|cmd)_injection", 10),
    MappingRule("sast-ldap-inj", "6.5.1", SAST, "query_name_regex",
                r"(?i)ldap_injection", 10),
    MappingRule("sast-xpath-inj", "6.5.1", SAST, "query_name_regex",
                r"(?i)xpath_injection", 10),
    MappingRule("sast-xss", "6.5.1", SAST, "query_name_regex",
                r"(?i)(reflected|stored|dom|universal)_xss", 10),
    MappingRule("sast-xxe", "6.5.1", SAST, "query_name_regex",
                r"(?i)xxe|xml_external_entit", 10),
    MappingRule("sast-ssrf", "6.5.1", SAST, "query_name_regex",
                r"(?i)ssrf|server_side_request_forgery", 10),
    MappingRule("cwe-89", "6.5.1", None, "cwe", "CWE-89", 10),
    MappingRule("cwe-78", "6.5.1", None, "cwe", "CWE-78", 10),
    MappingRule("cwe-90", "6.5.1", None, "cwe", "CWE-90", 10),
    MappingRule("cwe-643", "6.5.1", None, "cwe", "CWE-643", 10),
    MappingRule("cwe-611", "6.5.1", None, "cwe", "CWE-611", 10),
    MappingRule("cwe-79", "6.5.1", None, "cwe", "CWE-79", 10),
    MappingRule("cwe-918", "6.5.1", None, "cwe", "CWE-918", 10),
    MappingRule("cwe-94", "6.5.1", None, "cwe", "CWE-94", 10),
    MappingRule("apisec-sqli", "6.5.1", APISEC, "apisec_risk_type",
                r"(?i)sql injection", 10),
    MappingRule("apisec-xss", "6.5.1", APISEC, "apisec_risk_type",
                r"(?i)cross.?site scripting|xss", 10),
    MappingRule("apisec-injection", "6.5.1", APISEC, "apisec_risk_type",
                r"(?i)(command|code|nosql|ldap|xpath)\s?injection", 10),
    # ---------------------------------------------------------------- 6.5.2
    MappingRule("cwe-120", "6.5.2", None, "cwe", "CWE-120", 10),
    MappingRule("cwe-121", "6.5.2", None, "cwe", "CWE-121", 10),
    MappingRule("cwe-122", "6.5.2", None, "cwe", "CWE-122", 10),
    MappingRule("cwe-787", "6.5.2", None, "cwe", "CWE-787", 10),
    MappingRule("sast-buffer-overflow", "6.5.2", SAST, "query_name_regex",
                r"(?i)buffer_overflow|unchecked_buffer|array_index", 10),
    # ---------------------------------------------------------------- 6.5.3
    MappingRule("sast-hardcoded-pwd", "6.5.3", SAST, "query_name_regex",
                r"(?i)hardcoded_(password|credential|secret|connection_string|api_key)", 10),
    MappingRule("sast-weak-crypto", "6.5.3", SAST, "query_name_regex",
                r"(?i)(weak|insecure|broken)_(crypt|hash|encrypt|random|cipher)", 10),
    MappingRule("sast-des-md5", "6.5.3", SAST, "query_name_regex",
                r"(?i)(\bdes\b|\bmd5\b|\brc4\b|sha1).*(hash|encrypt|crypt)", 10),
    MappingRule("cwe-798", "6.5.3", None, "cwe", "CWE-798", 10),
    MappingRule("cwe-327", "6.5.3", None, "cwe", "CWE-327", 20),
    MappingRule("cwe-326", "6.5.3", None, "cwe", "CWE-326", 20),
    MappingRule("cwe-259", "6.5.3", None, "cwe", "CWE-259", 10),
    MappingRule("cwe-312", "6.5.3", None, "cwe", "CWE-312", 20),
    MappingRule("cwe-311", "6.5.3", None, "cwe", "CWE-311", 30),
    MappingRule("kics-secrets", "6.5.3", KICS, "kics_query_name_regex",
                r"(?i)passwords and secrets|plain.?text credential|hardcoded secret|hard.?coded password", 10),
    MappingRule("apisec-pii", "6.5.3", APISEC, "apisec_risk_type",
                r"(?i)(excessive data exposure|sensitive data|pii|personal data)", 20),
    # ---------------------------------------------------------------- 6.5.4
    MappingRule("cwe-319", "6.5.4", None, "cwe", "CWE-319", 10),
    MappingRule("cwe-295", "6.5.4", None, "cwe", "CWE-295", 20),
    MappingRule("cwe-326-comm", "6.5.4", None, "cwe", "CWE-326", 30),
    MappingRule("sast-cleartext", "6.5.4", SAST, "query_name_regex",
                r"(?i)cleartext_transmission|insecure_transport|http_?only|missing_ssl|insecure_ssl", 10),
    MappingRule("kics-insecure-tls", "6.5.4", KICS, "kics_query_name_regex",
                r"(?i)(insecure tls|outdated ssl|tls .*(version|protocol)|ssl certificate|alb.*http|http.*(listener|redirect))", 10),
    MappingRule("apisec-cleartext", "6.5.4", APISEC, "apisec_risk_type",
                r"(?i)(insecure transport|cleartext|unencrypted)", 10),
    # ---------------------------------------------------------------- 6.5.5
    MappingRule("cwe-209", "6.5.5", None, "cwe", "CWE-209", 10),
    MappingRule("cwe-200", "6.5.5", None, "cwe", "CWE-200", 20),
    MappingRule("sast-info-exposure", "6.5.5", SAST, "query_name_regex",
                r"(?i)verbose_error|stack_trace|information_exposure|error_message_(info|leak)", 10),
    MappingRule("apisec-error-handling", "6.5.5", APISEC, "apisec_risk_type",
                r"(?i)(improper error handling|stack ?trace|verbose error)", 10),
    # ---------------------------------------------------------------- 6.5.6
    MappingRule("cwe-502", "6.5.6", None, "cwe", "CWE-502", 10),
    MappingRule("cwe-434", "6.5.6", None, "cwe", "CWE-434", 20),
    MappingRule("cwe-470", "6.5.6", None, "cwe", "CWE-470", 20),
    MappingRule("sca-log4shell", "6.5.6", SCA, "cve_regex",
                r"CVE-2021-44228|CVE-2021-45046|CVE-2021-45105", 10),
    MappingRule("sca-spring4shell", "6.5.6", SCA, "cve_regex",
                r"CVE-2022-22965", 10),
    MappingRule("sca-pkg-struts", "6.5.6", SCA, "package_regex",
                r"(?i)(struts2|struts-core|log4j-core)", 20),
    MappingRule("sast-deserialization", "6.5.6", SAST, "query_name_regex",
                r"(?i)deserialization|untrusted_(object|input)", 10),
    MappingRule("apisec-mass-assignment", "6.5.6", APISEC, "apisec_risk_type",
                r"(?i)(mass assignment|server.?side request forgery)", 20),
    # ---------------------------------------------------------------- 6.2.4
    MappingRule("cwe-287", "6.2.4", None, "cwe", "CWE-287", 10),
    MappingRule("cwe-306", "6.2.4", None, "cwe", "CWE-306", 10),
    MappingRule("cwe-862", "6.2.4", None, "cwe", "CWE-862", 10),
    MappingRule("cwe-863", "6.2.4", None, "cwe", "CWE-863", 10),
    MappingRule("cwe-352", "6.2.4", None, "cwe", "CWE-352", 10),
    MappingRule("cwe-613", "6.2.4", None, "cwe", "CWE-613", 10),
    MappingRule("cwe-384", "6.2.4", None, "cwe", "CWE-384", 10),
    MappingRule("cwe-620", "6.2.4", None, "cwe", "CWE-620", 10),
    MappingRule("sast-auth", "6.2.4", SAST, "query_name_regex",
                r"(?i)(broken|missing|weak)_(auth|session|access_control)|csrf|cross.?site request forgery|privilege_escalation", 10),
    MappingRule("apisec-bola", "6.2.4", APISEC, "apisec_risk_type",
                r"(?i)(broken object level auth|bola|broken function level auth|bfa|broken authentication|missing authentication)", 10),
    # ---------------------------------------------------------------- 6.4.1
    MappingRule("apisec-common-vulns", "6.4.1", APISEC, "apisec_risk_type",
                r"(?i)(misconfiguration|security misconfig|improper assets management|unrestricted access|debug endpoint)", 20),
    # ---------------------------------------------------------------- 6.4.2
    MappingRule("kics-waf", "6.4.2", KICS, "kics_query_name_regex",
                r"(?i)(waf|web application firewall)", 20),
    # ---------------------------------------------------------------- 11.3.2
    MappingRule("kics-public-s3", "11.3.2", KICS, "kics_query_name_regex",
                r"(?i)s3 bucket.*(public|acl|policy)|cloudfront.*insecure|public.*(bucket|storage|endpoint)", 10),
    # ---------------------------------------------------------------- 11.3.1
    MappingRule("kics-iam", "11.3.1", KICS, "kics_query_name_regex",
                r"(?i)iam.*(policy|user|role)|security group.*(open|wide)|open.*port|unrestricted.*ingress|privileged (container|pod)", 10),
    MappingRule("kics-k8s", "11.3.1", KICS, "kics_query_name_regex",
                r"(?i)(kubernetes|container|dockerfile|terraform|cloudformation).*(misconfig|insecure|privilege)", 20),
    # ---------------------------------------------------------------- 6.3.3
    MappingRule("sca-all", "6.3.3", SCA, "cve_regex",
                r"CVE-\d{4}-\d{4,7}", 30),
)

BUILT_IN_RULES_BY_ID: dict[str, MappingRule] = {
    rule.rule_id: rule for rule in BUILT_IN_RULES
}
