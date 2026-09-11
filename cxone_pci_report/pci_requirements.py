"""PCI DSS v4.0.1 requirement data referenced by the mapping engine.

The requirement texts below are short paraphrases for report readability.
PCI SSC is the authoritative source for the normative requirement text.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class PciRequirement:
    requirement: str  # e.g. "6.3.1"
    title: str
    text: str
    guidance: str
    scanners: tuple[str, ...]  # scanner names primarily evidenced


PCI_REQUIREMENTS: tuple[PciRequirement, ...] = (
    PciRequirement(
        requirement="6.2.4",
        title="Software engineering techniques / secure development",
        text=(
            "Software is developed in accordance with industry standards and "
            "best practices. Code reviews, secure coding practices and "
            "controlled change procedures protect cardholder data. Findings "
            "related to broken authentication, broken access control, "
            "insecure session management and cross-site request forgery are "
            "evidence of gaps here."
        ),
        guidance=(
            "Review findings tagged to this requirement with the development "
            "team; enforce secure coding standards and peer code review for "
            "high-risk changes."
        ),
        scanners=("sast", "apisec"),
    ),
    PciRequirement(
        requirement="6.3.1",
        title="Security vulnerabilities identified and managed",
        text=(
            "All system components and software are protected from known "
            "vulnerabilities: vendor security patches are applied, and "
            "vulnerabilities are ranked by risk and remediated on a timely "
            "basis. This requirement is the default bucket for findings that "
            "do not match a more specific requirement."
        ),
        guidance=(
            "Rank findings by severity and exploitability; define and track "
            "remediation SLAs based on risk rating."
        ),
        scanners=("sast", "kics", "apisec"),
    ),
    PciRequirement(
        requirement="6.3.3",
        title="Third-party software components",
        text=(
            "All bespoke and custom software is reviewed and secured before "
            "production. Third-party and open-source components are "
            "inventoried, and known vulnerabilities in those components are "
            "identified and managed."
        ),
        guidance=(
            "Maintain a software component inventory (SBOM); upgrade "
            "vulnerable packages to patched versions or apply mitigations."
        ),
        scanners=("sca",),
    ),
    PciRequirement(
        requirement="6.4.1",
        title="Public-facing web applications — vulnerability review",
        text=(
            "Public-facing web applications are reviewed for common "
            "vulnerabilities, manually or with automated tools, at least "
            "annually and after significant change."
        ),
        guidance=(
            "Include public-facing endpoints in recurring SAST/API security "
            "reviews; document review results."
        ),
        scanners=("apisec", "sast"),
    ),
    PciRequirement(
        requirement="6.4.2",
        title="Public-facing web applications — automated protection",
        text=(
            "Automated technical solutions that detect and prevent web-based "
            "attacks (e.g. a web application firewall) are deployed in front "
            "of public-facing web applications. Findings on public-facing "
            "assets evidence residual exposure."
        ),
        guidance=(
            "Verify WAF/inline protection coverage for public-facing "
            "applications; tune rules to block the attack types identified."
        ),
        scanners=("apisec", "kics"),
    ),
    PciRequirement(
        requirement="6.5.1",
        title="Injection flaws",
        text=(
            "Web applications are not vulnerable to injection flaws: SQL, "
            "LDAP, XPath and command injection, XML external entities (XXE), "
            "cross-site scripting (XSS) and server-side request forgery "
            "(SSRF)."
        ),
        guidance=(
            "Use parameterized queries, contextual output encoding, and "
            "safe parsers; disallow external entity resolution."
        ),
        scanners=("sast", "apisec", "sca"),
    ),
    PciRequirement(
        requirement="6.5.2",
        title="Buffer overflows",
        text=(
            "Web applications are not vulnerable to buffer overflow attacks; "
            "memory-unsafe operations on untrusted input are eliminated."
        ),
        guidance=(
            "Bounds-check all input handling; prefer memory-safe languages "
            "and libraries."
        ),
        scanners=("sast",),
    ),
    PciRequirement(
        requirement="6.5.3",
        title="Insecure cryptographic storage",
        text=(
            "Sensitive authentication data and PAN are not stored "
            "insecurely: hardcoded secrets and credentials are removed and "
            "weak hashing/encryption is replaced with strong cryptography."
        ),
        guidance=(
            "Rotate exposed credentials; migrate to approved key lengths, "
            "hashing algorithms and secret management."
        ),
        scanners=("sast", "kics", "sca"),
    ),
    PciRequirement(
        requirement="6.5.4",
        title="Insecure communications",
        text=(
            "Sensitive data is not transmitted in cleartext; insecure "
            "transport and TLS configuration weaknesses are remediated."
        ),
        guidance=(
            "Enforce TLS 1.2+ with strong cipher suites for all "
            "cardholder-data channels."
        ),
        scanners=("sast", "kics", "apisec"),
    ),
    PciRequirement(
        requirement="6.5.5",
        title="Improper error handling",
        text=(
            "Error handling does not leak system information to untrusted "
            "users: verbose error messages, stack traces and excessive "
            "information exposure are removed."
        ),
        guidance=(
            "Return generic error responses; log details server-side only."
        ),
        scanners=("sast", "kics"),
    ),
    PciRequirement(
        requirement="6.5.6",
        title="Other high-risk vulnerabilities",
        text=(
            "All other high-risk vulnerabilities identified via trusted "
            "sources (e.g. OWASP Top 10, CVSS >= 9.0) are remediated: "
            "deserialization flaws, remote-code-execution-class CVEs and "
            "similar critical issues."
        ),
        guidance=(
            "Prioritize critical/CVSS 9+ findings for immediate "
            "remediation; apply vendor patches as released."
        ),
        scanners=("sast", "sca", "apisec"),
    ),
    PciRequirement(
        requirement="11.3.1",
        title="Internal vulnerability scans",
        text=(
            "Internal vulnerability scans are performed at least quarterly "
            "and after significant change; high-risk and critical findings "
            "are resolved and rescans confirm remediation. Findings in "
            "infrastructure-as-code and internal components are evidence."
        ),
        guidance=(
            "Treat IaC misconfigurations like internal scan findings: "
            "remediate, then verify with a follow-up scan."
        ),
        scanners=("sca", "kics", "sast"),
    ),
    PciRequirement(
        requirement="11.3.2",
        title="External vulnerability scans",
        text=(
            "External vulnerability scans are performed at least quarterly "
            "by an Approved Scanning Vendor (ASV). External-facing assets "
            "must be free of exploitable high-risk and critical issues. "
            "Findings on public-facing infrastructure and APIs are evidence."
        ),
        guidance=(
            "Remediate external-facing findings and pass a follow-up ASV "
            "scan to close the requirement."
        ),
        scanners=("apisec", "kics"),
    ),
)

REQUIREMENT_BY_ID: dict[str, PciRequirement] = {
    req.requirement: req for req in PCI_REQUIREMENTS
}
