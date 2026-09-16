"""PCI DSS v4.0.1 requirement data referenced by the mapping engine.

The requirement texts below are short paraphrases for report readability.
PCI SSC is the authoritative source for the normative requirement text.

``covered`` marks whether automated scan evidence (SAST/SCA/IaC/API) can
address the requirement. Uncovered requirements are listed in the report
with the reason and the responsible party (``note`` / ``owner``).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class PciRequirement:
    requirement: str  # e.g. "6.3.1"
    title: str
    text: str
    guidance: str
    scanners: tuple[str, ...]  # scanner names primarily evidenced
    covered: bool = True  # tool-based scan evidence can address it
    note: str = ""  # why out of scope (when covered=False)
    owner: str = ""  # responsible party (when covered=False)


PCI_REQUIREMENTS: tuple[PciRequirement, ...] = (
    PciRequirement(
        requirement="6.2.1",
        title="Secure software development",
        text=(
            "Bespoke and custom software is developed in accordance with "
            "industry standards and secure development practices, with "
            "security built in throughout the software development "
            "lifecycle. Findings evidencing weak security controls in "
            "application code are gaps here."
        ),
        guidance=(
            "Maintain documented secure coding standards and SDLC security "
            "activities; review high-risk findings with the development "
            "team."
        ),
        scanners=("sast", "apisec"),
    ),
    PciRequirement(
        requirement="6.2.2",
        title="Secure software engineering training",
        text=(
            "Software development personnel are trained in secure software "
            "engineering techniques at least once every 12 months, as "
            "relevant to their role and the languages in use."
        ),
        guidance=(
            "Training records and curricula are process evidence held by "
            "the customer; this assessment does not verify them."
        ),
        scanners=(),
        covered=False,
        note=(
            "Training records and curricula are process evidence; "
            "automated scan results cannot evidence this requirement."
        ),
        owner="Customer / QSA",
    ),
    PciRequirement(
        requirement="6.2.3",
        title="Pre-release code review",
        text=(
            "Bespoke and custom software is reviewed prior to release into "
            "production to identify and correct potential coding "
            "vulnerabilities, manually or with automated tools. SAST review "
            "results evidence this control."
        ),
        guidance=(
            "Run SAST reviews before each release and track sign-off; "
            "open findings are gaps in the review coverage."
        ),
        scanners=("sast",),
    ),
    PciRequirement(
        requirement="6.2.4",
        title="Software engineering techniques / common attacks",
        text=(
            "Software engineering techniques are in use to prevent or "
            "mitigate common software attacks: code reviews, secure coding "
            "practices and controlled change procedures protect cardholder "
            "data. Findings related to broken authentication, broken access "
            "control, insecure session management and cross-site request "
            "forgery are evidence of gaps here."
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
            "vulnerabilities: security vulnerabilities are identified, "
            "ranked by risk using trusted sources, and remediated on a "
            "timely basis. This requirement is the default bucket for "
            "findings that do not match a more specific requirement."
        ),
        guidance=(
            "Rank findings by severity and exploitability; define and track "
            "remediation SLAs based on risk rating."
        ),
        scanners=("sast", "kics", "apisec"),
    ),
    PciRequirement(
        requirement="6.3.2",
        title="Software and third-party component inventory (SBOM)",
        text=(
            "An inventory of bespoke and custom software, and third-party "
            "and open-source components incorporated into it, is maintained "
            "to facilitate vulnerability and patch management. Known "
            "vulnerabilities in those components are identified and "
            "managed; SCA findings evidence this requirement."
        ),
        guidance=(
            "Maintain a software component inventory (SBOM); upgrade "
            "vulnerable packages to patched versions or apply mitigations."
        ),
        scanners=("sca",),
    ),
    PciRequirement(
        requirement="6.3.3",
        title="Security patches installed",
        text=(
            "All system components and software are protected from known "
            "vulnerabilities by installing applicable vendor-supplied "
            "security patches; critical and high-severity patches are "
            "applied within one month of release. Findings in this report "
            "support patch prioritization."
        ),
        guidance=(
            "Patch timing (change records) is operational evidence held by "
            "the customer; use the findings in this section to prioritize "
            "patching and verify remediation with follow-up scans."
        ),
        scanners=("sca", "sast", "kics"),
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
        requirement="6.4.3",
        title="Payment-page scripts managed",
        text=(
            "All payment-page scripts loaded and executed in the consumer's "
            "browser are authorized, maintained in an inventory, and "
            "protected by integrity and change-detection controls "
            "(digital-skimming defense)."
        ),
        guidance=(
            "Maintain a script inventory with authorization and integrity "
            "monitoring (e.g. SRI, CSP, tamper detection) for payment pages."
        ),
        scanners=(),
        covered=False,
        note=(
            "Requires browser-side monitoring of live payment pages; not "
            "evidenced by source, API or container scanning."
        ),
        owner="Customer / QSA",
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
        title="External vulnerability scans (ASV)",
        text=(
            "External vulnerability scans are performed at least quarterly "
            "and after significant change by a PCI SSC Approved Scanning "
            "Vendor (ASV). External-facing assets must be free of "
            "exploitable high-risk and critical issues."
        ),
        guidance=(
            "Engage a PCI SSC Approved Scanning Vendor (ASV) for quarterly "
            "external scans; remediate until the scan passes."
        ),
        scanners=(),
        covered=False,
        note=(
            "External scans must be performed by a PCI SSC Approved "
            "Scanning Vendor (ASV); vendor scan tools are not an ASV "
            "substitute."
        ),
        owner="PCI SSC ASV (Customer)",
    ),
    PciRequirement(
        requirement="11.3.3",
        title="Penetration testing",
        text=(
            "Penetration testing of the cardholder data environment is "
            "performed annually and after significant changes by a "
            "qualified resource, internal or external, independent of the "
            "development and operations teams."
        ),
        guidance=(
            "Engage a qualified independent tester for annual and "
            "post-change penetration tests of the CDE."
        ),
        scanners=(),
        covered=False,
        note=(
            "Penetration testing must be performed by a qualified party "
            "independent of development and operations; outside the scope "
            "of this application security assessment."
        ),
        owner="Customer (independent tester)",
    ),
)

REQUIREMENT_BY_ID: dict[str, PciRequirement] = {
    req.requirement: req for req in PCI_REQUIREMENTS
}
