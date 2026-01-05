"""Finding-to-compliance-control mapper."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum

from ..core.models.finding import Finding
from ..core.models.severity import Severity
from .frameworks.owasp_llm import OWASP_LLM_TOP_10, OWASPControl
from .frameworks.owasp_mcp import OWASP_MCP_TOP_10, MCPControl
from .frameworks.soc2 import SOC2_CONTROLS, SOC2Control
from .frameworks.pci_dss import PCI_DSS_REQUIREMENTS, PCIDSSRequirement
from .frameworks.hipaa import HIPAA_SAFEGUARDS, HIPAASafeguard


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""

    OWASP_LLM = "owasp_llm"
    OWASP_MCP = "owasp_mcp"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"


@dataclass
class ComplianceMapping:
    """Mapping between a finding and compliance controls."""

    finding: Finding
    framework: ComplianceFramework
    control_ids: List[str]
    control_titles: List[str]
    compliance_status: str  # "violation", "warning", "compliant"
    notes: str = ""


@dataclass
class ComplianceStatus:
    """Overall compliance status for a framework."""

    framework: ComplianceFramework
    total_controls: int
    controls_assessed: int
    controls_passing: int
    controls_failing: int
    controls_warning: int
    compliance_percentage: float
    findings_by_control: Dict[str, List[Finding]] = field(default_factory=dict)


# Rule ID to OWASP LLM Top 10 mappings
OWASP_LLM_MAPPINGS: Dict[str, List[str]] = {
    # MCP rules
    "MCP-001": ["LLM06"],  # Hardcoded credentials -> Sensitive Info Disclosure
    "MCP-002": ["LLM01", "LLM02"],  # Command injection -> Prompt Injection, Insecure Output
    "MCP-003": ["LLM02"],  # Path traversal -> Insecure Output Handling
    "MCP-004": ["LLM02"],  # SSRF -> Insecure Output Handling
    "MCP-005": ["LLM06"],  # Sensitive env vars -> Sensitive Info Disclosure
    "MCP-006": ["LLM08"],  # No auth -> Excessive Agency
    "MCP-007": ["LLM07", "LLM08"],  # Insecure permissions -> Insecure Plugin, Excessive Agency
    # LangChain rules
    "LC-001": ["LLM06"],  # Hardcoded API keys -> Sensitive Info Disclosure
    "LC-002": ["LLM07", "LLM08"],  # Dangerous tools -> Insecure Plugin, Excessive Agency
    "LC-003": ["LLM01"],  # Prompt injection -> Prompt Injection
    "LC-004": ["LLM06"],  # Unprotected memory -> Sensitive Info Disclosure
    "LC-005": ["LLM08"],  # Unlimited iterations -> Excessive Agency
    "LC-006": ["LLM02", "LLM07"],  # Python execution -> Insecure Output, Insecure Plugin
    "LC-007": ["LLM02"],  # SQL injection -> Insecure Output Handling
    "LC-008": ["LLM06"],  # Verbose mode -> Sensitive Info Disclosure
    "LC-009": ["LLM05"],  # Unverified model -> Supply Chain
    "LC-010": ["LLM08"],  # Unrestricted callbacks -> Excessive Agency
    # OpenAI rules
    "OAI-001": ["LLM06"],  # Hardcoded API keys -> Sensitive Info Disclosure
    "OAI-002": ["LLM07", "LLM08"],  # Code interpreter -> Insecure Plugin, Excessive Agency
    "OAI-003": ["LLM06"],  # File search -> Sensitive Info Disclosure
    "OAI-004": ["LLM07"],  # Function calling -> Insecure Plugin Design
    "OAI-005": ["LLM02", "LLM07"],  # Dangerous functions -> Insecure Output, Insecure Plugin
    "OAI-006": ["LLM01"],  # Missing instructions -> Prompt Injection
    "OAI-007": ["LLM04"],  # Unlimited tokens -> Model DoS
    "OAI-008": ["LLM06"],  # Verbose mode -> Sensitive Info Disclosure
    # AutoGPT rules
    "AG-001": ["LLM06"],  # Hardcoded secrets -> Sensitive Info Disclosure
    "AG-002": ["LLM08"],  # High autonomy -> Excessive Agency
    "AG-003": ["LLM07", "LLM08"],  # Dangerous tools -> Insecure Plugin, Excessive Agency
    "AG-004": ["LLM08"],  # Inter-agent trust -> Excessive Agency
    "AG-005": ["LLM06"],  # Unprotected memory -> Sensitive Info Disclosure
    "AG-006": ["LLM08"],  # Unlimited delegation -> Excessive Agency
    "AG-007": ["LLM02"],  # Unrestricted web -> Insecure Output Handling
    "AG-008": ["LLM06"],  # Verbose mode -> Sensitive Info Disclosure
    "AG-009": ["LLM04", "LLM08"],  # Unlimited iterations -> Model DoS, Excessive Agency
    "AG-010": ["LLM08"],  # Execution mode -> Excessive Agency
    # AWS rules
    "AWS-S3-001": ["LLM06"],  # Public bucket -> Sensitive Info Disclosure
    "AWS-S3-002": ["LLM06"],  # No encryption -> Sensitive Info Disclosure
    "AWS-S3-003": ["LLM06"],  # No versioning -> Sensitive Info Disclosure
    "AWS-IAM-001": ["LLM08"],  # Admin policy -> Excessive Agency
    "AWS-IAM-002": ["LLM08"],  # Wildcard actions -> Excessive Agency
    "AWS-SG-001": ["LLM02"],  # Open SSH -> Insecure Output Handling
    "AWS-SG-002": ["LLM02"],  # Open RDP -> Insecure Output Handling
    "AWS-SG-003": ["LLM02"],  # All traffic ingress -> Insecure Output Handling
    # Terraform rules
    "TF-SG-001": ["LLM02"],  # Open SSH
    "TF-SG-002": ["LLM02"],  # Open RDP
    "TF-SG-003": ["LLM02"],  # All traffic ingress
    "TF-S3-001": ["LLM06"],  # Public ACL
    "TF-S3-002": ["LLM06"],  # No encryption
    "TF-RDS-001": ["LLM06"],  # Public RDS
    "TF-RDS-002": ["LLM06"],  # No encryption
    "TF-RDS-003": ["LLM06"],  # No deletion protection
    "TF-EC2-001": ["LLM06"],  # Public IP
    "TF-EC2-002": ["LLM06"],  # No IMDSv2
    "TF-EC2-003": ["LLM06"],  # Unencrypted volumes
}

# Rule ID to OWASP MCP Top 10 mappings
OWASP_MCP_MAPPINGS: Dict[str, List[str]] = {
    "MCP-001": ["MCP03"],  # Hardcoded credentials -> Credential Exposure
    "MCP-002": ["MCP04"],  # Command injection -> Command Injection
    "MCP-003": ["MCP07"],  # Path traversal -> Path Traversal
    "MCP-004": ["MCP09"],  # SSRF -> SSRF via MCP
    "MCP-005": ["MCP03"],  # Sensitive env vars -> Credential Exposure
    "MCP-006": ["MCP05"],  # No auth -> Insufficient Access Control
    "MCP-007": ["MCP08"],  # Insecure permissions -> Overprivileged Tools
}

# Rule ID to SOC2 mappings
SOC2_MAPPINGS: Dict[str, List[str]] = {
    # Credential exposure maps to access controls
    "MCP-001": ["CC6.1", "CC6.2"],
    "LC-001": ["CC6.1", "CC6.2"],
    "OAI-001": ["CC6.1", "CC6.2"],
    "AG-001": ["CC6.1", "CC6.2"],
    # Dangerous tools/execution maps to boundary protection
    "MCP-002": ["CC6.6"],
    "LC-002": ["CC6.6", "CC6.8"],
    "LC-006": ["CC6.6", "CC6.8"],
    "OAI-002": ["CC6.6", "CC6.8"],
    "OAI-005": ["CC6.6", "CC6.8"],
    "AG-003": ["CC6.6", "CC6.8"],
    # Network/SSRF issues map to boundary protection and transmission
    "MCP-004": ["CC6.6", "CC6.7"],
    "AG-007": ["CC6.6", "CC6.7"],
    # Auth issues map to access management
    "MCP-006": ["CC6.1", "CC6.2", "CC6.3"],
    "MCP-007": ["CC6.1", "CC6.3"],
    # Cloud security
    "AWS-S3-001": ["CC6.1", "C1.2"],
    "AWS-S3-002": ["C1.2"],
    "AWS-IAM-001": ["CC6.1", "CC6.3"],
    "AWS-IAM-002": ["CC6.1", "CC6.3"],
    "AWS-SG-001": ["CC6.6"],
    "AWS-SG-002": ["CC6.6"],
    "AWS-SG-003": ["CC6.6"],
}

# Rule ID to PCI-DSS mappings
PCI_DSS_MAPPINGS: Dict[str, List[str]] = {
    # Credential protection
    "MCP-001": ["3", "8"],
    "LC-001": ["3", "8"],
    "OAI-001": ["3", "8"],
    "AG-001": ["3", "8"],
    # Secure development
    "MCP-002": ["6"],
    "LC-006": ["6"],
    "LC-007": ["6"],
    "OAI-005": ["6"],
    # Network security
    "MCP-004": ["1"],
    "AWS-SG-001": ["1"],
    "AWS-SG-002": ["1"],
    "AWS-SG-003": ["1"],
    "TF-SG-001": ["1"],
    "TF-SG-002": ["1"],
    "TF-SG-003": ["1"],
    # Access control
    "MCP-006": ["7", "8"],
    "MCP-007": ["7"],
    "AWS-IAM-001": ["7"],
    "AWS-IAM-002": ["7"],
    # Data protection
    "AWS-S3-001": ["3", "9"],
    "AWS-S3-002": ["3", "4"],
    "TF-S3-002": ["3", "4"],
    "TF-RDS-002": ["3", "4"],
}

# Rule ID to HIPAA mappings
HIPAA_MAPPINGS: Dict[str, List[str]] = {
    # Access controls
    "MCP-006": ["164.312(a)(1)", "164.312(d)"],
    "MCP-007": ["164.312(a)(1)"],
    "AWS-IAM-001": ["164.312(a)(1)"],
    "AWS-IAM-002": ["164.312(a)(1)"],
    # Audit controls
    "LC-008": ["164.312(b)"],
    "OAI-008": ["164.312(b)"],
    "AG-008": ["164.312(b)"],
    # Transmission security
    "MCP-004": ["164.312(e)(1)"],
    "AG-007": ["164.312(e)(1)"],
    # Data integrity
    "LC-007": ["164.312(c)(1)"],
    # Device and media controls
    "AWS-S3-001": ["164.310(d)(1)"],
    "AWS-S3-002": ["164.310(d)(1)"],
}


class ComplianceMapper:
    """Maps findings to compliance framework controls."""

    def __init__(self):
        """Initialize compliance mapper."""
        self.owasp_llm_mappings = OWASP_LLM_MAPPINGS
        self.owasp_mcp_mappings = OWASP_MCP_MAPPINGS
        self.soc2_mappings = SOC2_MAPPINGS
        self.pci_dss_mappings = PCI_DSS_MAPPINGS
        self.hipaa_mappings = HIPAA_MAPPINGS

    def map_finding(
        self, finding: Finding, framework: ComplianceFramework
    ) -> Optional[ComplianceMapping]:
        """Map a finding to compliance controls."""
        rule_id = finding.rule_id

        if framework == ComplianceFramework.OWASP_LLM:
            return self._map_to_owasp_llm(finding, rule_id)
        elif framework == ComplianceFramework.OWASP_MCP:
            return self._map_to_owasp_mcp(finding, rule_id)
        elif framework == ComplianceFramework.SOC2:
            return self._map_to_soc2(finding, rule_id)
        elif framework == ComplianceFramework.PCI_DSS:
            return self._map_to_pci_dss(finding, rule_id)
        elif framework == ComplianceFramework.HIPAA:
            return self._map_to_hipaa(finding, rule_id)

        return None

    def _map_to_owasp_llm(
        self, finding: Finding, rule_id: str
    ) -> Optional[ComplianceMapping]:
        """Map finding to OWASP LLM Top 10."""
        control_ids = self.owasp_llm_mappings.get(rule_id, [])
        if not control_ids:
            # Try CWE-based mapping
            if finding.cwe_id:
                control_ids = self._map_cwe_to_owasp_llm(finding.cwe_id)

        if not control_ids:
            return None

        control_titles = []
        for cid in control_ids:
            control = OWASP_LLM_TOP_10.get(cid)
            if control:
                control_titles.append(control.title)

        return ComplianceMapping(
            finding=finding,
            framework=ComplianceFramework.OWASP_LLM,
            control_ids=control_ids,
            control_titles=control_titles,
            compliance_status=self._severity_to_status(finding.severity),
        )

    def _map_to_owasp_mcp(
        self, finding: Finding, rule_id: str
    ) -> Optional[ComplianceMapping]:
        """Map finding to OWASP MCP Top 10."""
        control_ids = self.owasp_mcp_mappings.get(rule_id, [])
        if not control_ids:
            return None

        control_titles = []
        for cid in control_ids:
            control = OWASP_MCP_TOP_10.get(cid)
            if control:
                control_titles.append(control.title)

        return ComplianceMapping(
            finding=finding,
            framework=ComplianceFramework.OWASP_MCP,
            control_ids=control_ids,
            control_titles=control_titles,
            compliance_status=self._severity_to_status(finding.severity),
        )

    def _map_to_soc2(
        self, finding: Finding, rule_id: str
    ) -> Optional[ComplianceMapping]:
        """Map finding to SOC2 controls."""
        control_ids = self.soc2_mappings.get(rule_id, [])
        if not control_ids:
            return None

        control_titles = []
        for cid in control_ids:
            control = SOC2_CONTROLS.get(cid)
            if control:
                control_titles.append(control.title)

        return ComplianceMapping(
            finding=finding,
            framework=ComplianceFramework.SOC2,
            control_ids=control_ids,
            control_titles=control_titles,
            compliance_status=self._severity_to_status(finding.severity),
        )

    def _map_to_pci_dss(
        self, finding: Finding, rule_id: str
    ) -> Optional[ComplianceMapping]:
        """Map finding to PCI-DSS requirements."""
        control_ids = self.pci_dss_mappings.get(rule_id, [])
        if not control_ids:
            return None

        control_titles = []
        for cid in control_ids:
            req = PCI_DSS_REQUIREMENTS.get(cid)
            if req:
                control_titles.append(req.title)

        return ComplianceMapping(
            finding=finding,
            framework=ComplianceFramework.PCI_DSS,
            control_ids=control_ids,
            control_titles=control_titles,
            compliance_status=self._severity_to_status(finding.severity),
        )

    def _map_to_hipaa(
        self, finding: Finding, rule_id: str
    ) -> Optional[ComplianceMapping]:
        """Map finding to HIPAA safeguards."""
        control_ids = self.hipaa_mappings.get(rule_id, [])
        if not control_ids:
            return None

        control_titles = []
        for cid in control_ids:
            safeguard = HIPAA_SAFEGUARDS.get(cid)
            if safeguard:
                control_titles.append(safeguard.title)

        return ComplianceMapping(
            finding=finding,
            framework=ComplianceFramework.HIPAA,
            control_ids=control_ids,
            control_titles=control_titles,
            compliance_status=self._severity_to_status(finding.severity),
        )

    def _map_cwe_to_owasp_llm(self, cwe_id: str) -> List[str]:
        """Map CWE ID to OWASP LLM controls."""
        cwe_mappings = {
            "CWE-74": ["LLM01"],  # Injection
            "CWE-20": ["LLM01", "LLM03"],  # Input validation
            "CWE-79": ["LLM02"],  # XSS
            "CWE-918": ["LLM02"],  # SSRF
            "CWE-94": ["LLM02"],  # Code injection
            "CWE-502": ["LLM03"],  # Deserialization
            "CWE-400": ["LLM04"],  # Resource exhaustion
            "CWE-770": ["LLM04"],  # Allocation without limits
            "CWE-829": ["LLM05"],  # Untrusted functionality
            "CWE-494": ["LLM05"],  # Download without integrity check
            "CWE-200": ["LLM06"],  # Information exposure
            "CWE-212": ["LLM06"],  # Improper cross-boundary removal
            "CWE-250": ["LLM07", "LLM08"],  # Excessive privilege
            "CWE-732": ["LLM07"],  # Incorrect permission
            "CWE-284": ["LLM08", "LLM10"],  # Improper access control
            "CWE-1188": ["LLM09"],  # Insecure default initialization
            "CWE-522": ["LLM10"],  # Insufficiently protected credentials
        }
        return cwe_mappings.get(cwe_id, [])

    def _severity_to_status(self, severity: Severity) -> str:
        """Convert severity to compliance status."""
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return "violation"
        elif severity == Severity.MEDIUM:
            return "warning"
        else:
            return "observation"

    def get_compliance_status(
        self, findings: List[Finding], framework: ComplianceFramework
    ) -> ComplianceStatus:
        """Get overall compliance status for a framework."""
        # Get total controls for framework
        if framework == ComplianceFramework.OWASP_LLM:
            total_controls = len(OWASP_LLM_TOP_10)
        elif framework == ComplianceFramework.OWASP_MCP:
            total_controls = len(OWASP_MCP_TOP_10)
        elif framework == ComplianceFramework.SOC2:
            total_controls = len(SOC2_CONTROLS)
        elif framework == ComplianceFramework.PCI_DSS:
            total_controls = len(PCI_DSS_REQUIREMENTS)
        elif framework == ComplianceFramework.HIPAA:
            total_controls = len(HIPAA_SAFEGUARDS)
        else:
            total_controls = 0

        # Map findings to controls
        findings_by_control: Dict[str, List[Finding]] = {}
        controls_assessed: Set[str] = set()

        for finding in findings:
            mapping = self.map_finding(finding, framework)
            if mapping:
                for control_id in mapping.control_ids:
                    controls_assessed.add(control_id)
                    if control_id not in findings_by_control:
                        findings_by_control[control_id] = []
                    findings_by_control[control_id].append(finding)

        # Calculate status counts
        controls_failing = 0
        controls_warning = 0
        controls_passing = len(controls_assessed)

        for control_id, control_findings in findings_by_control.items():
            has_violation = any(
                f.severity in (Severity.CRITICAL, Severity.HIGH)
                for f in control_findings
            )
            has_warning = any(f.severity == Severity.MEDIUM for f in control_findings)

            if has_violation:
                controls_failing += 1
                controls_passing -= 1
            elif has_warning:
                controls_warning += 1

        # Calculate compliance percentage
        if len(controls_assessed) > 0:
            compliance_percentage = (controls_passing / len(controls_assessed)) * 100
        else:
            compliance_percentage = 100.0

        return ComplianceStatus(
            framework=framework,
            total_controls=total_controls,
            controls_assessed=len(controls_assessed),
            controls_passing=controls_passing,
            controls_failing=controls_failing,
            controls_warning=controls_warning,
            compliance_percentage=compliance_percentage,
            findings_by_control=findings_by_control,
        )

    def get_all_mappings(
        self, findings: List[Finding]
    ) -> Dict[ComplianceFramework, List[ComplianceMapping]]:
        """Get mappings for all frameworks."""
        result: Dict[ComplianceFramework, List[ComplianceMapping]] = {}

        for framework in ComplianceFramework:
            mappings = []
            for finding in findings:
                mapping = self.map_finding(finding, framework)
                if mapping:
                    mappings.append(mapping)
            if mappings:
                result[framework] = mappings

        return result
