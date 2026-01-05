"""SOC2 Trust Services Criteria compliance framework."""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class SOC2Control:
    """SOC2 control definition."""

    id: str
    category: str
    title: str
    description: str
    criteria: List[str] = field(default_factory=list)


SOC2_CONTROLS: Dict[str, SOC2Control] = {
    # Security
    "CC6.1": SOC2Control(
        id="CC6.1",
        category="Security",
        title="Logical and Physical Access Controls",
        description="The entity implements logical access security measures to protect against threats.",
        criteria=[
            "Access to systems is restricted to authorized users",
            "Authentication mechanisms are in place",
            "Access reviews are performed regularly",
        ],
    ),
    "CC6.2": SOC2Control(
        id="CC6.2",
        category="Security",
        title="System Account Management",
        description="Prior to issuing system credentials, registered users are identified and authenticated.",
        criteria=[
            "User registration process exists",
            "Identity verification is performed",
            "Credentials are securely provisioned",
        ],
    ),
    "CC6.3": SOC2Control(
        id="CC6.3",
        category="Security",
        title="Authorization and Access Removal",
        description="Access to protected information is authorized and removed when no longer required.",
        criteria=[
            "Authorization process is documented",
            "Access removal process exists",
            "Timely deprovisioning occurs",
        ],
    ),
    "CC6.6": SOC2Control(
        id="CC6.6",
        category="Security",
        title="Boundary Protection",
        description="The entity implements controls to prevent unauthorized access through system boundaries.",
        criteria=[
            "Network segmentation is implemented",
            "Firewall rules are configured",
            "Intrusion detection is in place",
        ],
    ),
    "CC6.7": SOC2Control(
        id="CC6.7",
        category="Security",
        title="Transmission Protection",
        description="Data transmitted outside the system is protected.",
        criteria=[
            "Encryption in transit is implemented",
            "TLS is used for communications",
            "Certificate management exists",
        ],
    ),
    "CC6.8": SOC2Control(
        id="CC6.8",
        category="Security",
        title="Malware Prevention",
        description="The entity implements controls to prevent malicious software.",
        criteria=[
            "Antimalware solutions are deployed",
            "Software is scanned before deployment",
            "Security updates are applied",
        ],
    ),
    # Availability
    "A1.1": SOC2Control(
        id="A1.1",
        category="Availability",
        title="Capacity Planning",
        description="Current processing capacity is maintained to meet availability commitments.",
        criteria=[
            "Capacity monitoring is in place",
            "Scaling mechanisms exist",
            "Performance thresholds are defined",
        ],
    ),
    "A1.2": SOC2Control(
        id="A1.2",
        category="Availability",
        title="Environmental Protections",
        description="Environmental protections and monitoring are implemented.",
        criteria=[
            "Data center protections exist",
            "Environmental monitoring is active",
            "Redundancy is implemented",
        ],
    ),
    # Confidentiality
    "C1.1": SOC2Control(
        id="C1.1",
        category="Confidentiality",
        title="Confidential Information Identification",
        description="Confidential information is identified and classified.",
        criteria=[
            "Data classification scheme exists",
            "Confidential data is labeled",
            "Handling procedures are documented",
        ],
    ),
    "C1.2": SOC2Control(
        id="C1.2",
        category="Confidentiality",
        title="Confidential Information Protection",
        description="Confidential information is protected during processing, storage, and transmission.",
        criteria=[
            "Encryption at rest is implemented",
            "Encryption in transit is implemented",
            "Access controls are applied",
        ],
    ),
    # Processing Integrity
    "PI1.1": SOC2Control(
        id="PI1.1",
        category="Processing Integrity",
        title="Processing Accuracy",
        description="System processing is complete, accurate, and authorized.",
        criteria=[
            "Input validation is implemented",
            "Processing controls exist",
            "Output verification occurs",
        ],
    ),
    # Privacy
    "P1.1": SOC2Control(
        id="P1.1",
        category="Privacy",
        title="Privacy Notice",
        description="The entity provides notice about privacy practices.",
        criteria=[
            "Privacy policy is published",
            "Collection purposes are disclosed",
            "User rights are communicated",
        ],
    ),
    "P4.1": SOC2Control(
        id="P4.1",
        category="Privacy",
        title="Personal Information Collection",
        description="Personal information is collected consistent with privacy commitments.",
        criteria=[
            "Consent is obtained",
            "Collection is limited to stated purposes",
            "Data minimization is practiced",
        ],
    ),
}


def get_control(control_id: str) -> SOC2Control:
    """Get SOC2 control by ID."""
    return SOC2_CONTROLS.get(control_id)


def get_controls_by_category(category: str) -> List[SOC2Control]:
    """Get SOC2 controls by category."""
    return [c for c in SOC2_CONTROLS.values() if c.category == category]


def get_all_controls() -> List[SOC2Control]:
    """Get all SOC2 controls."""
    return list(SOC2_CONTROLS.values())
