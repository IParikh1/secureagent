"""PCI-DSS compliance framework."""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class PCIDSSRequirement:
    """PCI-DSS requirement definition."""

    id: str
    title: str
    description: str
    sub_requirements: List[str] = field(default_factory=list)


PCI_DSS_REQUIREMENTS: Dict[str, PCIDSSRequirement] = {
    "1": PCIDSSRequirement(
        id="1",
        title="Install and Maintain Network Security Controls",
        description="Network security controls (NSCs) are network functions that restrict traffic.",
        sub_requirements=[
            "1.1 Processes for installing and maintaining NSCs are defined",
            "1.2 NSCs are configured and maintained",
            "1.3 Network access to and from cardholder data environment is restricted",
            "1.4 Network connections between trusted and untrusted networks are controlled",
        ],
    ),
    "2": PCIDSSRequirement(
        id="2",
        title="Apply Secure Configurations",
        description="Vendor defaults and other security parameters must be changed.",
        sub_requirements=[
            "2.1 Secure configuration processes are defined",
            "2.2 System components are configured and managed securely",
            "2.3 Wireless environments are configured and managed securely",
        ],
    ),
    "3": PCIDSSRequirement(
        id="3",
        title="Protect Stored Account Data",
        description="Protection methods such as encryption, masking, and hashing are critical.",
        sub_requirements=[
            "3.1 Processes to protect stored account data are defined",
            "3.2 Storage of account data is kept to a minimum",
            "3.3 Sensitive authentication data is not stored after authorization",
            "3.4 Access to displays of full PAN and copying is restricted",
            "3.5 PAN is secured wherever it is stored",
        ],
    ),
    "4": PCIDSSRequirement(
        id="4",
        title="Protect Cardholder Data in Transit",
        description="Sensitive cardholder data is encrypted during transmission over networks.",
        sub_requirements=[
            "4.1 Processes to protect CHD with strong cryptography during transmission",
            "4.2 PAN is secured with strong cryptography during transmission",
        ],
    ),
    "5": PCIDSSRequirement(
        id="5",
        title="Protect Systems Against Malware",
        description="Malware protection mechanisms are deployed and maintained.",
        sub_requirements=[
            "5.1 Processes for protecting systems against malware are defined",
            "5.2 Malware is prevented, detected, and addressed",
            "5.3 Anti-phishing mechanisms protect users",
        ],
    ),
    "6": PCIDSSRequirement(
        id="6",
        title="Develop Secure Systems and Software",
        description="Security is considered throughout software development lifecycle.",
        sub_requirements=[
            "6.1 Secure development processes are defined",
            "6.2 Bespoke software is developed securely",
            "6.3 Security vulnerabilities are identified and addressed",
            "6.4 Public-facing web applications are protected",
            "6.5 Changes to code are managed securely",
        ],
    ),
    "7": PCIDSSRequirement(
        id="7",
        title="Restrict Access by Business Need",
        description="Access to cardholder data is restricted by business need to know.",
        sub_requirements=[
            "7.1 Processes to restrict access to CHD are defined",
            "7.2 Access to system components and data is appropriately defined",
            "7.3 Access to systems is managed via access control systems",
        ],
    ),
    "8": PCIDSSRequirement(
        id="8",
        title="Identify Users and Authenticate Access",
        description="Each user has unique identification and access is authenticated.",
        sub_requirements=[
            "8.1 Processes for user identification and authentication are defined",
            "8.2 User identification and accounts are managed",
            "8.3 Strong authentication for users and administrators",
            "8.4 MFA is implemented for access into the CDE",
            "8.5 MFA systems are configured to prevent misuse",
            "8.6 Use of application and system accounts is managed",
        ],
    ),
    "9": PCIDSSRequirement(
        id="9",
        title="Restrict Physical Access",
        description="Physical access to cardholder data is restricted.",
        sub_requirements=[
            "9.1 Processes to restrict physical access are defined",
            "9.2 Physical access controls manage entry into facilities",
            "9.3 Physical access for personnel and visitors is authorized",
            "9.4 Media with cardholder data is securely stored, accessed, distributed, and destroyed",
            "9.5 POI devices are protected from tampering and substitution",
        ],
    ),
    "10": PCIDSSRequirement(
        id="10",
        title="Log and Monitor Access",
        description="Logging mechanisms and ability to track user activities are implemented.",
        sub_requirements=[
            "10.1 Processes for logging and monitoring access are defined",
            "10.2 Audit logs are implemented to support detection",
            "10.3 Audit logs are protected from destruction and modification",
            "10.4 Audit logs are reviewed to identify anomalies",
            "10.5 Audit log history is retained and available for analysis",
            "10.6 Time-synchronization mechanisms support consistent time",
            "10.7 Failures of security control systems are detected and addressed",
        ],
    ),
    "11": PCIDSSRequirement(
        id="11",
        title="Test Security Regularly",
        description="System components and software are tested frequently.",
        sub_requirements=[
            "11.1 Processes for regular testing of security are defined",
            "11.2 Wireless access points are identified and monitored",
            "11.3 External and internal vulnerabilities are identified and addressed",
            "11.4 External and internal penetration testing is performed",
            "11.5 Network intrusions and unexpected file changes are detected",
            "11.6 Unauthorized changes on payment pages are detected",
        ],
    ),
    "12": PCIDSSRequirement(
        id="12",
        title="Support Information Security",
        description="Organization's information security policy supports personnel and processes.",
        sub_requirements=[
            "12.1 A comprehensive information security policy is established",
            "12.2 Acceptable use policies are implemented",
            "12.3 Risks to the cardholder data environment are identified and managed",
            "12.4 PCI DSS compliance is managed",
            "12.5 PCI DSS scope is documented and validated",
            "12.6 Security awareness education is ongoing",
            "12.7 Personnel are screened to reduce risks",
            "12.8 Third-party service providers are managed",
            "12.9 TPSPs acknowledge responsibility for CHD security",
            "12.10 Suspected and confirmed incidents are responded to immediately",
        ],
    ),
}


def get_requirement(req_id: str) -> PCIDSSRequirement:
    """Get PCI-DSS requirement by ID."""
    return PCI_DSS_REQUIREMENTS.get(req_id)


def get_all_requirements() -> List[PCIDSSRequirement]:
    """Get all PCI-DSS requirements."""
    return list(PCI_DSS_REQUIREMENTS.values())
