"""HIPAA Security Rule safeguards framework."""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class HIPAASafeguard:
    """HIPAA safeguard definition."""

    id: str
    category: str
    title: str
    standard: str
    description: str
    implementation_specs: List[str] = field(default_factory=list)
    required: bool = True


HIPAA_SAFEGUARDS: Dict[str, HIPAASafeguard] = {
    # Administrative Safeguards
    "164.308(a)(1)": HIPAASafeguard(
        id="164.308(a)(1)",
        category="Administrative",
        title="Security Management Process",
        standard="Implement policies to prevent, detect, contain, and correct security violations.",
        description="Risk analysis and risk management policies and procedures.",
        implementation_specs=[
            "Risk analysis (Required)",
            "Risk management (Required)",
            "Sanction policy (Required)",
            "Information system activity review (Required)",
        ],
    ),
    "164.308(a)(3)": HIPAASafeguard(
        id="164.308(a)(3)",
        category="Administrative",
        title="Workforce Security",
        standard="Implement policies to ensure appropriate access to ePHI.",
        description="Procedures for authorization and supervision of workforce members.",
        implementation_specs=[
            "Authorization/supervision (Addressable)",
            "Workforce clearance procedure (Addressable)",
            "Termination procedures (Addressable)",
        ],
        required=False,
    ),
    "164.308(a)(4)": HIPAASafeguard(
        id="164.308(a)(4)",
        category="Administrative",
        title="Information Access Management",
        standard="Implement policies for authorizing access to ePHI.",
        description="Policies and procedures for granting access to ePHI.",
        implementation_specs=[
            "Isolating health care clearinghouse functions (Required)",
            "Access authorization (Addressable)",
            "Access establishment and modification (Addressable)",
        ],
    ),
    "164.308(a)(5)": HIPAASafeguard(
        id="164.308(a)(5)",
        category="Administrative",
        title="Security Awareness and Training",
        standard="Implement security awareness and training program.",
        description="Training for workforce on policies and procedures.",
        implementation_specs=[
            "Security reminders (Addressable)",
            "Protection from malicious software (Addressable)",
            "Log-in monitoring (Addressable)",
            "Password management (Addressable)",
        ],
        required=False,
    ),
    # Physical Safeguards
    "164.310(a)(1)": HIPAASafeguard(
        id="164.310(a)(1)",
        category="Physical",
        title="Facility Access Controls",
        standard="Implement policies to limit physical access.",
        description="Procedures to safeguard facility and equipment from unauthorized access.",
        implementation_specs=[
            "Contingency operations (Addressable)",
            "Facility security plan (Addressable)",
            "Access control and validation procedures (Addressable)",
            "Maintenance records (Addressable)",
        ],
        required=False,
    ),
    "164.310(b)": HIPAASafeguard(
        id="164.310(b)",
        category="Physical",
        title="Workstation Use",
        standard="Implement policies for proper workstation use.",
        description="Specify proper functions and manner of performing functions.",
        implementation_specs=[
            "Workstation use policies (Required)",
        ],
    ),
    "164.310(c)": HIPAASafeguard(
        id="164.310(c)",
        category="Physical",
        title="Workstation Security",
        standard="Implement physical safeguards for workstations.",
        description="Physical safeguards restricting access to authorized users.",
        implementation_specs=[
            "Workstation physical safeguards (Required)",
        ],
    ),
    "164.310(d)(1)": HIPAASafeguard(
        id="164.310(d)(1)",
        category="Physical",
        title="Device and Media Controls",
        standard="Implement policies governing hardware and electronic media.",
        description="Procedures for disposal and reuse of electronic media.",
        implementation_specs=[
            "Disposal (Required)",
            "Media re-use (Required)",
            "Accountability (Addressable)",
            "Data backup and storage (Addressable)",
        ],
    ),
    # Technical Safeguards
    "164.312(a)(1)": HIPAASafeguard(
        id="164.312(a)(1)",
        category="Technical",
        title="Access Control",
        standard="Implement technical policies for access control.",
        description="Allow access only to authorized persons or software programs.",
        implementation_specs=[
            "Unique user identification (Required)",
            "Emergency access procedure (Required)",
            "Automatic logoff (Addressable)",
            "Encryption and decryption (Addressable)",
        ],
    ),
    "164.312(b)": HIPAASafeguard(
        id="164.312(b)",
        category="Technical",
        title="Audit Controls",
        standard="Implement hardware and software audit controls.",
        description="Mechanisms that record and examine activity in information systems.",
        implementation_specs=[
            "Audit controls (Required)",
        ],
    ),
    "164.312(c)(1)": HIPAASafeguard(
        id="164.312(c)(1)",
        category="Technical",
        title="Integrity",
        standard="Implement policies to protect ePHI from improper alteration.",
        description="Mechanisms to authenticate ePHI and detect unauthorized changes.",
        implementation_specs=[
            "Mechanism to authenticate ePHI (Addressable)",
        ],
        required=False,
    ),
    "164.312(d)": HIPAASafeguard(
        id="164.312(d)",
        category="Technical",
        title="Person or Entity Authentication",
        standard="Implement procedures to verify identity.",
        description="Verify person or entity seeking access is who they claim to be.",
        implementation_specs=[
            "Person or entity authentication (Required)",
        ],
    ),
    "164.312(e)(1)": HIPAASafeguard(
        id="164.312(e)(1)",
        category="Technical",
        title="Transmission Security",
        standard="Implement technical security measures for ePHI transmission.",
        description="Guard against unauthorized access during transmission.",
        implementation_specs=[
            "Integrity controls (Addressable)",
            "Encryption (Addressable)",
        ],
        required=False,
    ),
}


def get_safeguard(safeguard_id: str) -> HIPAASafeguard:
    """Get HIPAA safeguard by ID."""
    return HIPAA_SAFEGUARDS.get(safeguard_id)


def get_safeguards_by_category(category: str) -> List[HIPAASafeguard]:
    """Get HIPAA safeguards by category."""
    return [s for s in HIPAA_SAFEGUARDS.values() if s.category == category]


def get_required_safeguards() -> List[HIPAASafeguard]:
    """Get all required HIPAA safeguards."""
    return [s for s in HIPAA_SAFEGUARDS.values() if s.required]


def get_all_safeguards() -> List[HIPAASafeguard]:
    """Get all HIPAA safeguards."""
    return list(HIPAA_SAFEGUARDS.values())
