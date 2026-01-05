# Compliance Mapping Guide

SecureAgent maps security findings to industry compliance frameworks, helping you understand regulatory implications and prepare for audits.

---

## Table of Contents

1. [Overview](#overview)
2. [Supported Frameworks](#supported-frameworks)
3. [OWASP LLM Top 10](#owasp-llm-top-10)
4. [OWASP MCP Top 10](#owasp-mcp-top-10)
5. [SOC 2](#soc-2)
6. [PCI-DSS](#pci-dss)
7. [HIPAA](#hipaa)
8. [Using Compliance Reports](#using-compliance-reports)

---

## Overview

### How Compliance Mapping Works

```mermaid
flowchart LR
    subgraph "Security Scan"
        FINDING[Security Finding]
    end

    subgraph "Mapping"
        MAPPER[Compliance Mapper]
        RULES[Mapping Rules]
    end

    subgraph "Output"
        OWASP[OWASP Controls]
        SOC2[SOC 2 Controls]
        PCI[PCI-DSS Controls]
        HIPAA_C[HIPAA Controls]
    end

    FINDING --> MAPPER
    RULES --> MAPPER
    MAPPER --> OWASP & SOC2 & PCI & HIPAA_C
```

### Why Compliance Mapping Matters

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   WITHOUT COMPLIANCE MAPPING          WITH COMPLIANCE MAPPING   │
│   ═════════════════════════          ════════════════════════   │
│                                                                 │
│   "You have 15 security             "You have 15 findings       │
│    findings"                          that affect:              │
│                                                                 │
│   ┌─────────────────────┐            • 3 OWASP LLM controls     │
│   │  Now what?          │            • 5 SOC 2 controls         │
│   │  Which matter?      │            • 2 PCI-DSS requirements   │
│   │  Am I compliant?    │                                       │
│   └─────────────────────┘            Your SOC 2 compliance:     │
│                                      [████████░░] 80%"          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Supported Frameworks

| Framework | Focus Area | Best For |
|-----------|-----------|----------|
| **OWASP LLM Top 10** | AI/LLM security risks | AI applications |
| **OWASP MCP Top 10** | MCP server security | MCP deployments |
| **SOC 2** | Trust service criteria | SaaS companies |
| **PCI-DSS** | Payment card security | Payment processing |
| **HIPAA** | Health data protection | Healthcare |

```mermaid
graph TB
    subgraph "Your Industry"
        HEALTH[Healthcare]
        FINANCE[Financial]
        SAAS[SaaS/Tech]
        AI_FOCUS[AI-Focused]
    end

    subgraph "Primary Framework"
        HIPAA_F[HIPAA]
        PCI_F[PCI-DSS]
        SOC2_F[SOC 2]
        OWASP_F[OWASP LLM/MCP]
    end

    HEALTH --> HIPAA_F
    FINANCE --> PCI_F
    SAAS --> SOC2_F
    AI_FOCUS --> OWASP_F
```

---

## OWASP LLM Top 10

The OWASP Top 10 for Large Language Model Applications covers AI-specific security risks.

### Controls Overview

```mermaid
graph TB
    subgraph "OWASP LLM Top 10"
        LLM01[LLM01: Prompt Injection]
        LLM02[LLM02: Insecure Output]
        LLM03[LLM03: Training Poisoning]
        LLM04[LLM04: DoS]
        LLM05[LLM05: Supply Chain]
        LLM06[LLM06: Permission Issues]
        LLM07[LLM07: Data Leakage]
        LLM08[LLM08: Excessive Agency]
        LLM09[LLM09: Overreliance]
        LLM10[LLM10: Model Theft]
    end
```

### Mapping Details

| Control | SecureAgent Rules | Description |
|---------|------------------|-------------|
| **LLM01** | MCP-002, LC-001 | Prompt and command injection |
| **LLM02** | LC-007, OAI-005 | Unvalidated output handling |
| **LLM06** | MCP-005, LC-001, LC-002 | Overly permissive agents |
| **LLM07** | MCP-001, LC-003, OAI-001 | Credential and data exposure |
| **LLM08** | MCP-003, LC-001, OAI-002 | Too much autonomous action |

### Example Report

```
╔═══════════════════════════════════════════════════════════════╗
║              OWASP LLM TOP 10 COMPLIANCE REPORT               ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║   Control Status                                              ║
║   ──────────────                                              ║
║                                                               ║
║   LLM01 Prompt Injection      🔴 VIOLATION   2 findings       ║
║   LLM02 Insecure Output       🟢 COMPLIANT                    ║
║   LLM03 Training Poisoning    🟢 COMPLIANT                    ║
║   LLM04 Denial of Service     🟢 COMPLIANT                    ║
║   LLM05 Supply Chain          🟡 WARNING     1 finding        ║
║   LLM06 Permission Issues     🔴 VIOLATION   3 findings       ║
║   LLM07 Data Leakage          🔴 VIOLATION   1 finding        ║
║   LLM08 Excessive Agency      🟡 WARNING     2 findings       ║
║   LLM09 Overreliance          🟢 COMPLIANT                    ║
║   LLM10 Model Theft           🟢 COMPLIANT                    ║
║                                                               ║
║   Overall: 60% Compliant                                      ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## OWASP MCP Top 10

Specific to Model Context Protocol server security.

### Controls Overview

| Control | Name | Description |
|---------|------|-------------|
| **MCP01** | Server Spoofing | Fake MCP server attacks |
| **MCP02** | Tool Poisoning | Malicious tool definitions |
| **MCP03** | Credential Exposure | Secrets in configs |
| **MCP04** | Command Injection | Shell command vulnerabilities |
| **MCP05** | Privilege Escalation | Unauthorized access |
| **MCP06** | Data Exfiltration | Unauthorized data transfer |
| **MCP07** | Insecure Communication | Unencrypted traffic |
| **MCP08** | Logging Failures | Missing audit trails |
| **MCP09** | Resource Exhaustion | DoS vulnerabilities |
| **MCP10** | Version Vulnerabilities | Outdated components |

### Mapping Flow

```mermaid
flowchart LR
    subgraph "MCP Scanner Findings"
        F1[MCP-001: Hardcoded Creds]
        F2[MCP-002: Command Injection]
        F3[MCP-003: Shell Patterns]
    end

    subgraph "OWASP MCP Controls"
        MCP03_C[MCP03: Credential Exposure]
        MCP04_C[MCP04: Command Injection]
        MCP05_C[MCP05: Privilege Escalation]
    end

    F1 --> MCP03_C
    F2 --> MCP04_C
    F3 --> MCP04_C & MCP05_C
```

---

## SOC 2

SOC 2 (Service Organization Control 2) is essential for SaaS companies and service providers.

### Trust Service Criteria

```mermaid
graph TB
    subgraph "SOC 2 Trust Principles"
        SEC[Security<br/>CC6, CC7, CC8]
        AVAIL[Availability<br/>A1]
        PI[Processing Integrity<br/>PI1]
        CONF[Confidentiality<br/>C1]
        PRIV[Privacy<br/>P1-P8]
    end

    subgraph "SecureAgent Coverage"
        ACCESS[Access Controls]
        DATA[Data Protection]
        MONITOR[Monitoring]
    end

    SEC --> ACCESS & DATA & MONITOR
    CONF --> DATA
    PRIV --> DATA
```

### Key Control Mappings

| SOC 2 Control | Description | SecureAgent Rules |
|---------------|-------------|-------------------|
| **CC6.1** | Access to systems | MCP-005, AWS-IAM-001 |
| **CC6.6** | Manage credentials | MCP-001, LC-003 |
| **CC6.7** | Restrict access | AWS-S3-001, AWS-EC2-001 |
| **CC7.2** | Monitor for anomalies | All findings tracked |
| **CC8.1** | Change management | Terraform scans |
| **C1.2** | Confidential data | MCP-006, AWS-S3-003 |

### Example Mapping

```
Finding: MCP-001 Hardcoded Credential
├── SOC 2 Controls Affected:
│   ├── CC6.1 - Logical access security
│   ├── CC6.6 - Credential management
│   └── C1.2 - Confidential information protection
│
├── Compliance Status: VIOLATION
│
└── Remediation Required:
    Remove credentials from configuration files.
    Use environment variables or secret management.
```

---

## PCI-DSS

Payment Card Industry Data Security Standard for payment processing.

### Applicable Requirements

```mermaid
graph TB
    subgraph "PCI-DSS Requirements"
        REQ1[Req 1: Firewalls]
        REQ2[Req 2: Default Passwords]
        REQ3[Req 3: Protect Data]
        REQ6[Req 6: Secure Systems]
        REQ7[Req 7: Access Control]
        REQ8[Req 8: Authentication]
        REQ10[Req 10: Logging]
    end

    subgraph "SecureAgent Checks"
        NET[Network Security]
        CRED[Credential Security]
        ENCRYPT[Encryption]
        CODE[Code Security]
    end

    REQ1 --> NET
    REQ2 --> CRED
    REQ3 --> ENCRYPT
    REQ6 --> CODE
    REQ7 --> CRED
    REQ8 --> CRED
```

### Control Mappings

| PCI-DSS | Requirement | SecureAgent Rules |
|---------|-------------|-------------------|
| **1.3** | Restrict internet access | AWS-EC2-001, TF-SG-001 |
| **2.1** | Change defaults | AWS-IAM-002 |
| **3.4** | Render data unreadable | AWS-S3-003, TF-EC2-002 |
| **6.5.1** | Injection flaws | MCP-002, LC-004 |
| **6.5.10** | Broken auth | MCP-001, LC-003 |
| **7.1** | Limit access | MCP-005, AWS-IAM-001 |

---

## HIPAA

Health Insurance Portability and Accountability Act for healthcare data.

### Security Rule Categories

```mermaid
graph TB
    subgraph "HIPAA Security Rule"
        ADMIN[Administrative<br/>Safeguards]
        PHYS[Physical<br/>Safeguards]
        TECH[Technical<br/>Safeguards]
    end

    subgraph "Technical Safeguards (SecureAgent Focus)"
        ACCESS_C[Access Control]
        AUDIT[Audit Controls]
        INTEGRITY[Integrity Controls]
        TRANSMIT[Transmission Security]
    end

    TECH --> ACCESS_C & AUDIT & INTEGRITY & TRANSMIT
```

### Control Mappings

| HIPAA Control | Description | SecureAgent Rules |
|---------------|-------------|-------------------|
| **164.312(a)(1)** | Access control | All IAM/permission rules |
| **164.312(a)(2)(iv)** | Encryption | AWS-S3-003, TF-EC2-002 |
| **164.312(b)** | Audit controls | Logging-related findings |
| **164.312(c)(1)** | Integrity | Data protection findings |
| **164.312(d)** | Authentication | Credential findings |
| **164.312(e)(1)** | Transmission | Network exposure findings |

---

## Using Compliance Reports

### Generate Reports

```bash
# Generate OWASP LLM compliance report
secureagent compliance report owasp-llm

# Generate SOC 2 compliance status
secureagent compliance report soc2

# Check all frameworks
secureagent compliance status

# Show compliance gaps
secureagent compliance gaps
```

### Export Formats

```bash
# Export as HTML (for sharing)
secureagent compliance export --format html --output report.html

# Export as JSON (for automation)
secureagent compliance export --format json --output report.json

# Export as PDF (for auditors)
secureagent compliance export --format pdf --output report.pdf
```

### Report Structure

```mermaid
flowchart TB
    subgraph "Compliance Report"
        EXEC[Executive Summary]
        STATUS[Control Status]
        GAPS[Gap Analysis]
        FINDINGS[Related Findings]
        REMEDIATE[Remediation Plan]
    end

    EXEC --> STATUS --> GAPS --> FINDINGS --> REMEDIATE
```

### Understanding Report Output

```
╔═══════════════════════════════════════════════════════════════╗
║                   SOC 2 COMPLIANCE REPORT                     ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║   EXECUTIVE SUMMARY                                           ║
║   ─────────────────                                           ║
║   Scan Date: 2024-01-15                                       ║
║   Overall Compliance: 75%                                     ║
║   Critical Gaps: 3                                            ║
║                                                               ║
║   COMPLIANCE BY CATEGORY                                      ║
║   ──────────────────────                                      ║
║                                                               ║
║   Security (CC6-CC8)                                          ║
║   ├── CC6.1 Access Controls     🟢 COMPLIANT                  ║
║   ├── CC6.6 Credentials         🔴 VIOLATION                  ║
║   ├── CC6.7 Restrict Access     🔴 VIOLATION                  ║
║   └── CC7.2 Monitoring          🟢 COMPLIANT                  ║
║                                                               ║
║   Confidentiality (C1)                                        ║
║   └── C1.2 Protection           🟡 PARTIAL                    ║
║                                                               ║
║   GAP DETAILS                                                 ║
║   ───────────                                                 ║
║                                                               ║
║   CC6.6 - Credential Management                               ║
║   ┌─────────────────────────────────────────────────────┐    ║
║   │ Finding: MCP-001 Hardcoded credential in config     │    ║
║   │ Impact: Unauthorized access to systems              │    ║
║   │ Remediation: Use environment variables              │    ║
║   └─────────────────────────────────────────────────────┘    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## Compliance Workflow

### Recommended Process

```mermaid
flowchart TB
    subgraph "1. Baseline"
        SCAN1[Run Full Scan]
        REPORT1[Generate Reports]
        BASELINE[Establish Baseline]
    end

    subgraph "2. Remediate"
        PRIORITY[Prioritize Gaps]
        FIX[Fix Issues]
        VERIFY[Verify Fixes]
    end

    subgraph "3. Maintain"
        CICD[Add to CI/CD]
        MONITOR[Monitor Continuously]
        AUDIT[Prepare for Audits]
    end

    SCAN1 --> REPORT1 --> BASELINE
    BASELINE --> PRIORITY --> FIX --> VERIFY
    VERIFY --> CICD --> MONITOR --> AUDIT
```

### For Auditors

SecureAgent reports are designed to support audit processes:

1. **Evidence Collection** - All findings include timestamps and locations
2. **Remediation Tracking** - Track which issues were fixed
3. **Historical Data** - Export reports over time
4. **Control Mapping** - Direct mapping to framework controls

---

## Next Steps

- [Integrations](integrations.md) - Set up CI/CD and notifications
- [CLI Reference](cli-reference.md) - All compliance commands
- [Getting Started](getting-started.md) - Installation guide
