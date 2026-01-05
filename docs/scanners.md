# Scanners Guide

SecureAgent includes multiple specialized scanners for different types of AI systems and cloud infrastructure. This guide explains how each scanner works and what it checks.

---

## Table of Contents

1. [Scanner Overview](#scanner-overview)
2. [MCP Scanner](#mcp-scanner)
3. [LangChain Scanner](#langchain-scanner)
4. [OpenAI Assistants Scanner](#openai-assistants-scanner)
5. [AWS Scanner](#aws-scanner)
6. [Azure Scanner](#azure-scanner)
7. [Terraform Scanner](#terraform-scanner)

---

## Scanner Overview

### How Scanners Work

```mermaid
flowchart TB
    subgraph "Scanner Workflow"
        INPUT[Input Target<br/>File or Directory]
        DISCOVER[Discover<br/>Relevant Files]
        PARSE[Parse & Extract<br/>Configuration]
        RULES[Apply Security<br/>Rules]
        FINDINGS[Generate<br/>Findings]
    end

    INPUT --> DISCOVER --> PARSE --> RULES --> FINDINGS
```

### Available Scanners

| Scanner | Target | Key Checks |
|---------|--------|------------|
| **MCP** | MCP server configs | Credentials, shell commands, permissions |
| **LangChain** | Python code | Dangerous tools, API keys, memory leaks |
| **OpenAI** | Python code | Code interpreter, function calls, file access |
| **AWS** | Live AWS account | S3, IAM, EC2, security groups |
| **Azure** | Live Azure account | Storage, Key Vault, networking |
| **Terraform** | `.tf` files | IaC misconfigurations |

### Running Multiple Scanners

```bash
# Run specific scanners
secureagent scan ./project --scanners mcp,langchain

# Run all scanners
secureagent scan ./project --scanners all
```

---

## MCP Scanner

The MCP (Model Context Protocol) scanner analyzes MCP server configurations for security issues.

### What It Scans

```mermaid
graph TB
    subgraph "MCP Configuration"
        SERVERS[Server Definitions]
        COMMANDS[Command Patterns]
        ENV[Environment Variables]
        ARGS[Command Arguments]
    end

    subgraph "Security Checks"
        CRED[Credential Detection]
        SHELL[Shell Injection]
        PATH[Path Traversal]
        PRIV[Privilege Level]
    end

    SERVERS --> CRED
    COMMANDS --> SHELL
    ENV --> CRED
    ARGS --> PATH & SHELL
```

### Security Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| MCP-001 | Hardcoded Credentials | CRITICAL | API keys or passwords in config |
| MCP-002 | Command Injection | CRITICAL | Untrusted input in commands |
| MCP-003 | Shell Command Patterns | HIGH | Dangerous shell commands |
| MCP-004 | Path Traversal | HIGH | `../` patterns in paths |
| MCP-005 | Overly Permissive | MEDIUM | Too many capabilities |
| MCP-006 | Sensitive Env Vars | MEDIUM | Sensitive data in environment |
| MCP-007 | No Input Validation | LOW | Missing validation rules |

### How It Works

```mermaid
sequenceDiagram
    participant User
    participant Scanner as MCP Scanner
    participant Parser as JSON Parser
    participant Rules as Rules Engine

    User->>Scanner: scan(config.json)
    Scanner->>Parser: parse JSON
    Parser->>Scanner: config object

    loop For each server
        Scanner->>Rules: check_credentials(server)
        Rules->>Scanner: findings[]

        Scanner->>Rules: check_commands(server)
        Rules->>Scanner: findings[]

        Scanner->>Rules: check_permissions(server)
        Rules->>Scanner: findings[]
    end

    Scanner->>User: all findings
```

### Example Findings

**Hardcoded Credential:**
```json
{
  "mcpServers": {
    "database": {
      "command": "db-server",
      "env": {
        "DB_PASSWORD": "supersecret123"  // ❌ Hardcoded!
      }
    }
  }
}
```

**Fix:** Use environment variable reference:
```json
"DB_PASSWORD": "${DB_PASSWORD}"  // ✓ Safe
```

### Command Line

```bash
# Scan MCP config
secureagent mcp scan ~/.config/claude/claude_desktop_config.json

# Validate config structure
secureagent mcp validate config.json

# Auto-fix issues
secureagent mcp fix config.json
```

---

## LangChain Scanner

The LangChain scanner analyzes Python code that uses the LangChain framework.

### What It Scans

```mermaid
graph TB
    subgraph "LangChain Code"
        TOOLS[Tool Definitions]
        AGENTS[Agent Configurations]
        MEMORY[Memory Systems]
        CHAINS[Chain Definitions]
    end

    subgraph "Security Checks"
        SHELL_T[Shell Tool Usage]
        REPL[Python REPL]
        SQL[SQL Injection]
        KEY[API Key Exposure]
    end

    TOOLS --> SHELL_T & REPL
    AGENTS --> KEY
    MEMORY --> SQL
    CHAINS --> KEY
```

### Security Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| LC-001 | Shell Tool | CRITICAL | Unrestricted shell execution |
| LC-002 | Python REPL | CRITICAL | Arbitrary code execution |
| LC-003 | Hardcoded API Key | CRITICAL | API keys in source code |
| LC-004 | SQL Database | HIGH | Potential SQL injection |
| LC-005 | Unencrypted Memory | HIGH | Sensitive data in memory |
| LC-006 | File System Tool | HIGH | Unrestricted file access |
| LC-007 | Verbose Mode | MEDIUM | Debug output exposed |

### Detection Patterns

```mermaid
flowchart LR
    subgraph "Code Analysis"
        AST[Parse Python AST]
        IMPORT[Find Imports]
        CALL[Find Function Calls]
        STRING[Find String Literals]
    end

    subgraph "Pattern Matching"
        TOOL_PAT[Tool Patterns]
        KEY_PAT[API Key Patterns]
        SQL_PAT[SQL Patterns]
    end

    AST --> IMPORT --> TOOL_PAT
    AST --> CALL --> SQL_PAT
    AST --> STRING --> KEY_PAT
```

### Example Findings

**Dangerous Tool:**
```python
from langchain.tools import ShellTool

agent = initialize_agent(
    tools=[ShellTool()],  # ❌ Full shell access!
    llm=llm
)
```

**Hardcoded API Key:**
```python
openai_api_key = "sk-abc123..."  # ❌ Exposed!
```

### Command Line

```bash
# Scan Python files
secureagent scan ./my_agent.py --scanners langchain

# Scan directory
secureagent scan ./langchain_project --scanners langchain
```

---

## OpenAI Assistants Scanner

Scans code that uses OpenAI's Assistants API for security issues.

### What It Scans

```mermaid
graph TB
    subgraph "OpenAI Assistants"
        ASSIST[Assistant Creation]
        TOOLS_OAI[Tool Configuration]
        FILES[File Attachments]
        FUNC[Function Definitions]
    end

    subgraph "Security Checks"
        INTERP[Code Interpreter]
        SEARCH[File Search]
        FUNC_CHK[Function Risks]
        KEY_CHK[API Key Check]
    end

    ASSIST --> KEY_CHK
    TOOLS_OAI --> INTERP & SEARCH
    FUNC --> FUNC_CHK
```

### Security Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| OAI-001 | Hardcoded API Key | CRITICAL | OpenAI key in code |
| OAI-002 | Code Interpreter | HIGH | Arbitrary code execution |
| OAI-003 | File Search | MEDIUM | Access to uploaded files |
| OAI-004 | Dangerous Function | HIGH | Risky function calls |
| OAI-005 | Missing Instructions | MEDIUM | No safety instructions |
| OAI-006 | Retrieval Enabled | MEDIUM | Knowledge retrieval active |

### Tool Risk Assessment

```mermaid
graph LR
    subgraph "Tool Types"
        CI[Code Interpreter]
        FS[File Search]
        FN[Function Calling]
    end

    subgraph "Risk Level"
        HIGH_R[HIGH RISK]
        MED_R[MEDIUM RISK]
    end

    CI --> HIGH_R
    FS --> MED_R
    FN --> HIGH_R
```

### Example Findings

**Code Interpreter Risk:**
```python
assistant = client.beta.assistants.create(
    tools=[{"type": "code_interpreter"}],  # ⚠️ Can run arbitrary code
    model="gpt-4"
)
```

### Command Line

```bash
# Scan for OpenAI patterns
secureagent scan ./assistant.py --scanners openai
```

---

## AWS Scanner

Scans your live AWS account for security misconfigurations.

### What It Scans

```mermaid
graph TB
    subgraph "AWS Services"
        S3[S3 Buckets]
        IAM[IAM Policies]
        EC2[EC2 Instances]
        SG[Security Groups]
        RDS[RDS Databases]
    end

    subgraph "Security Checks"
        PUBLIC[Public Access]
        ENCRYPT[Encryption]
        POLICY[Policy Review]
        NETWORK[Network Exposure]
    end

    S3 --> PUBLIC & ENCRYPT
    IAM --> POLICY
    EC2 --> NETWORK
    SG --> NETWORK
    RDS --> PUBLIC & ENCRYPT
```

### Security Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| AWS-S3-001 | Public Bucket | CRITICAL | Bucket accessible to everyone |
| AWS-S3-002 | Public ACL | HIGH | ACL allows public access |
| AWS-S3-003 | No Encryption | MEDIUM | Bucket not encrypted |
| AWS-IAM-001 | Admin Policy | HIGH | Overly permissive policy |
| AWS-IAM-002 | No MFA | HIGH | Root/admin without MFA |
| AWS-EC2-001 | Public SG | HIGH | Security group open to 0.0.0.0/0 |
| AWS-EC2-002 | SSH Exposed | CRITICAL | SSH open to internet |
| AWS-EC2-003 | DB Exposed | CRITICAL | Database port exposed |

### Scan Flow

```mermaid
sequenceDiagram
    participant User
    participant Scanner as AWS Scanner
    participant AWS as AWS APIs

    User->>Scanner: cloud scan --provider aws

    Scanner->>AWS: List S3 Buckets
    AWS->>Scanner: bucket list

    loop For each bucket
        Scanner->>AWS: Get bucket ACL
        Scanner->>AWS: Get public access block
        Scanner->>Scanner: Check for violations
    end

    Scanner->>AWS: List IAM policies
    Scanner->>AWS: List security groups
    Scanner->>AWS: Describe EC2 instances

    Scanner->>User: Security findings
```

### Example Findings

**Public S3 Bucket:**
```
┌─────────────────────────────────────────────────────────────┐
│ 🔴 CRITICAL: Public S3 Bucket                               │
├─────────────────────────────────────────────────────────────┤
│ Resource: arn:aws:s3:::my-data-bucket                       │
│                                                             │
│ This bucket is publicly accessible. Anyone on the           │
│ internet can read its contents.                             │
│                                                             │
│ Remediation:                                                │
│ 1. Enable "Block Public Access" in bucket settings          │
│ 2. Review and update bucket policy                          │
│ 3. Audit existing objects for sensitive data                │
└─────────────────────────────────────────────────────────────┘
```

### Command Line

```bash
# Scan all AWS services
secureagent cloud scan --provider aws

# Scan specific services
secureagent cloud aws s3
secureagent cloud aws iam
secureagent cloud aws ec2
```

---

## Azure Scanner

Scans your Azure subscription for security issues.

### What It Scans

```mermaid
graph TB
    subgraph "Azure Services"
        STORAGE[Storage Accounts]
        KEYVAULT[Key Vault]
        VM[Virtual Machines]
        NSG[Network Security Groups]
    end

    subgraph "Security Checks"
        ACCESS[Access Control]
        ENCRYPT_AZ[Encryption]
        NETWORK_AZ[Network Rules]
        SECRETS[Secret Management]
    end

    STORAGE --> ACCESS & ENCRYPT_AZ
    KEYVAULT --> SECRETS
    VM --> NETWORK_AZ
    NSG --> NETWORK_AZ
```

### Security Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| AZURE-STOR-001 | Public Container | CRITICAL | Container allows public access |
| AZURE-STOR-002 | HTTP Allowed | HIGH | HTTPS not enforced |
| AZURE-KV-001 | No Soft Delete | MEDIUM | Key Vault recovery disabled |
| AZURE-NSG-001 | Open Inbound | HIGH | NSG allows all inbound |

### Command Line

```bash
# Scan Azure resources
secureagent cloud scan --provider azure

# Scan specific services
secureagent cloud azure storage
```

---

## Terraform Scanner

Scans Infrastructure as Code (IaC) for security issues before deployment.

### What It Scans

```mermaid
graph TB
    subgraph "Terraform Resources"
        TF_S3[aws_s3_bucket]
        TF_SG[aws_security_group]
        TF_IAM[aws_iam_policy]
        TF_RDS[aws_db_instance]
        TF_EC2[aws_instance]
    end

    subgraph "Checks"
        CONFIG[Configuration]
        DEFAULTS[Insecure Defaults]
        EXPOSURE[Exposure Risks]
    end

    TF_S3 & TF_SG & TF_IAM & TF_RDS & TF_EC2 --> CONFIG & DEFAULTS & EXPOSURE
```

### Why Scan Terraform?

```mermaid
flowchart LR
    subgraph "Without Scanning"
        CODE1[Write Terraform] --> DEPLOY1[Deploy]
        DEPLOY1 --> PROD1[Insecure in Production!]
    end

    subgraph "With Scanning"
        CODE2[Write Terraform] --> SCAN[SecureAgent Scan]
        SCAN --> FIX[Fix Issues]
        FIX --> DEPLOY2[Deploy]
        DEPLOY2 --> PROD2[Secure in Production ✓]
    end

    style PROD1 fill:#ff6666
    style PROD2 fill:#66ff66
```

### Security Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| TF-S3-001 | Public Bucket | CRITICAL | S3 bucket allows public access |
| TF-SG-001 | Open Security Group | HIGH | SG allows 0.0.0.0/0 |
| TF-SG-002 | SSH From Internet | CRITICAL | Port 22 open to all |
| TF-SG-003 | All Traffic | CRITICAL | Protocol -1 (all) allowed |
| TF-RDS-001 | Public RDS | CRITICAL | Database publicly accessible |
| TF-EC2-001 | No IMDSv2 | MEDIUM | Instance metadata not secured |
| TF-EC2-002 | Unencrypted EBS | MEDIUM | EBS volume not encrypted |

### Example Findings

**Insecure Security Group:**
```hcl
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ❌ SSH open to world!
  }
}
```

**Fix:**
```hcl
cidr_blocks = ["10.0.0.0/8"]  # ✓ Internal only
```

### Command Line

```bash
# Scan Terraform files
secureagent scan ./terraform --scanners terraform

# Scan specific file
secureagent scan ./main.tf --scanners terraform
```

---

## Scanner Comparison

### When to Use Each Scanner

```mermaid
flowchart TB
    subgraph "What are you scanning?"
        Q1{MCP Server<br/>Configuration?}
        Q2{LangChain<br/>Python Code?}
        Q3{OpenAI<br/>Assistants Code?}
        Q4{Live AWS<br/>Account?}
        Q5{Terraform<br/>Files?}
    end

    Q1 -->|Yes| MCP_S[Use MCP Scanner]
    Q2 -->|Yes| LC_S[Use LangChain Scanner]
    Q3 -->|Yes| OAI_S[Use OpenAI Scanner]
    Q4 -->|Yes| AWS_S[Use AWS Scanner]
    Q5 -->|Yes| TF_S[Use Terraform Scanner]
```

### Feature Comparison

| Feature | MCP | LangChain | OpenAI | AWS | Azure | Terraform |
|---------|-----|-----------|--------|-----|-------|-----------|
| Credential Detection | ✓ | ✓ | ✓ | - | - | - |
| Command Injection | ✓ | ✓ | - | - | - | - |
| Network Exposure | - | - | - | ✓ | ✓ | ✓ |
| IAM Analysis | - | - | - | ✓ | ✓ | ✓ |
| Encryption Check | - | - | - | ✓ | ✓ | ✓ |
| Tool Analysis | ✓ | ✓ | ✓ | - | - | - |
| Auto-Fix | ✓ | - | - | - | - | - |

---

## Creating Custom Scanners

See [Architecture](architecture.md#plugin-system) for details on creating custom scanners.

```python
from secureagent.core.scanner.base import BaseScanner
from secureagent.core.models.finding import Finding

class CustomScanner(BaseScanner):
    name = "custom"
    description = "My custom scanner"

    def scan(self, target: str) -> List[Finding]:
        findings = []
        # Your scanning logic here
        return findings
```

---

## Next Steps

- [CLI Reference](cli-reference.md) - Complete command documentation
- [Compliance](compliance.md) - How findings map to standards
- [Integrations](integrations.md) - CI/CD integration
