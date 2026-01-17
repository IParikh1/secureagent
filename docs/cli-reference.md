# CLI Reference

Complete command reference for SecureAgent.

---

## Table of Contents

1. [Global Options](#global-options)
2. [scan](#scan)
3. [mcp](#mcp)
4. [cloud](#cloud)
5. [rag](#rag)
6. [multiagent](#multiagent)
7. [detect](#detect)
8. [inventory](#inventory)
9. [analyze](#analyze)
10. [compliance](#compliance)
11. [github](#github)
12. [slack](#slack)

---

## Global Options

These options work with all commands:

```bash
secureagent [OPTIONS] COMMAND
```

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--help` | Show help message |
| `--verbose`, `-v` | Enable verbose output |
| `--quiet`, `-q` | Suppress non-essential output |
| `--config FILE` | Use custom config file |

---

## scan

Universal scan command for all security scanners.

### Usage

```bash
secureagent scan [OPTIONS] TARGET
```

### Arguments

| Argument | Description |
|----------|-------------|
| `TARGET` | File or directory to scan |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--scanners`, `-s` | `auto` | Comma-separated list of scanners |
| `--format`, `-f` | `console` | Output format |
| `--output`, `-o` | - | Output file path |
| `--min-severity` | `info` | Minimum severity to report |
| `--ci` | `false` | CI mode with exit codes |
| `--fail-on` | - | Exit 1 if findings >= severity |
| `--ignore-rules` | - | Rules to ignore (comma-separated) |
| `--ignore-paths` | - | Paths to ignore (comma-separated) |
| `--compliance` | - | Include compliance mapping |
| `--include-fixes` | `false` | Include fix suggestions |

### Scanner Values

```
mcp         - MCP server configurations
langchain   - LangChain Python code
openai      - OpenAI Assistants code
autogpt     - AutoGPT/CrewAI code
multiagent  - Multi-agent orchestration security
rag         - RAG system security
aws         - Live AWS account
azure       - Live Azure account
terraform   - Terraform files
all         - All available scanners
auto        - Auto-detect based on files
```

### Format Values

```
console  - Rich terminal output (default)
json     - JSON format
sarif    - SARIF 2.1.0 format
html     - HTML report
```

### Examples

```bash
# Basic scan
secureagent scan .

# Scan with specific scanners
secureagent scan . --scanners mcp,langchain

# Output to JSON file
secureagent scan . --format json --output results.json

# CI mode with failure threshold
secureagent scan . --ci --fail-on high

# Filter by severity
secureagent scan . --min-severity high

# Ignore specific rules
secureagent scan . --ignore-rules MCP-003,LC-007

# With compliance mapping
secureagent scan . --compliance owasp-llm,soc2
```

### Exit Codes (CI Mode)

| Code | Meaning |
|------|---------|
| 0 | No findings (or below threshold) |
| 1 | Findings at or above threshold |
| 2 | Scan error |

---

## mcp

MCP-specific commands.

### mcp scan

```bash
secureagent mcp scan [OPTIONS] TARGET
```

Scan MCP configuration files.

| Option | Description |
|--------|-------------|
| `--format`, `-f` | Output format |
| `--output`, `-o` | Output file |
| `--verbose`, `-v` | Verbose output |

### mcp validate

```bash
secureagent mcp validate [OPTIONS] CONFIG_FILE
```

Validate MCP configuration structure.

| Option | Description |
|--------|-------------|
| `--strict` | Strict validation mode |

### mcp fix

```bash
secureagent mcp fix [OPTIONS] CONFIG_FILE
```

Auto-fix security issues in MCP config.

| Option | Description |
|--------|-------------|
| `--dry-run` | Show changes without applying |
| `--backup` | Create backup before fixing |

### mcp rules

```bash
secureagent mcp rules
```

List all MCP security rules.

### Examples

```bash
# Scan MCP config
secureagent mcp scan ~/.config/claude/claude_desktop_config.json

# Validate structure
secureagent mcp validate config.json

# Auto-fix with backup
secureagent mcp fix config.json --backup

# Preview fixes
secureagent mcp fix config.json --dry-run

# List rules
secureagent mcp rules
```

---

## cloud

Cloud infrastructure scanning.

### cloud scan

```bash
secureagent cloud scan [OPTIONS]
```

Scan cloud infrastructure.

| Option | Description |
|--------|-------------|
| `--provider`, `-p` | Cloud provider (aws, azure, all) |
| `--services` | Specific services to scan |
| `--region` | AWS region(s) |
| `--format`, `-f` | Output format |
| `--output`, `-o` | Output file |

### cloud aws

```bash
secureagent cloud aws [SERVICE]
```

Scan specific AWS services.

| Service | Description |
|---------|-------------|
| `s3` | S3 buckets |
| `iam` | IAM policies and users |
| `ec2` | EC2 instances and security groups |

### cloud azure

```bash
secureagent cloud azure [SERVICE]
```

Scan specific Azure services.

| Service | Description |
|---------|-------------|
| `storage` | Storage accounts |
| `keyvault` | Key Vault |

### Examples

```bash
# Scan all AWS services
secureagent cloud scan --provider aws

# Scan specific AWS service
secureagent cloud aws s3
secureagent cloud aws iam

# Scan Azure
secureagent cloud scan --provider azure

# Scan all providers
secureagent cloud scan --provider all

# Output to JSON
secureagent cloud scan --provider aws --format json --output aws-results.json
```

---

## rag

RAG (Retrieval-Augmented Generation) security scanning commands.

### rag scan

```bash
secureagent rag scan [OPTIONS] TARGET
```

Full RAG system security scan.

| Option | Description |
|--------|-------------|
| `--format`, `-f` | Output format |
| `--output`, `-o` | Output file |
| `--min-severity` | Minimum severity to report |

### rag vector-stores

```bash
secureagent rag vector-stores [OPTIONS] TARGET
```

Analyze vector store security.

| Option | Description |
|--------|-------------|
| `--provider` | Vector store provider (pinecone, chroma, etc.) |
| `--check-encryption` | Check encryption settings |
| `--check-access` | Check access controls |

### rag documents

```bash
secureagent rag documents [OPTIONS] TARGET
```

Analyze document ingestion security.

| Option | Description |
|--------|-------------|
| `--scan-content` | Scan document contents |
| `--check-metadata` | Check metadata handling |

### rag poisoning

```bash
secureagent rag poisoning [OPTIONS] TARGET
```

Detect RAG poisoning attempts.

| Option | Description |
|--------|-------------|
| `--deep-scan` | Perform deep analysis |
| `--check-embeddings` | Analyze embeddings |

### rag test

```bash
secureagent rag test [OPTIONS] ENDPOINT
```

Active security testing with RAG payloads.

| Option | Description |
|--------|-------------|
| `--payloads` | Payload categories to test |
| `--timeout` | Request timeout |

### Examples

```bash
# Full RAG scan
secureagent rag scan ./rag-project

# Check vector store security
secureagent rag vector-stores ./config --provider pinecone

# Analyze document ingestion
secureagent rag documents ./ingestion

# Detect poisoning
secureagent rag poisoning ./knowledge-base

# Test RAG endpoint
secureagent rag test http://localhost:8000/query
```

---

## multiagent

Multi-agent system security scanning commands.

### multiagent scan

```bash
secureagent multiagent scan [OPTIONS] TARGET
```

Full multi-agent system security scan.

| Option | Description |
|--------|-------------|
| `--format`, `-f` | Output format |
| `--output`, `-o` | Output file |
| `--frameworks` | Specific frameworks to scan |

### multiagent orchestration

```bash
secureagent multiagent orchestration [OPTIONS] TARGET
```

Analyze orchestration security.

| Option | Description |
|--------|-------------|
| `--check-cycles` | Check for workflow cycles |
| `--check-privileges` | Analyze privilege escalation |

### multiagent communication

```bash
secureagent multiagent communication [OPTIONS] TARGET
```

Analyze agent communication channels.

| Option | Description |
|--------|-------------|
| `--check-encryption` | Verify channel encryption |
| `--check-auth` | Check authentication |

### multiagent delegation

```bash
secureagent multiagent delegation [OPTIONS] TARGET
```

Detect delegation attacks.

| Option | Description |
|--------|-------------|
| `--max-depth` | Maximum delegation depth |
| `--check-circular` | Check for circular delegation |

### multiagent frameworks

```bash
secureagent multiagent frameworks [OPTIONS] TARGET
```

Detect and analyze multi-agent frameworks.

| Option | Description |
|--------|-------------|
| `--detailed` | Show detailed analysis |

### multiagent test

```bash
secureagent multiagent test [OPTIONS] ENDPOINT
```

Active security testing with multi-agent payloads.

| Option | Description |
|--------|-------------|
| `--payloads` | Payload categories to test |
| `--timeout` | Request timeout |

### Examples

```bash
# Full multi-agent scan
secureagent multiagent scan ./project

# Check orchestration
secureagent multiagent orchestration ./workflow

# Analyze communication
secureagent multiagent communication ./config

# Detect delegation attacks
secureagent multiagent delegation ./agents

# Detect frameworks
secureagent multiagent frameworks ./project

# Test endpoint
secureagent multiagent test http://localhost:8000/agent
```

---

## detect

Jailbreak detection and analysis commands.

### detect jailbreak

```bash
secureagent detect jailbreak [OPTIONS] INPUT
```

Detect jailbreak attempts in prompts.

| Option | Description |
|--------|-------------|
| `--model` | Detection model to use |
| `--threshold` | Detection threshold |
| `--detailed` | Show detailed analysis |

### detect analyze

```bash
secureagent detect analyze [OPTIONS] TARGET
```

Analyze prompts for injection patterns.

| Option | Description |
|--------|-------------|
| `--patterns` | Pattern categories to check |
| `--output`, `-o` | Output file |

### Examples

```bash
# Detect jailbreak in input
secureagent detect jailbreak "Ignore previous instructions..."

# Analyze prompt file
secureagent detect analyze ./prompts.txt

# Detailed analysis
secureagent detect jailbreak "input" --detailed --threshold 0.8
```

---

## inventory

AI agent inventory management.

### inventory discover

```bash
secureagent inventory discover [OPTIONS] PATH
```

Discover AI agents in a path.

| Option | Description |
|--------|-------------|
| `--frameworks` | Frameworks to look for |
| `--recursive`, `-r` | Recursive search |

### inventory list

```bash
secureagent inventory list [OPTIONS]
```

List discovered agents.

| Option | Description |
|--------|-------------|
| `--format`, `-f` | Output format |
| `--filter` | Filter by framework |
| `--sort` | Sort by field |

### inventory show

```bash
secureagent inventory show AGENT_ID
```

Show details for a specific agent.

### inventory export

```bash
secureagent inventory export [OPTIONS]
```

Export inventory.

| Option | Description |
|--------|-------------|
| `--format`, `-f` | Export format (json, csv) |
| `--output`, `-o` | Output file |

### inventory sync

```bash
secureagent inventory sync [OPTIONS]
```

Sync inventory with catalog.

### Examples

```bash
# Discover agents
secureagent inventory discover .

# List all agents
secureagent inventory list

# Filter by framework
secureagent inventory list --filter framework=langchain

# Show agent details
secureagent inventory show agent-001

# Export to JSON
secureagent inventory export --format json --output inventory.json
```

---

## analyze

Risk and data analysis commands.

### analyze permissions

```bash
secureagent analyze permissions AGENT_ID
```

Show permission map for an agent.

### analyze data-flow

```bash
secureagent analyze data-flow AGENT_ID
```

Trace data flows for an agent.

### analyze guardrails

```bash
secureagent analyze guardrails AGENT_ID
```

Check guardrail coverage.

### analyze egress

```bash
secureagent analyze egress AGENT_ID
```

Map egress paths.

### analyze risk

```bash
secureagent analyze risk [OPTIONS] TARGET
```

Calculate risk score.

| Option | Description |
|--------|-------------|
| `--detailed` | Show detailed breakdown |
| `--include-ml` | Include ML risk score |

### Examples

```bash
# Permission analysis
secureagent analyze permissions agent-001

# Data flow tracing
secureagent analyze data-flow agent-001

# Risk assessment
secureagent analyze risk agent-001 --detailed

# Guardrail coverage
secureagent analyze guardrails agent-001
```

---

## compliance

Compliance reporting commands.

### compliance report

```bash
secureagent compliance report [OPTIONS] FRAMEWORK
```

Generate compliance report.

| Framework | Description |
|-----------|-------------|
| `owasp-llm` | OWASP LLM Top 10 |
| `owasp-mcp` | OWASP MCP Top 10 |
| `soc2` | SOC 2 |
| `pci-dss` | PCI-DSS |
| `hipaa` | HIPAA |

| Option | Description |
|--------|-------------|
| `--format`, `-f` | Output format |
| `--output`, `-o` | Output file |

### compliance status

```bash
secureagent compliance status [OPTIONS]
```

Show compliance status overview.

| Option | Description |
|--------|-------------|
| `--frameworks` | Specific frameworks |

### compliance gaps

```bash
secureagent compliance gaps [OPTIONS]
```

Show compliance gaps.

| Option | Description |
|--------|-------------|
| `--framework` | Specific framework |
| `--severity` | Filter by severity |

### compliance export

```bash
secureagent compliance export [OPTIONS]
```

Export compliance report.

| Option | Description |
|--------|-------------|
| `--format`, `-f` | Export format (html, pdf, json) |
| `--framework` | Specific framework |
| `--output`, `-o` | Output file |

### Examples

```bash
# Generate OWASP LLM report
secureagent compliance report owasp-llm

# Check status for all frameworks
secureagent compliance status

# Show gaps for SOC 2
secureagent compliance gaps --framework soc2

# Export HTML report
secureagent compliance export --format html --framework soc2 --output soc2-report.html
```

---

## github

GitHub integration commands.

### github scan

```bash
secureagent github scan [OPTIONS] REPO
```

Scan a GitHub repository.

| Option | Description |
|--------|-------------|
| `--pr` | PR number for comments |
| `--create-issues` | Create issues for findings |
| `--issue-severity` | Severity threshold for issues |

### github setup

```bash
secureagent github setup
```

Configure GitHub integration.

### github status

```bash
secureagent github status
```

Check integration status.

### Examples

```bash
# Scan repo
secureagent github scan owner/repo

# With PR comments
secureagent github scan owner/repo --pr 123

# Create issues
secureagent github scan owner/repo --create-issues --issue-severity critical
```

---

## slack

Slack integration commands.

### slack setup

```bash
secureagent slack setup
```

Configure Slack integration.

### slack test

```bash
secureagent slack test
```

Test Slack connection.

### slack status

```bash
secureagent slack status
```

Check Slack integration status.

### Examples

```bash
# Set up Slack
secureagent slack setup

# Test connection
secureagent slack test

# Check status
secureagent slack status
```

---

## Configuration File

### Location

SecureAgent looks for configuration in:

1. `.secureagent.yaml` in current directory
2. `.secureagent.yml` in current directory
3. `~/.config/secureagent/config.yaml`

### Full Example

```yaml
# Scanners
scanners:
  - mcp
  - langchain
  - openai

# Severity threshold
min_severity: medium

# Rules to ignore
ignore_rules:
  - MCP-003
  - LC-007

# Paths to ignore
ignore_paths:
  - tests/
  - node_modules/
  - venv/
  - .git/

# Output settings
output:
  format: console
  color: true
  verbose: false

# CI settings
ci:
  fail_on: high
  sarif_output: results.sarif

# Cloud settings
cloud:
  aws:
    regions:
      - us-east-1
      - us-west-2
    services:
      - s3
      - iam
      - ec2

# Alert settings
alerts:
  slack:
    webhook_url: ${SLACK_WEBHOOK_URL}
    channel: "#security-alerts"
    min_severity: high

  webhooks:
    - url: ${SIEM_WEBHOOK}
      min_severity: info

# Compliance
compliance:
  frameworks:
    - owasp-llm
    - soc2
  auto_map: true

# ML settings
ml:
  enabled: true
  model_path: models/secureagent_risk_v1.pkl
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SECUREAGENT_CONFIG` | Path to config file |
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `AWS_REGION` | Default AWS region |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription |
| `GITHUB_TOKEN` | GitHub API token |
| `SLACK_WEBHOOK_URL` | Slack webhook URL |

---

## See Also

- [Getting Started](getting-started.md)
- [Scanners Guide](scanners.md)
- [Integrations](integrations.md)
- [Compliance](compliance.md)
