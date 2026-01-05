# Getting Started with SecureAgent

This guide will help you install SecureAgent and run your first security scan in under 5 minutes.

---

## Table of Contents

1. [Installation](#installation)
2. [Your First Scan](#your-first-scan)
3. [Understanding Results](#understanding-results)
4. [Next Steps](#next-steps)

---

## Installation

### Requirements

- Python 3.9 or higher
- pip (Python package manager)

### Quick Install

```bash
# Install SecureAgent
pip install secureagent

# Verify installation
secureagent --version
```

### Installation Options

```bash
# Basic installation (MCP + LangChain scanning)
pip install secureagent

# With AWS scanning
pip install secureagent[aws]

# With Azure scanning
pip install secureagent[azure]

# With ML risk scoring
pip install secureagent[ml]

# With all features
pip install secureagent[full]
```

### Install from Source

```bash
git clone https://github.com/IParikh1/secureagent.git
cd secureagent
pip install -e .
```

---

## Your First Scan

### Option 1: Scan an MCP Configuration

If you use Claude Desktop or another MCP-enabled tool:

```bash
# Scan your Claude Desktop config
secureagent scan ~/.config/claude/claude_desktop_config.json
```

### Option 2: Scan a Project Directory

```bash
# Scan current directory
secureagent scan .

# Scan specific directory
secureagent scan ./my-ai-project
```

### Option 3: Scan with Specific Scanners

```bash
# Only MCP scanner
secureagent scan . --scanners mcp

# MCP and LangChain
secureagent scan . --scanners mcp,langchain

# All available scanners
secureagent scan . --scanners all
```

### Interactive Walkthrough

```
$ secureagent scan ./my-project

SecureAgent v1.0.0
══════════════════════════════════════════════════════════════

Discovering targets...
  ✓ Found 3 MCP configuration files
  ✓ Found 12 Python files

Running scanners...
  ✓ MCP Scanner: 3 files scanned
  ✓ LangChain Scanner: 12 files scanned

══════════════════════════════════════════════════════════════
                        SCAN RESULTS
══════════════════════════════════════════════════════════════

Summary
───────────────────────────────────────────────────────────────
  🔴 CRITICAL   1
  🟠 HIGH       2
  🟡 MEDIUM     3
  🟢 LOW        1
  ───────────────
  Total         7 findings

Findings
───────────────────────────────────────────────────────────────

[CRITICAL] MCP-001: Hardcoded Credential Detected
  📍 config/mcp.json:15

  API key "sk-abc..." found in configuration.

  💡 Remediation: Use environment variables instead.
     Change: "api_key": "sk-abc..."
     To:     "api_key": "${OPENAI_API_KEY}"

[HIGH] LC-001: Shell Tool Usage
  📍 agents/helper.py:42

  ShellTool() grants unrestricted command execution.

  💡 Remediation: Use a restricted command allowlist.

... (more findings)

══════════════════════════════════════════════════════════════
Scan completed in 1.2s
```

---

## Understanding Results

### Severity Levels

| Level | Icon | Meaning | Action |
|-------|------|---------|--------|
| **CRITICAL** | 🔴 | Immediate security risk | Fix now |
| **HIGH** | 🟠 | Significant vulnerability | Fix soon |
| **MEDIUM** | 🟡 | Moderate risk | Plan to fix |
| **LOW** | 🟢 | Minor issue | Consider fixing |
| **INFO** | 🔵 | Informational | No action needed |

### Reading a Finding

```
┌─────────────────────────────────────────────────────────────┐
│ [CRITICAL] MCP-001: Hardcoded Credential Detected           │
│                                                             │
│ 📍 Location: config/mcp.json:15                             │
│                                                             │
│ What's wrong:                                               │
│ API key "sk-abc..." found in configuration file.            │
│                                                             │
│ Why it matters:                                             │
│ Anyone with access to this file can use your API key.       │
│                                                             │
│ 💡 Remediation:                                             │
│ Use environment variables instead.                          │
│ Change: "api_key": "sk-abc..."                              │
│ To:     "api_key": "${OPENAI_API_KEY}"                      │
│                                                             │
│ 📊 Risk Score: 0.95                                         │
│ 📋 Compliance: OWASP LLM07, SOC2 CC6.6                      │
└─────────────────────────────────────────────────────────────┘
```

### Output Formats

```bash
# Console output (default)
secureagent scan .

# JSON output
secureagent scan . --format json

# Save to file
secureagent scan . --format json --output results.json

# SARIF (for GitHub)
secureagent scan . --format sarif --output results.sarif

# HTML report
secureagent scan . --format html --output report.html
```

---

## Common Use Cases

### Scan Before Committing

```bash
# Add to your workflow
secureagent scan . --ci --fail-on high
```

### Check Specific File

```bash
secureagent scan ./config/mcp.json
```

### Filter by Severity

```bash
# Only show high and critical
secureagent scan . --min-severity high
```

### With Compliance Info

```bash
# Include compliance mapping
secureagent scan . --compliance owasp-llm
```

---

## Configuration

### Create a Config File

Create `.secureagent.yaml` in your project:

```yaml
# Scanners to run by default
scanners:
  - mcp
  - langchain

# Minimum severity to report
min_severity: medium

# Ignore specific rules
ignore_rules:
  - MCP-003  # We've accepted this risk

# Paths to ignore
ignore_paths:
  - tests/
  - node_modules/
```

### Environment Variables

```bash
# AWS credentials (for cloud scanning)
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx

# Slack webhook (for alerts)
export SLACK_WEBHOOK_URL=https://hooks.slack.com/...

# GitHub token (for PR comments)
export GITHUB_TOKEN=ghp_xxx
```

---

## Quick Reference

### Essential Commands

```bash
# Basic scan
secureagent scan <target>

# With options
secureagent scan <target> --scanners mcp,langchain --format json

# Cloud scanning
secureagent cloud scan --provider aws

# Inventory
secureagent inventory discover .
secureagent inventory list

# Compliance
secureagent compliance report owasp-llm
secureagent compliance status

# Help
secureagent --help
secureagent scan --help
```

### Common Options

| Option | Description |
|--------|-------------|
| `--scanners` | Which scanners to run |
| `--format` | Output format (console/json/sarif/html) |
| `--output` | Save results to file |
| `--min-severity` | Filter by minimum severity |
| `--ci` | CI mode (exit codes for pipelines) |
| `--fail-on` | Fail if severity >= threshold |
| `--verbose` | Show detailed output |

---

## Troubleshooting

### "No findings" but expected some

```bash
# Check which files were scanned
secureagent scan . --verbose

# Verify scanner is detecting files
secureagent scan . --scanners mcp --verbose
```

### Permission errors with cloud scanning

```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check required permissions
secureagent cloud check-permissions --provider aws
```

### Scan is slow

```bash
# Exclude unnecessary directories
secureagent scan . --ignore-paths "node_modules,venv,.git"

# Or add to config
# .secureagent.yaml
ignore_paths:
  - node_modules/
  - venv/
  - .git/
```

---

## Next Steps

Now that you've run your first scan:

1. **[How It Works](how-it-works.md)** - Understand how SecureAgent protects you
2. **[Scanners Guide](scanners.md)** - Learn about each scanner
3. **[Integrations](integrations.md)** - Set up CI/CD and notifications
4. **[CLI Reference](cli-reference.md)** - Complete command documentation
5. **[Compliance](compliance.md)** - Understand compliance mapping

---

## Getting Help

- **Documentation**: You're reading it!
- **Issues**: [GitHub Issues](https://github.com/IParikh1/secureagent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/IParikh1/secureagent/discussions)

---

<div align="center">

**Ready to secure your AI systems!** 🔒

</div>
