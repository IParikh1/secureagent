# SecureAgent - Comprehensive AI & Cloud Security Platform

**Vision**: The first comprehensive security platform for AI agents and cloud infrastructure, providing visibility, risk assessment, and compliance across the entire AI deployment stack.

**Business Model**: Tiered pricing with capability-based upgrades (Free → Pro → Enterprise)

**Current Version**: v1.1.0 (Released 2026-01-16)

**Overall Progress**: ~99% Complete (Core), 0% Complete (AI-Enhanced Mode)

---

## Dual-Mode Architecture

SecureAgent operates in two distinct modes, allowing users to choose based on their needs:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      SECUREAGENT DUAL-MODE ARCHITECTURE                 │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  MODE 1: STANDARD (Default)              MODE 2: AI-ENHANCED (Opt-in)  │
│  ─────────────────────────               ────────────────────────────  │
│                                                                         │
│  • Rule-based scanning                   • Everything in Standard, plus │
│  • Local ML risk scoring                 • LLM-powered semantic analysis│
│  • Pattern matching                      • Context-aware remediation    │
│  • No external API calls                 • Attack path reasoning        │
│  • Works offline/air-gapped              • Threat intelligence          │
│  • Zero data leaves your machine         • Requires API key or local LLM│
│                                                                         │
│  secureagent scan ./config               secureagent scan ./config --ai │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

                            DATA FLOW COMPARISON

    STANDARD MODE                           AI-ENHANCED MODE
    ─────────────                           ─────────────────

    ┌──────────┐                            ┌──────────┐
    │  Config  │                            │  Config  │
    └────┬─────┘                            └────┬─────┘
         │                                       │
         ▼                                       ▼
    ┌──────────┐                            ┌──────────┐
    │  Rules   │                            │  Rules   │
    │  Engine  │                            │  Engine  │
    └────┬─────┘                            └────┬─────┘
         │                                       │
         ▼                                       ▼
    ┌──────────┐                            ┌──────────┐      ┌──────────┐
    │  Local   │                            │  Local   │ ───► │   LLM    │
    │  ML      │                            │  ML      │      │  (opt)   │
    └────┬─────┘                            └────┬─────┘      └────┬─────┘
         │                                       │                  │
         ▼                                       └────────┬─────────┘
    ┌──────────┐                                          ▼
    │ Findings │                                    ┌──────────┐
    └──────────┘                                    │ Enhanced │
                                                    │ Findings │
         ✓ Offline                                  └──────────┘
         ✓ No data egress
         ✓ Fast                                          ✓ Deeper analysis
                                                         ✓ Fewer false positives
                                                         ✓ Smart remediation
```

### Mode Selection Philosophy

| User Need | Recommended Mode | Why |
|-----------|------------------|-----|
| Air-gapped environment | Standard | No external calls |
| Privacy-sensitive configs | Standard | Data never leaves machine |
| CI/CD pipelines | Standard | Fast, deterministic |
| Deep security analysis | AI-Enhanced | Semantic understanding |
| Context-aware fixes | AI-Enhanced | LLM generates tailored fixes |
| Novel threat detection | AI-Enhanced | LLM identifies new patterns |

---

## Progress Summary

| Phase | Status | Completion |
|-------|--------|------------|
| Phase 1: Core Framework | ✅ Complete | 100% |
| Phase 2: AI Agent Scanners | ✅ Complete | 100% |
| Phase 3: AI Inventory & Discovery | ✅ Complete | 100% |
| Phase 4: Risk & Data Analysis | ✅ Complete | 100% |
| Phase 5: Cloud Scanner Migration | ✅ Complete | 100% |
| Phase 6: Compliance & Reporting | ✅ Complete | 100% |
| Phase 7: Integrations | ✅ Complete | 100% |
| Phase 8: ML & Graph Analysis | ⚡ Near Complete | 95% |
| Phase 9: CI/CD, Docker & Compatibility | ✅ Complete | 100% |
| Phase 10: Testing | ⚡ Near Complete | 90% |
| **Phase 11: AI-Enhanced Mode** | 🔲 Not Started | 0% |

### Key Metrics
- **Python files**: 70+ (core) + ~15 (AI-enhanced, planned)
- **Lines of code**: 10,000+
- **Lines of test code**: 2,500+
- **Tests passing**: 308
- **Scanners**: 9 (MCP, LangChain, OpenAI, AutoGPT, Multi-Agent, RAG, AWS, Azure, Terraform)
- **Security Rules**: 100+ (AI Agents: 70+, Cloud: 30+)
- **Compliance frameworks**: 4 (SOC2, NIST, GDPR, OWASP)
- **Integrations**: 5 (GitHub, GitLab, Slack, Webhooks, SIEM)

---

## Product Capabilities

### Standard Mode (Rule-Based) - SHIPPED

#### 1. AI Agent Security Scanning
- **MCP Scanner** - MCP server configurations (10 rules)
- **LangChain Scanner** - LangChain agent vulnerabilities (10 rules)
- **OpenAI Assistants Scanner** - Function calls, file access, tools (10 rules)
- **AutoGPT/CrewAI Scanner** - Multi-agent framework security (10 rules)
- **Multi-Agent Security Scanner** - Orchestration, communication, delegation (30 rules)
  - Orchestration analysis (LangGraph, AutoGen, CrewAI)
  - Communication channel security
  - Delegation attack detection
  - Framework-specific analyzers
- **RAG Security Scanner** - Vector stores, documents, poisoning (30 rules)
  - Vector store security (Pinecone, Chroma, Weaviate, Qdrant, Milvus, PGVector, Redis, FAISS)
  - Document ingestion security
  - RAG poisoning detection
- **Jailbreak Detection** - Prompt injection and jailbreak attempt detection

#### 2. AI Inventory & Discovery
- **Agent Catalog** - Discover and list all AI agents
- **Model Registry** - Track which LLMs each agent calls
- **Tool Mapping** - Document all tools/connectors per agent
- **Data Source Inventory** - Map read/write data sources

#### 3. Permission & Risk Analysis
- **Action Permission Map** - What each agent can execute
- **ML Risk Scoring** - 93.2% accuracy risk assessment
- **Privilege Analysis** - Identify over-privileged agents
- **Blast Radius Estimation** - Impact if agent compromised

#### 4. Data Exposure & Flow
- **Prompt Data Flow** - What data enters prompts
- **Memory Analysis** - Data in agent memory/context
- **Guardrail Coverage** - Map which guardrails protect what
- **Egress Path Mapping** - Where data can flow out

#### 5. Cloud Security
- **AWS Scanner** - S3, IAM, EC2, Lambda (27+ checks)
- **Azure Scanner** - Storage, KeyVault, Functions
- **Terraform Scanner** - IaC security (11 checks)
- **CloudTrail Detection** - Real-time threat monitoring

#### 6. Compliance & Reporting
- **OWASP LLM Top 10** - Findings mapped to OWASP
- **OWASP MCP Top 10** - MCP-specific risk mapping
- **CWE Mapping** - Common Weakness Enumeration
- **SOC2/PCI-DSS/HIPAA** - Compliance dashboards
- **Audit-Ready Reports** - PDF/HTML exports

#### 7. Integrations
- **GitHub** - Repo scanning, PR comments, issue creation
- **GitLab** - CI/CD integration
- **Slack Bot** - Interactive queries and alerts
- **SARIF Output** - GitHub Code Scanning
- **Webhooks** - Generic event notifications

---

### AI-Enhanced Mode (LLM-Powered) - PLANNED

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    AI-ENHANCED MODE CAPABILITIES                        │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                         FREE TIER (v2.0)                                │
│                                                                         │
│  ┌─────────────────────────────┐    ┌─────────────────────────────┐    │
│  │    SEMANTIC ANALYST         │    │   REMEDIATION GENERATOR     │    │
│  │                             │    │                             │    │
│  │  • Intent analysis          │    │  • Context-aware fixes      │    │
│  │  • False positive reduction │    │  • Multiple fix options     │    │
│  │  • Novel pattern detection  │    │  • Impact analysis          │    │
│  │  • Confidence scoring       │    │  • Schema validation        │    │
│  │                             │    │                             │    │
│  │  Limit: 100 AI scans/month  │    │  Limit: 100 fixes/month     │    │
│  └─────────────────────────────┘    └─────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         PRO TIER ($39/mo) (v2.5)                        │
│                                                                         │
│                    ┌─────────────────────────────┐                      │
│                    │   ATTACK PATH ANALYZER      │                      │
│                    │                             │                      │
│                    │  • Multi-hop chain analysis │                      │
│                    │  • Blast radius estimation  │                      │
│                    │  • MITRE ATT&CK mapping     │                      │
│                    │  • Likelihood scoring       │                      │
│                    │  • Visual attack graphs     │                      │
│                    │                             │                      │
│                    │  Unlimited AI scans         │                      │
│                    └─────────────────────────────┘                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     ENTERPRISE TIER ($499/mo) (v3.0)                    │
│                                                                         │
│  ┌─────────────────────────────┐    ┌─────────────────────────────┐    │
│  │  THREAT INTEL ENRICHER      │    │   CONTINUOUS MONITOR        │    │
│  │                             │    │                             │    │
│  │  • CVE correlation          │    │  • Config drift detection   │    │
│  │  • Exploit database lookup  │    │  • Runtime monitoring       │    │
│  │  • Threat actor tracking    │    │  • Anomaly detection        │    │
│  │  • Emerging threat alerts   │    │  • Compliance tracking      │    │
│  │                             │    │                             │    │
│  └─────────────────────────────┘    └─────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Agent 1: Semantic Vulnerability Analyst (Free Tier)

**Purpose**: Understand *intent* behind MCP configurations, not just pattern-match

| Capability | Description |
|------------|-------------|
| Intent Analysis | Understand what a tool *does*, not just what it's *named* |
| Context Awareness | Evaluate risk based on surrounding configuration |
| Novel Pattern Detection | Identify new attack vectors not in rule database |
| Confidence Scoring | Quantify certainty of findings |
| False Positive Reduction | Filter out benign configurations that trigger rules |

**Specification**:
- Model: Claude Haiku (default) or local Llama 3
- Latency: <3s per finding
- Rate Limit (Free): 100 AI-enhanced scans/month

---

#### Agent 2: Intelligent Remediation Generator (Free Tier)

**Purpose**: Generate context-aware, implementation-ready fixes

| Capability | Description |
|------------|-------------|
| Context-Aware Fixes | Match existing code style/patterns |
| Multiple Options | Security/usability tradeoff alternatives |
| Dependency Analysis | Ensure fixes don't break functionality |
| Validation | Verify generated fixes pass schema |
| Impact Preview | Show what changes before applying |

**Specification**:
- Model: Claude Haiku or local model
- Output: 1-3 fix options with impact analysis
- All fixes validated against JSON schema

---

#### Agent 3: Attack Path Analyzer (Pro Tier)

**Purpose**: Deep analysis of privilege escalation and lateral movement

| Capability | Description |
|------------|-------------|
| Multi-Hop Analysis | Trace attack paths across tool chains |
| Blast Radius Estimation | Worst-case impact assessment |
| MITRE ATT&CK Mapping | Map to known attack techniques |
| Likelihood Scoring | Which paths are most exploitable? |
| Visual Graphs | Mermaid diagrams of attack chains |

**Specification**:
- Model: Claude Sonnet (complex reasoning required)
- Output: Attack chains with visualizations
- Integrates with existing `graph/` module

---

#### Agent 4: Threat Intelligence Enricher (Enterprise Tier)

**Purpose**: Correlate findings with real-world threat data

| Capability | Description |
|------------|-------------|
| CVE Correlation | Match findings to known vulnerabilities |
| Exploit Database | Check for public exploits |
| Threat Actor Tracking | Identify known adversary techniques |
| Emerging Threats | Flag newly disclosed attack patterns |

**Specification**:
- Data Sources: NVD, MITRE ATLAS, GitHub Advisories
- Update Frequency: Daily sync
- Requires: Vector DB infrastructure (optional)

---

#### Agent 5: Continuous Security Monitor (Enterprise Tier)

**Purpose**: Real-time security posture monitoring

| Capability | Description |
|------------|-------------|
| Config Drift Detection | Alert on changes from secure baseline |
| Runtime Monitoring | Track actual MCP traffic (via proxy) |
| Anomaly Detection | Identify unusual patterns |
| Compliance Tracking | Maintain posture over time |

**Specification**:
- Deployment: Background daemon/service
- Alerts: Webhook, email, Slack integrations
- Requires: All other agents as foundation

---

## Architecture

**Approach**: Monorepo with plugin-style scanner architecture
- Single CLI (Typer-based)
- Pluggable, self-registering scanner modules
- Lazy-loaded cloud SDKs (optional dependencies)
- Unified Finding model for all scanner types
- **AI agents as optional enhancement layer**

---

## Project Structure

```
secureagent/
├── pyproject.toml
├── src/secureagent/
│   ├── __init__.py
│   ├── __main__.py
│   │
│   ├── cli/                              # CLI Interface
│   │   ├── app.py                        # Main Typer app
│   │   ├── scan_commands.py              # Universal scan command
│   │   ├── mcp_commands.py               # MCP subcommands
│   │   ├── cloud_commands.py             # Cloud subcommands
│   │   ├── inventory_commands.py         # Inventory commands
│   │   ├── compliance_commands.py        # Compliance reports
│   │   ├── ai_commands.py                # AI-enhanced commands (NEW)
│   │   └── compat.py                     # Backward compatibility
│   │
│   ├── core/                             # Core Framework
│   │   ├── config.py                     # Unified configuration
│   │   ├── models/
│   │   │   ├── finding.py                # Unified Finding model
│   │   │   ├── severity.py               # Severity enum
│   │   │   ├── agent.py                  # Agent model
│   │   │   ├── data_flow.py              # Data flow models
│   │   │   └── ai_enhancement.py         # AI enhancement models (NEW)
│   │   ├── scanner/
│   │   │   ├── base.py                   # BaseScanner ABC
│   │   │   └── registry.py               # Scanner plugin registry
│   │   ├── reporters/
│   │   │   ├── console.py                # Rich console output
│   │   │   ├── json_reporter.py          # JSON output
│   │   │   ├── sarif.py                  # SARIF for CI/CD
│   │   │   └── html_reporter.py          # HTML reports
│   │   └── alerting/
│   │       ├── manager.py                # AlertManager
│   │       ├── sns.py                    # AWS SNS
│   │       ├── slack.py                  # Slack webhooks
│   │       └── webhook.py                # Generic webhooks
│   │
│   ├── scanners/                         # Security Scanners (Rule-Based)
│   │   ├── mcp/                          # MCP configs
│   │   │   ├── scanner.py
│   │   │   ├── rules.py
│   │   │   └── models.py
│   │   ├── langchain/                    # LangChain agents
│   │   │   ├── scanner.py
│   │   │   ├── rules.py
│   │   │   └── models.py
│   │   ├── openai_assistants/            # OpenAI Assistants
│   │   │   ├── scanner.py
│   │   │   ├── rules.py
│   │   │   └── models.py
│   │   ├── autogpt/                      # AutoGPT/CrewAI
│   │   │   ├── scanner.py
│   │   │   └── rules.py
│   │   ├── aws/                          # AWS cloud
│   │   │   ├── scanner.py
│   │   │   ├── s3_checks.py
│   │   │   ├── iam_checks.py
│   │   │   └── ec2_checks.py
│   │   ├── azure/                        # Azure cloud
│   │   │   ├── scanner.py
│   │   │   └── storage_checks.py
│   │   └── terraform/                    # Terraform IaC
│   │       ├── scanner.py
│   │       └── checks.py
│   │
│   ├── ai_agents/                        # AI-Enhanced Mode (NEW)
│   │   ├── __init__.py
│   │   ├── base.py                       # BaseAIAgent ABC
│   │   ├── registry.py                   # AI agent registry
│   │   ├── provider/                     # LLM Provider Abstraction
│   │   │   ├── __init__.py
│   │   │   ├── base.py                   # BaseLLMProvider ABC
│   │   │   ├── claude.py                 # Anthropic Claude
│   │   │   ├── openai.py                 # OpenAI GPT
│   │   │   └── local.py                  # Local models (Ollama/Llama)
│   │   ├── semantic_analyst/             # Agent 1: Semantic Analysis
│   │   │   ├── __init__.py
│   │   │   ├── agent.py                  # Main agent logic
│   │   │   ├── prompts.py                # Prompt templates
│   │   │   └── schemas.py                # Output schemas
│   │   ├── remediation_generator/        # Agent 2: Fix Generation
│   │   │   ├── __init__.py
│   │   │   ├── agent.py
│   │   │   ├── prompts.py
│   │   │   ├── validator.py              # Fix validation
│   │   │   └── schemas.py
│   │   ├── attack_path_analyzer/         # Agent 3: Attack Paths (Pro)
│   │   │   ├── __init__.py
│   │   │   ├── agent.py
│   │   │   ├── prompts.py
│   │   │   └── visualizer.py             # Mermaid generation
│   │   ├── threat_intel_enricher/        # Agent 4: Threat Intel (Enterprise)
│   │   │   ├── __init__.py
│   │   │   ├── agent.py
│   │   │   ├── sources/                  # Data source connectors
│   │   │   │   ├── nvd.py
│   │   │   │   ├── mitre.py
│   │   │   │   └── github_advisories.py
│   │   │   └── cache.py                  # Threat data cache
│   │   └── continuous_monitor/           # Agent 5: Monitoring (Enterprise)
│   │       ├── __init__.py
│   │       ├── agent.py
│   │       ├── drift_detector.py
│   │       └── daemon.py                 # Background service
│   │
│   ├── inventory/                        # AI Inventory & Discovery
│   │   ├── __init__.py
│   │   ├── discovery.py                  # Agent auto-discovery
│   │   ├── catalog.py                    # Agent catalog management
│   │   ├── models_registry.py            # LLM model tracking
│   │   ├── tools_registry.py             # Tool/connector registry
│   │   └── data_sources.py               # Data source mapping
│   │
│   ├── analysis/                         # Risk & Data Analysis
│   │   ├── __init__.py
│   │   ├── permissions.py                # Permission mapping
│   │   ├── risk_analyzer.py              # Risk analysis engine
│   │   ├── data_flow.py                  # Data flow tracing
│   │   ├── guardrails.py                 # Guardrail coverage
│   │   ├── egress.py                     # Egress path detection
│   │   └── prompt_analysis.py            # Prompt data exposure
│   │
│   ├── compliance/                       # Compliance & Reporting
│   │   ├── __init__.py
│   │   ├── frameworks/
│   │   │   ├── owasp_llm.py              # OWASP LLM Top 10
│   │   │   ├── owasp_mcp.py              # OWASP MCP Top 10
│   │   │   ├── soc2.py                   # SOC2 controls
│   │   │   ├── pci_dss.py                # PCI-DSS mapping
│   │   │   └── hipaa.py                  # HIPAA controls
│   │   ├── mapper.py                     # Finding-to-control mapper
│   │   └── report_generator.py           # Compliance reports
│   │
│   ├── integrations/                     # External Integrations
│   │   ├── __init__.py
│   │   ├── github/
│   │   │   ├── scanner.py                # Repo scanning
│   │   │   ├── pr_comments.py            # PR comment posting
│   │   │   └── issues.py                 # Issue creation
│   │   ├── gitlab/
│   │   │   └── integration.py
│   │   ├── slack/
│   │   │   ├── bot.py                    # Slack bot
│   │   │   └── commands.py               # Slash commands
│   │   └── webhooks/
│   │       └── dispatcher.py             # Webhook notifications
│   │
│   ├── detectors/                        # Real-time Detection
│   │   ├── __init__.py
│   │   └── cloudtrail.py                 # CloudTrail threat detection
│   │
│   ├── ml/                               # Machine Learning (Local)
│   │   ├── __init__.py
│   │   ├── models.py                     # Ensemble model
│   │   ├── features/
│   │   │   ├── base.py
│   │   │   ├── mcp_features.py
│   │   │   ├── cloud_features.py
│   │   │   └── agent_features.py         # Agent-specific features
│   │   ├── risk_scorer.py                # Unified risk scoring
│   │   └── trainer.py                    # Model training
│   │
│   ├── graph/                            # Capability Graph
│   │   ├── __init__.py
│   │   ├── models.py                     # Graph data models
│   │   ├── analyzer.py                   # Graph analysis
│   │   ├── cloud_extension.py            # Cloud resource nodes
│   │   └── visualizer.py                 # Graph visualization
│   │
│   └── remediation/                      # Auto-Remediation
│       ├── __init__.py
│       ├── generator.py                  # Rule-based fix generation
│       └── fixer.py                      # Apply fixes
│
├── models/                               # Pre-trained ML models
│   └── secureagent_risk_v1.pkl
│
├── tests/
│   ├── conftest.py
│   ├── core/
│   ├── scanners/
│   ├── inventory/
│   ├── analysis/
│   ├── compliance/
│   ├── integrations/
│   ├── ml/
│   └── ai_agents/                        # AI agent tests (NEW)
│
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── docs/
│   ├── getting-started.md
│   ├── cli-reference.md
│   ├── integrations.md
│   ├── compliance-frameworks.md
│   └── ai-enhanced-mode.md               # AI mode documentation (NEW)
│
├── examples/
│   ├── github-action.yml
│   ├── gitlab-ci.yml
│   └── slack-bot-setup.md
│
└── .github/workflows/
    ├── ci.yml
    └── release.yml
```

---

## Core Data Models

### Unified Finding Model
```python
class Finding(BaseModel):
    id: str                           # Unique ID
    rule_id: str                      # e.g., "MCP-001", "AWS-S3-001", "LC-001"
    domain: FindingDomain             # mcp, langchain, openai, aws, azure, terraform
    title: str
    description: str
    severity: Severity                # CRITICAL, HIGH, MEDIUM, LOW, INFO
    location: Location                # File path OR cloud resource
    remediation: str
    cwe_id: Optional[str]
    owasp_id: Optional[str]           # OWASP LLM Top 10 mapping
    risk_score: Optional[float]       # ML-calculated (0.0-1.0)
    compliance_mappings: List[str]    # ["SOC2-CC6.1", "PCI-DSS-6.5.1"]
    metadata: Dict[str, Any]

    # AI-Enhanced fields (populated when --ai flag used)
    ai_analysis: Optional[AIAnalysis]           # Semantic analysis results
    ai_remediation: Optional[AIRemediation]     # Generated fixes
    ai_confidence: Optional[float]              # AI confidence score
```

### AI Enhancement Models (NEW)
```python
class AIAnalysis(BaseModel):
    """Results from Semantic Analyst agent"""
    intent: str                       # What the config is trying to do
    risk_rationale: str               # Why this is/isn't risky
    false_positive_likelihood: float  # 0.0-1.0
    novel_patterns: List[str]         # Patterns not in rule database
    context_factors: List[str]        # Surrounding config that affects risk
    confidence: float                 # 0.0-1.0

class AIRemediation(BaseModel):
    """Results from Remediation Generator agent"""
    options: List[RemediationOption]  # 1-3 fix options
    recommended: int                  # Index of recommended option
    validation_passed: bool           # Schema validation result

class RemediationOption(BaseModel):
    title: str                        # e.g., "Conservative Fix"
    description: str                  # What this fix does
    fix_content: str                  # The actual fix (JSON/YAML)
    security_impact: str              # How it improves security
    usability_impact: str             # Any usability tradeoffs
    breaking_changes: List[str]       # What might break

class AttackPath(BaseModel):
    """Results from Attack Path Analyzer agent"""
    chain: List[AttackStep]           # Sequence of attack steps
    entry_point: str                  # Where attack starts
    target: str                       # What attacker wants
    likelihood: float                 # 0.0-1.0
    blast_radius: str                 # Impact description
    mitre_techniques: List[str]       # MITRE ATT&CK IDs
    mermaid_diagram: str              # Visual representation
```

### Agent Inventory Model
```python
class AgentInventoryItem(BaseModel):
    id: str                           # Unique agent ID
    name: str                         # Agent name
    framework: AgentFramework         # mcp, langchain, openai_assistants, autogpt, crewai
    models: List[ModelReference]      # LLMs this agent calls
    tools: List[ToolReference]        # Tools/connectors available
    data_sources: List[DataSource]    # Read/write data sources
    permissions: List[Permission]     # Actions agent can execute
    guardrails: List[Guardrail]       # Configured guardrails
    egress_paths: List[EgressPath]    # Where data can flow out
    risk_score: float                 # Overall risk score
    discovered_at: datetime
    config_path: Optional[str]        # Path to config file
```

### Data Flow Model
```python
class DataFlow(BaseModel):
    source: DataEndpoint              # Where data comes from
    destination: DataEndpoint         # Where data goes to
    data_types: List[DataType]        # PII, credentials, etc.
    flow_type: FlowType               # prompt_input, memory, output, tool_call
    guardrails: List[str]             # Guardrails protecting this flow
    risk_level: Severity              # Risk level of this flow
```

---

## CLI Command Structure

```
secureagent
├── scan <target>                     # Universal scan command
│   ├── --scanners <mcp,langchain,openai,aws,terraform,all>
│   ├── --format <console|json|sarif|html>
│   ├── --output <path>
│   ├── --min-severity <critical|high|medium|low>
│   ├── --compliance <owasp|soc2|pci|hipaa>
│   ├── --ci                          # CI mode with exit codes
│   │
│   │   # AI-Enhanced Mode flags (NEW)
│   ├── --ai                          # Enable AI-enhanced analysis
│   ├── --no-ai                       # Explicitly disable (default)
│   ├── --ai-provider <claude|openai|local>
│   ├── --ai-model <model-name>       # e.g., "haiku", "gpt-4", "llama3"
│   └── --ai-fix                      # Generate AI remediation options
│
├── ai                                # AI-specific commands (NEW)
│   ├── analyze <finding-id>          # Deep analysis of specific finding
│   ├── fix <finding-id>              # Generate fix options
│   ├── attack-paths <target>         # Analyze attack paths (Pro)
│   ├── enrich <target>               # Threat intel enrichment (Enterprise)
│   ├── status                        # AI usage/quota status
│   └── config                        # Configure AI providers
│
├── inventory                         # AI Agent Inventory
│   ├── discover                      # Auto-discover agents
│   ├── list                          # List all agents
│   ├── show <agent-id>               # Show agent details
│   ├── export                        # Export inventory
│   └── sync                          # Sync with catalog
│
├── analyze                           # Risk & Data Analysis
│   ├── permissions <agent-id>        # Show permission map
│   ├── data-flow <agent-id>          # Trace data flows
│   ├── guardrails <agent-id>         # Check guardrail coverage
│   ├── egress <agent-id>             # Map egress paths
│   └── risk <agent-id|path>          # ML risk scoring
│
├── compliance                        # Compliance Reporting
│   ├── report <framework>            # Generate compliance report
│   ├── status                        # Compliance status overview
│   ├── gaps                          # Show compliance gaps
│   └── export <format>               # Export report (pdf|html|json)
│
├── mcp                               # MCP-specific commands
│   ├── scan <path>
│   ├── validate <path>
│   ├── fix <path>
│   ├── fix <path> --ai               # AI-generated fixes (NEW)
│   └── rules
│
├── cloud                             # Cloud scanning
│   ├── scan --provider <aws|azure|all>
│   ├── aws [s3|iam|ec2]
│   └── azure [storage]
│
├── iac                               # Infrastructure-as-Code
│   └── scan <path> --type <terraform>
│
├── github                            # GitHub integration
│   ├── scan <repo>                   # Scan repository
│   ├── setup                         # Configure GitHub App
│   └── status                        # Check integration status
│
├── slack                             # Slack bot
│   ├── setup                         # Configure Slack bot
│   ├── test                          # Test connection
│   └── status                        # Bot status
│
├── monitor                           # Continuous monitoring (Enterprise, NEW)
│   ├── start                         # Start monitoring daemon
│   ├── stop                          # Stop monitoring
│   ├── status                        # Monitoring status
│   └── alerts                        # View recent alerts
│
└── ml                                # ML model management
    ├── train
    ├── validate
    └── info
```

---

## CLI Usage Examples

### Standard Mode (Default - No LLM)

```bash
# Basic scanning - rule-based, no external calls
secureagent scan ./mcp.json
secureagent scan ./configs/ --scanners mcp,langchain
secureagent scan . --format sarif --output results.sarif

# Inventory and analysis
secureagent inventory discover ./project
secureagent analyze risk ./mcp.json
secureagent analyze data-flow agent-123

# Compliance reporting
secureagent compliance report owasp-llm
secureagent compliance gaps --format html

# CI/CD usage
secureagent scan . --ci --min-severity high
```

### AI-Enhanced Mode (Opt-in - Uses LLM)

```bash
# Enable AI analysis
secureagent scan ./mcp.json --ai
secureagent scan ./mcp.json --ai --ai-provider local  # Use local Llama

# Generate AI fixes
secureagent scan ./mcp.json --ai --ai-fix
secureagent mcp fix ./mcp.json --ai

# Deep analysis of specific finding
secureagent ai analyze finding-abc123

# Attack path analysis (Pro tier)
secureagent ai attack-paths ./mcp.json

# Threat enrichment (Enterprise tier)
secureagent ai enrich ./mcp.json

# Continuous monitoring (Enterprise tier)
secureagent monitor start ./configs/
secureagent monitor status
```

### Environment Variables

```bash
# AI Provider Configuration
export SECUREAGENT_AI_PROVIDER=claude          # claude, openai, local
export SECUREAGENT_AI_MODEL=haiku              # Model to use
export ANTHROPIC_API_KEY=sk-ant-...            # For Claude
export OPENAI_API_KEY=sk-...                   # For OpenAI
export SECUREAGENT_LOCAL_MODEL_URL=http://localhost:11434  # For Ollama

# Disable AI globally (for air-gapped environments)
export SECUREAGENT_AI_DISABLED=true
```

---

## Implementation Phases

### Phase 1: Core Framework (15 files) - ✅ 100% COMPLETE
- [x] Create project structure and pyproject.toml
- [x] Implement unified Finding model (`core/models/finding.py`)
- [x] Implement Agent model (`core/models/agent.py`)
- [x] Implement Data Flow model (`core/models/data_flow.py`)
- [x] Implement Severity enum (`core/models/severity.py`)
- [x] Implement BaseScanner ABC (`core/scanner/base.py`)
- [x] Implement scanner registry (`core/scanner/registry.py`)
- [x] Set up Typer CLI framework (`cli/app.py`)
- [x] Implement unified config (`core/config.py`)

### Phase 2: AI Agent Scanners (12 files) - ✅ 100% COMPLETE
- [x] Migrate MCP scanner from `/tmp/mcpscan/mcpscan/scanner/mcp/scanner.py`
- [x] Port MCP security rules from `/tmp/mcpscan/mcpscan/scanner/mcp/rules.py`
- [x] Create LangChain scanner (`scanners/langchain/scanner.py`)
- [x] Create LangChain rules (`scanners/langchain/rules.py`)
- [x] Create OpenAI Assistants scanner (`scanners/openai_assistants/scanner.py`)
- [x] Create OpenAI Assistants rules (`scanners/openai_assistants/rules.py`)
- [x] Create AutoGPT/CrewAI scanner (`scanners/autogpt/scanner.py`)
- [x] Implement MCP CLI commands

### Phase 3: AI Inventory & Discovery (6 files) - ✅ 100% COMPLETE
- [x] Implement agent discovery (`inventory/discovery.py`)
- [x] Implement agent catalog (`inventory/catalog.py`)
- [x] Implement model registry (`inventory/models_registry.py`)
- [x] Implement tools registry (`inventory/tools_registry.py`)
- [x] Implement data source mapping (`inventory/data_sources.py`)
- [x] Implement inventory CLI commands

### Phase 4: Risk & Data Analysis (7 files) - ✅ 100% COMPLETE
- [x] Implement permission mapper (`analysis/permissions.py`)
- [x] Implement risk analyzer (`analysis/risk_analyzer.py`)
- [x] Implement data flow tracer (`analysis/data_flow.py`)
- [x] Implement guardrail checker (`analysis/guardrails.py`)
- [x] Implement egress path detector (`analysis/egress.py`)
- [x] Implement prompt analyzer (`analysis/prompt_analysis.py`)
- [x] Implement analyze CLI commands

### Phase 5: Cloud Scanner Migration (10 files) - ✅ 100% COMPLETE
- [x] Migrate AWS scanner from `/tmp/cybermonitor/cybermonitor/scanners/aws_scanner.py`
- [x] Migrate Azure scanner from `/tmp/cybermonitor/cybermonitor/scanners/azure_scanner.py`
- [x] Migrate Terraform scanner from `/tmp/cybermonitor/cybermonitor/scanners/terraform_scanner.py`
- [x] Port CloudTrail detector from `/tmp/cybermonitor/cybermonitor/detectors/cloudtrail_detector.py`
- [x] Implement cloud CLI commands
- [x] Implement IaC CLI commands

### Phase 6: Compliance & Reporting (10 files) - ✅ 100% COMPLETE
- [x] Implement OWASP LLM Top 10 framework (`compliance/frameworks/owasp_llm.py`)
- [x] Implement OWASP MCP Top 10 framework (`compliance/frameworks/owasp_mcp.py`)
- [x] Implement SOC2 controls (`compliance/frameworks/soc2.py`)
- [x] Implement PCI-DSS mapping (`compliance/frameworks/pci_dss.py`)
- [x] Implement HIPAA controls (`compliance/frameworks/hipaa.py`)
- [x] Implement finding-to-control mapper (`compliance/mapper.py`)
- [x] Implement report generator (`compliance/report_generator.py`)
- [x] Migrate Rich console reporter from mcpscan
- [x] Migrate JSON/SARIF/HTML reporters
- [x] Implement compliance CLI commands

### Phase 7: Integrations (10 files) - ✅ 100% COMPLETE
- [x] Implement GitHub repo scanner (`integrations/github/scanner.py`)
- [x] Implement PR comment posting (`integrations/github/pr_comments.py`)
- [x] Implement issue creation (`integrations/github/issues.py`)
- [x] Implement GitLab integration (`integrations/gitlab/integration.py`)
- [x] Implement Slack bot (`integrations/slack/bot.py`)
- [x] Implement Slack slash commands (`integrations/slack/commands.py`)
- [x] Implement webhook dispatcher (`integrations/webhooks/dispatcher.py`)
- [x] Port AlertManager from CyberMonitor
- [x] Port SNS and Slack alerters
- [x] Implement integration CLI commands

### Phase 8: ML & Graph Analysis (10 files) - ⚡ 95% COMPLETE
- [x] Migrate EnsembleModel from `/tmp/mcpscan/mcpscan/ml/models.py`
- [x] Migrate RiskScorer from `/tmp/mcpscan/mcpscan/ml/risk_scorer.py`
- [x] Port MCP feature extractor (`ml/features/mcp_features.py`)
- [x] Create cloud feature extractor (`ml/features/cloud_features.py`)
- [x] Create agent feature extractor (`ml/features/agent_features.py`)
- [x] Migrate graph analyzer from mcpscan
- [x] Extend graph for cloud resources (`graph/cloud_extension.py`)
- [x] Implement graph visualizer (`graph/visualizer.py`)
- [x] Implement ML CLI commands
- [ ] Train unified model (feature extraction done, training pipeline not complete)

### Phase 9: CI/CD, Docker & Compatibility (8 files) - ✅ 100% COMPLETE
- [x] Create multi-stage Dockerfile
- [x] Create docker-compose.yml
- [x] Create GitHub Actions CI workflow
- [x] Create GitHub Actions release workflow
- [x] Create example GitHub Action for users
- [x] Create example GitLab CI for users
- [x] Implement backward compatibility wrappers (`cli/compat.py`)
- [x] Write documentation

### Phase 10: Testing (10+ files) - ⚡ 90% COMPLETE
- [x] Write core model tests
- [x] Write scanner tests (all frameworks)
- [x] Write inventory tests
- [x] Write analysis tests
- [x] Write compliance tests
- [x] Write integration tests
- [x] Write ML tests
- [x] Write CLI integration tests
- [x] Write end-to-end tests (basic flow)
- [ ] Write performance tests (not implemented)

### Phase 11: AI-Enhanced Mode (15 files) - 🔲 NOT STARTED

**Phase 11a: Foundation (Days 1-3)**
- [ ] Implement LLM provider abstraction (`ai_agents/provider/base.py`)
- [ ] Implement Claude provider (`ai_agents/provider/claude.py`)
- [ ] Implement OpenAI provider (`ai_agents/provider/openai.py`)
- [ ] Implement local model provider (`ai_agents/provider/local.py`)
- [ ] Implement async processing pipeline
- [ ] Implement rate limiting with tier awareness
- [ ] Implement BaseAIAgent ABC (`ai_agents/base.py`)
- [ ] Implement AI agent registry (`ai_agents/registry.py`)
- [ ] Add AI enhancement fields to Finding model

**Phase 11b: Semantic Analyst (Days 4-8)**
- [ ] Implement Semantic Analyst agent (`ai_agents/semantic_analyst/agent.py`)
- [ ] Create prompt templates (`ai_agents/semantic_analyst/prompts.py`)
- [ ] Define output schemas (`ai_agents/semantic_analyst/schemas.py`)
- [ ] Implement confidence scoring
- [ ] Integrate with existing scanners
- [ ] Add `--ai` flag to scan command

**Phase 11c: Remediation Generator (Days 9-12)**
- [ ] Implement Remediation Generator agent (`ai_agents/remediation_generator/agent.py`)
- [ ] Create fix generation prompts (`ai_agents/remediation_generator/prompts.py`)
- [ ] Implement fix validator (`ai_agents/remediation_generator/validator.py`)
- [ ] Generate multiple fix options with tradeoffs
- [ ] Add `--ai-fix` flag to commands

**Phase 11d: Attack Path Analyzer - Pro (Days 13-16)**
- [ ] Implement Attack Path Analyzer (`ai_agents/attack_path_analyzer/agent.py`)
- [ ] Create attack chain prompts
- [ ] Implement MITRE ATT&CK mapping
- [ ] Implement Mermaid diagram generation
- [ ] Integrate with existing graph module
- [ ] Add tier verification for Pro features

**Phase 11e: Enterprise Agents (Days 17-24)**
- [ ] Implement Threat Intel Enricher (`ai_agents/threat_intel_enricher/agent.py`)
- [ ] Implement NVD connector (`ai_agents/threat_intel_enricher/sources/nvd.py`)
- [ ] Implement MITRE connector
- [ ] Implement Continuous Monitor daemon (`ai_agents/continuous_monitor/daemon.py`)
- [ ] Implement drift detection
- [ ] Add `secureagent monitor` commands

**Phase 11f: Testing & Polish (Days 25-30)**
- [ ] Write AI agent unit tests
- [ ] Write integration tests for AI mode
- [ ] Write prompt quality benchmarks
- [ ] Documentation for AI-enhanced mode
- [ ] Beta testing with select users

---

## Tiered Release Roadmap

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         RELEASE TIMELINE                                │
└─────────────────────────────────────────────────────────────────────────┘

v1.0.2 (CURRENT) ──────────────────────────────────────────────────────────
│  ✅ Standard Mode complete
│  ✅ Rule-based scanning
│  ✅ Local ML risk scoring
│  ✅ All integrations
│
│  3.5-5 weeks (DevTeam accelerated)
│                    │
v2.0 ─────────────────┴────────────────────────────────────────────────────
│  🔲 AI-Enhanced Mode (Free tier)
│  🔲 Semantic Analyst agent
│  🔲 Remediation Generator agent
│  🔲 100 AI scans/month free
│
│  +3 weeks
│                    │
v2.5 ─────────────────┴────────────────────────────────────────────────────
│  🔲 Pro tier launch ($39/mo)
│  🔲 Attack Path Analyzer agent
│  🔲 Unlimited AI scans
│  🔲 Visual attack graphs
│
│  +6 weeks
│                    │
v3.0 ─────────────────┴────────────────────────────────────────────────────
│  🔲 Enterprise tier launch ($499/mo)
│  🔲 Threat Intelligence Enricher
│  🔲 Continuous Security Monitor
│  🔲 Real-time drift detection
│
└──────────────────────────────────────────────────────────────────────────
```

---

## Pricing Tiers

| Feature | Free | Pro ($39/mo) | Enterprise ($499/mo) |
|---------|------|--------------|----------------------|
| **Standard Mode** | | | |
| Rule-based scanning | ✓ Unlimited | ✓ Unlimited | ✓ Unlimited |
| ML risk scoring | ✓ | ✓ | ✓ |
| All 7 scanners | ✓ | ✓ | ✓ |
| CI/CD integration | ✓ | ✓ | ✓ |
| SARIF output | ✓ | ✓ | ✓ |
| Compliance reports | Basic | Full | Full |
| **AI-Enhanced Mode** | | | |
| Semantic Analyst | 100/mo | Unlimited | Unlimited |
| Remediation Generator | 100/mo | Unlimited | Unlimited |
| Attack Path Analyzer | - | ✓ | ✓ |
| Threat Intelligence | - | - | ✓ |
| Continuous Monitoring | - | - | ✓ |
| **Support** | | | |
| Community support | ✓ | ✓ | ✓ |
| Priority support | - | ✓ | ✓ |
| Dedicated support | - | - | ✓ |
| SLA | - | - | 99.9% |

---

## Technical Considerations

### Model Selection by Tier

| Tier | Default Model | Fallback | Why |
|------|---------------|----------|-----|
| Free | Claude Haiku | Local Llama 3 | Cost-efficient |
| Pro | Claude Sonnet | Claude Haiku | Better reasoning |
| Enterprise | Claude Opus | Claude Sonnet | Best quality |

### Cost Controls

| Control | Implementation |
|---------|----------------|
| Rate limits | Per-tier monthly quotas |
| Caching | Cache identical config analyses |
| Batching | Batch multiple findings per API call |
| Local fallback | Ollama/Llama for cost-sensitive users |

### Security (AI Mode)

| Concern | Mitigation |
|---------|------------|
| Data privacy | Redact secrets before API calls |
| Prompt injection | Structured output schemas |
| Hallucination | Confidence scores + human review |
| API key exposure | Env vars, not config files |

### Air-Gapped Support

```bash
# For environments without external access
export SECUREAGENT_AI_DISABLED=true    # Disable AI entirely
# OR
export SECUREAGENT_AI_PROVIDER=local   # Use local Ollama
export SECUREAGENT_LOCAL_MODEL_URL=http://internal-ollama:11434
```

---

## Dependencies (pyproject.toml)

```toml
[tool.poetry.dependencies]
python = "^3.9"

# Core (always installed)
typer = ">=0.9.0,<0.12.0"
click = ">=8.0.0,<8.2.0"
rich = "^13.7.0"
pydantic = "^2.5.0"
pyyaml = "^6.0.1"
httpx = "^0.25.0"                      # HTTP client for integrations

# Optional: Cloud providers
boto3 = { version = "^1.26.0", optional = true }
azure-identity = { version = "^1.12.0", optional = true }
azure-mgmt-storage = { version = "^21.0.0", optional = true }

# Optional: IaC scanning
python-hcl2 = { version = "^4.3.0", optional = true }

# Optional: ML features (local)
numpy = { version = "^1.24.0", optional = true }
scikit-learn = { version = "^1.3.0", optional = true }

# Optional: AI framework scanning
langchain-core = { version = "^0.1.0", optional = true }
openai = { version = "^1.0.0", optional = true }

# Optional: Integrations
slack-sdk = { version = "^3.23.0", optional = true }
pygithub = { version = "^2.1.0", optional = true }

# Optional: Reporting
jinja2 = { version = "^3.1.0", optional = true }
weasyprint = { version = "^60.0", optional = true }  # PDF generation

# Optional: AI-Enhanced Mode (NEW)
anthropic = { version = "^0.18.0", optional = true }  # Claude API

[tool.poetry.extras]
aws = ["boto3"]
azure = ["azure-identity", "azure-mgmt-storage"]
iac = ["python-hcl2"]
ml = ["numpy", "scikit-learn"]
langchain = ["langchain-core"]
openai = ["openai"]
slack = ["slack-sdk"]
github = ["pygithub"]
reports = ["jinja2", "weasyprint"]
ai = ["anthropic", "openai"]           # AI-Enhanced Mode (NEW)
full = [
    "boto3", "azure-identity", "azure-mgmt-storage",
    "python-hcl2", "numpy", "scikit-learn",
    "langchain-core", "openai", "slack-sdk", "pygithub",
    "jinja2", "weasyprint", "anthropic"
]

[tool.poetry.scripts]
secureagent = "secureagent.cli.app:app"
mcpscan = "secureagent.cli.compat:mcpscan_main"
cybermonitor = "secureagent.cli.compat:cybermonitor_main"
```

---

## Decisions

| Decision | Choice |
|----------|--------|
| **Project Location** | `~/secureagent` (new repository) |
| **Backward Compatibility** | Yes - keep `mcpscan` and `cybermonitor` as CLI wrappers |
| **Feature Scope** | Full integration - all scanners, inventory, analysis, compliance, integrations |
| **AI Frameworks** | MCP, LangChain, OpenAI Assistants, AutoGPT/CrewAI |
| **Business Model** | Tiered pricing (capability-based) |
| **Implementation Approach** | Full build - complete implementation, review at end |
| **AI Mode** | Opt-in only, standard mode is default |
| **LLM Provider** | Multi-provider support (Claude, OpenAI, local) |
| **Air-Gap Support** | Yes - standard mode works fully offline |

---

## Releases

| Version | Date | Highlights |
|---------|------|------------|
| v1.0.0 | 2026-01-08 | Initial release with all core features |
| v1.0.1 | 2026-01-08 | CI/CD fixes, Typer/Click version pinning |
| v1.0.2 | 2026-01-09 | Fixed MCP scanner "not available" error |
| v2.0.0 | TBD | AI-Enhanced Mode (Free tier agents) |
| v2.5.0 | TBD | Pro tier (Attack Path Analyzer) |
| v3.0.0 | TBD | Enterprise tier (Threat Intel, Monitoring) |

---

## Success Metrics

### Product Metrics

| Metric | Target | Timeline |
|--------|--------|----------|
| Standard mode users | 500+ | Week 4 post-launch |
| AI mode adoption | 30% of users | Week 8 post-v2.0 |
| Pro subscribers | 50+ | Week 12 post-v2.5 |
| Enterprise customers | 5+ | Week 16 post-v3.0 |

### Quality Metrics

| Agent | Metric | Target |
|-------|--------|--------|
| Semantic Analyst | False positive reduction | >50% |
| Remediation Generator | Fix adoption rate | >70% |
| Attack Path Analyzer | Critical paths identified | 100% |

---

## Conclusion

**SecureAgent v1.0.2 is production-ready** with complete Standard Mode functionality:
- All 7 scanner types working (audits LLMs without using LLMs)
- Complete inventory system
- Risk analysis engine with 93.2% accuracy ML model
- 4 compliance frameworks
- 5 integrations (GitHub, GitLab, Slack, Webhooks, SIEM)
- CI/CD with Docker images published to ghcr.io
- 227 tests passing
- Works fully offline/air-gapped

**AI-Enhanced Mode (Phase 11)** is the next major milestone:
- Adds LLM-powered semantic analysis as opt-in enhancement
- Maintains full backward compatibility
- Users choose: fast/offline (Standard) or deep/intelligent (AI-Enhanced)
- Tiered pricing enables sustainable business model

The dual-mode architecture ensures SecureAgent serves both:
1. **Privacy-conscious users** who want to audit LLMs without using LLMs
2. **Power users** who want LLM-enhanced security intelligence

---

*Document Version: 3.0 (Dual-Mode Architecture)*
*January 2026*
