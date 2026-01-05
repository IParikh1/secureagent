# SecureAgent Architecture

This document provides a technical deep-dive into SecureAgent's architecture, designed for developers and security engineers who want to understand how the system works internally.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Core Components](#core-components)
3. [Data Flow](#data-flow)
4. [Scanner Architecture](#scanner-architecture)
5. [Analysis Engine](#analysis-engine)
6. [ML Pipeline](#ml-pipeline)
7. [Plugin System](#plugin-system)

---

## System Overview

SecureAgent is built as a modular, plugin-based architecture that allows for easy extension and customization.

```mermaid
graph TB
    subgraph "User Interface Layer"
        CLI[CLI Interface]
        API[REST API]
        SDK[Python SDK]
    end

    subgraph "Core Engine"
        ORCH[Orchestrator]
        REG[Scanner Registry]
        CONFIG[Config Manager]
    end

    subgraph "Scanners"
        MCP[MCP Scanner]
        LC[LangChain Scanner]
        OAI[OpenAI Scanner]
        AWS[AWS Scanner]
        AZURE[Azure Scanner]
        TF[Terraform Scanner]
    end

    subgraph "Analysis Layer"
        RISK[Risk Analyzer]
        PERM[Permission Mapper]
        GRAPH[Capability Graph]
        FLOW[Data Flow Tracer]
    end

    subgraph "Output Layer"
        REPORT[Reporters]
        ALERT[Alerting]
        COMPLY[Compliance Mapper]
    end

    subgraph "ML Layer"
        FEAT[Feature Extraction]
        MODEL[Risk Models]
        SCORE[Risk Scorer]
    end

    CLI --> ORCH
    API --> ORCH
    SDK --> ORCH

    ORCH --> REG
    ORCH --> CONFIG
    REG --> MCP & LC & OAI & AWS & AZURE & TF

    MCP & LC & OAI & AWS & AZURE & TF --> RISK
    RISK --> PERM & GRAPH & FLOW

    RISK --> FEAT
    FEAT --> MODEL
    MODEL --> SCORE

    RISK --> REPORT & ALERT & COMPLY
```

---

## Core Components

### 1. Unified Finding Model

All scanners produce findings in a standardized format:

```mermaid
classDiagram
    class Finding {
        +str id
        +str rule_id
        +FindingDomain domain
        +str title
        +str description
        +Severity severity
        +Location location
        +str remediation
        +float risk_score
        +List~str~ compliance_mappings
    }

    class Location {
        +str file_path
        +int line
        +int column
        +str resource_id
    }

    class Severity {
        <<enumeration>>
        CRITICAL
        HIGH
        MEDIUM
        LOW
        INFO
    }

    class FindingDomain {
        <<enumeration>>
        MCP
        LANGCHAIN
        OPENAI
        AWS
        AZURE
        TERRAFORM
    }

    Finding --> Location
    Finding --> Severity
    Finding --> FindingDomain
```

### 2. Scanner Registry

Scanners self-register using a plugin pattern:

```mermaid
sequenceDiagram
    participant App as Application
    participant Reg as Scanner Registry
    participant Scan as Scanner Plugin

    App->>Reg: initialize()
    Reg->>Reg: discover_plugins()
    loop For each scanner
        Scan->>Reg: register(name, scanner_class)
        Reg->>Reg: store in registry
    end
    App->>Reg: get_scanner("mcp")
    Reg->>App: MCPScanner instance
```

### 3. Configuration System

```mermaid
graph LR
    subgraph "Config Sources"
        FILE[.secureagent.yaml]
        ENV[Environment Variables]
        CLI_ARGS[CLI Arguments]
        DEFAULT[Defaults]
    end

    subgraph "Config Manager"
        MERGE[Merge Strategy]
        VALIDATE[Validation]
        RESOLVE[Variable Resolution]
    end

    FILE --> MERGE
    ENV --> MERGE
    CLI_ARGS --> MERGE
    DEFAULT --> MERGE
    MERGE --> VALIDATE --> RESOLVE
```

---

## Data Flow

### Complete Scan Flow

```mermaid
flowchart TB
    subgraph Input["Input Phase"]
        TARGET[Scan Target]
        DISCOVER[Target Discovery]
        PARSE[Parse Configuration]
    end

    subgraph Scan["Scanning Phase"]
        SELECT[Select Scanners]
        EXECUTE[Execute Scans]
        COLLECT[Collect Findings]
    end

    subgraph Enrich["Enrichment Phase"]
        ML_SCORE[ML Risk Scoring]
        COMPLY_MAP[Compliance Mapping]
        GRAPH_BUILD[Build Capability Graph]
    end

    subgraph Analyze["Analysis Phase"]
        BLAST[Blast Radius Calculation]
        PERM_MAP[Permission Mapping]
        DATA_FLOW[Data Flow Analysis]
    end

    subgraph Output["Output Phase"]
        FORMAT[Format Results]
        REPORT[Generate Reports]
        ALERT_SEND[Send Alerts]
        INTEGRATE[Push to Integrations]
    end

    TARGET --> DISCOVER --> PARSE
    PARSE --> SELECT --> EXECUTE --> COLLECT
    COLLECT --> ML_SCORE --> COMPLY_MAP --> GRAPH_BUILD
    GRAPH_BUILD --> BLAST --> PERM_MAP --> DATA_FLOW
    DATA_FLOW --> FORMAT --> REPORT & ALERT_SEND & INTEGRATE
```

### Finding Processing Pipeline

```mermaid
flowchart LR
    RAW[Raw Finding] --> NORM[Normalize]
    NORM --> DEDUP[Deduplicate]
    DEDUP --> SCORE[Score Risk]
    SCORE --> MAP[Map Compliance]
    MAP --> ENRICH[Enrich Metadata]
    ENRICH --> FINAL[Final Finding]

    style RAW fill:#ffcccc
    style FINAL fill:#ccffcc
```

---

## Scanner Architecture

### Base Scanner Interface

All scanners implement the `BaseScanner` abstract class:

```mermaid
classDiagram
    class BaseScanner {
        <<abstract>>
        +str name
        +str description
        +scan(target: str) List~Finding~
        +discover_targets(path: str) List~str~
        +get_rules() List~Rule~
    }

    class MCPScanner {
        +scan(target: str) List~Finding~
        -check_credentials(config)
        -check_commands(config)
        -check_permissions(config)
    }

    class LangChainScanner {
        +scan(target: str) List~Finding~
        -analyze_tools(code)
        -check_memory(code)
        -detect_injection(code)
    }

    class AWSScanner {
        +scan(target: str) List~Finding~
        -check_s3(client)
        -check_iam(client)
        -check_ec2(client)
    }

    BaseScanner <|-- MCPScanner
    BaseScanner <|-- LangChainScanner
    BaseScanner <|-- AWSScanner
```

### Scanner Execution Model

```mermaid
sequenceDiagram
    participant Orch as Orchestrator
    participant Reg as Registry
    participant Scan as Scanner
    participant Rule as Rules Engine
    participant Find as Finding Builder

    Orch->>Reg: get_scanners(types)
    Reg->>Orch: [scanner1, scanner2, ...]

    loop For each scanner
        Orch->>Scan: scan(target)
        Scan->>Scan: parse_target()
        Scan->>Rule: get_rules()
        Rule->>Scan: [rule1, rule2, ...]

        loop For each rule
            Scan->>Rule: check(parsed_data)
            alt Violation Found
                Rule->>Find: create_finding(violation)
                Find->>Scan: Finding
            end
        end

        Scan->>Orch: List[Finding]
    end

    Orch->>Orch: merge_findings()
    Orch->>Orch: deduplicate()
```

---

## Analysis Engine

### Capability Graph

The capability graph models relationships between agents, tools, and resources:

```mermaid
graph TB
    subgraph Agents
        A1[AI Agent 1]
        A2[AI Agent 2]
    end

    subgraph Tools
        T1[Shell Tool]
        T2[File Tool]
        T3[HTTP Tool]
    end

    subgraph Resources
        R1[(Database)]
        R2[File System]
        R3[External API]
    end

    A1 -->|uses| T1
    A1 -->|uses| T2
    A2 -->|uses| T2
    A2 -->|uses| T3

    T1 -->|executes on| R2
    T2 -->|reads/writes| R2
    T2 -->|accesses| R1
    T3 -->|calls| R3

    style T1 fill:#ff6666
    style R1 fill:#ffcc66
```

### Blast Radius Calculation

```mermaid
flowchart TB
    subgraph "Compromised Node"
        AGENT[Agent Compromised]
    end

    subgraph "Direct Impact"
        TOOL1[Tool 1]
        TOOL2[Tool 2]
    end

    subgraph "Indirect Impact"
        RES1[Resource 1]
        RES2[Resource 2]
        RES3[Resource 3]
    end

    subgraph "Affected Data"
        DATA1[Customer Data]
        DATA2[System Configs]
    end

    AGENT -->|"Depth 1"| TOOL1 & TOOL2
    TOOL1 -->|"Depth 2"| RES1 & RES2
    TOOL2 -->|"Depth 2"| RES2 & RES3
    RES1 -->|"Depth 3"| DATA1
    RES2 -->|"Depth 3"| DATA2

    style AGENT fill:#ff0000,color:#fff
    style TOOL1 fill:#ff6666
    style TOOL2 fill:#ff6666
    style RES1 fill:#ffcc66
    style RES2 fill:#ffcc66
    style RES3 fill:#ffcc66
```

### Permission Analysis

```mermaid
graph LR
    subgraph "Permission Categories"
        SHELL[Shell Execution]
        FILE[File Access]
        NET[Network Access]
        DATA[Database Access]
        CRED[Credential Access]
    end

    subgraph "Risk Levels"
        CRIT[CRITICAL]
        HIGH[HIGH]
        MED[MEDIUM]
        LOW[LOW]
    end

    SHELL --> CRIT
    CRED --> CRIT
    FILE --> HIGH
    DATA --> HIGH
    NET --> MED

    style CRIT fill:#ff0000,color:#fff
    style HIGH fill:#ff6666
    style MED fill:#ffcc66
    style LOW fill:#66ff66
```

---

## ML Pipeline

### Risk Scoring Architecture

```mermaid
flowchart TB
    subgraph "Feature Extraction"
        RAW[Raw Finding]
        MCP_F[MCP Features]
        CLOUD_F[Cloud Features]
        AGENT_F[Agent Features]
    end

    subgraph "Feature Engineering"
        NORM[Normalize]
        SCALE[Scale]
        ENCODE[Encode Categorical]
    end

    subgraph "Ensemble Model"
        RF[Random Forest]
        GB[Gradient Boosting]
        LR[Logistic Regression]
    end

    subgraph "Output"
        VOTE[Voting]
        SCORE[Risk Score 0.0-1.0]
        CONF[Confidence Level]
    end

    RAW --> MCP_F & CLOUD_F & AGENT_F
    MCP_F & CLOUD_F & AGENT_F --> NORM --> SCALE --> ENCODE

    ENCODE --> RF & GB & LR
    RF & GB & LR --> VOTE
    VOTE --> SCORE & CONF
```

### Feature Categories

```mermaid
mindmap
    root((Features))
        MCP Features
            Tool Count
            Dangerous Tools
            Permission Level
            Credential Patterns
        Cloud Features
            Public Exposure
            Encryption Status
            IAM Permissions
            Network Config
        Agent Features
            Framework Type
            Model Count
            Data Sources
            Guardrails
```

---

## Plugin System

### Adding a New Scanner

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant Base as BaseScanner
    participant Impl as CustomScanner
    participant Reg as Registry

    Dev->>Base: Inherit from BaseScanner
    Dev->>Impl: Implement scan()
    Dev->>Impl: Implement discover_targets()
    Dev->>Impl: Define rules

    Note over Impl: class CustomScanner(BaseScanner):<br/>    name = "custom"<br/>    def scan(self, target):<br/>        ...

    Impl->>Reg: @register_scanner
    Reg->>Reg: Store CustomScanner

    Note over Reg: Scanner now available via CLI:<br/>secureagent scan --scanners custom
```

### Reporter Plugin Architecture

```mermaid
classDiagram
    class BaseReporter {
        <<abstract>>
        +report(findings) str
        +save(findings, path) None
    }

    class ConsoleReporter {
        +report(findings) str
        -format_finding(finding)
        -colorize(text, severity)
    }

    class JSONReporter {
        +report(findings) str
        -serialize(findings)
    }

    class SARIFReporter {
        +report(findings) str
        -to_sarif(findings)
    }

    class HTMLReporter {
        +report(findings) str
        -render_template(findings)
    }

    BaseReporter <|-- ConsoleReporter
    BaseReporter <|-- JSONReporter
    BaseReporter <|-- SARIFReporter
    BaseReporter <|-- HTMLReporter
```

---

## Directory Structure

```
secureagent/
├── src/secureagent/
│   ├── cli/                 # Command-line interface
│   │   ├── app.py           # Main Typer application
│   │   ├── scan_commands.py # Scan subcommands
│   │   └── ...
│   │
│   ├── core/                # Core framework
│   │   ├── models/          # Data models (Finding, Agent, etc.)
│   │   ├── scanner/         # Base scanner & registry
│   │   ├── reporters/       # Output formatters
│   │   └── alerting/        # Alert dispatchers
│   │
│   ├── scanners/            # Security scanners
│   │   ├── mcp/             # MCP server scanner
│   │   ├── langchain/       # LangChain scanner
│   │   ├── aws/             # AWS cloud scanner
│   │   └── ...
│   │
│   ├── analysis/            # Analysis engines
│   │   ├── permissions.py   # Permission mapping
│   │   ├── risk_analyzer.py # Risk calculations
│   │   └── data_flow.py     # Data flow tracing
│   │
│   ├── graph/               # Capability graph
│   │   ├── models.py        # Graph data structures
│   │   ├── analyzer.py      # Graph analysis
│   │   └── visualizer.py    # Graph rendering
│   │
│   ├── ml/                  # Machine learning
│   │   ├── models.py        # ML models
│   │   ├── features/        # Feature extractors
│   │   └── risk_scorer.py   # Risk scoring
│   │
│   └── compliance/          # Compliance mapping
│       ├── frameworks/      # OWASP, SOC2, etc.
│       └── mapper.py        # Finding-to-control mapper
│
├── models/                  # Pre-trained ML models
├── tests/                   # Test suite
└── docs/                    # Documentation
```

---

## Performance Considerations

```mermaid
graph TB
    subgraph "Optimizations"
        LAZY[Lazy Loading]
        CACHE[Result Caching]
        PARALLEL[Parallel Scanning]
        STREAM[Stream Processing]
    end

    subgraph "Lazy Loading"
        SDK_LAZY[Cloud SDKs loaded on demand]
        ML_LAZY[ML models loaded when needed]
    end

    subgraph "Parallel Scanning"
        MULTI[Multiple scanners run concurrently]
        BATCH[Batch file processing]
    end

    LAZY --> SDK_LAZY & ML_LAZY
    PARALLEL --> MULTI & BATCH
```

---

## Security Considerations

SecureAgent itself follows security best practices:

1. **No credential storage** - All credentials passed via environment variables
2. **Minimal permissions** - Only requests necessary cloud permissions
3. **Local processing** - Findings processed locally, no data sent externally
4. **Audit logging** - All operations logged for audit trail

---

## Next Steps

- [How It Works](how-it-works.md) - Non-technical overview
- [Scanners Guide](scanners.md) - Deep dive into each scanner
- [CLI Reference](cli-reference.md) - Complete command documentation
