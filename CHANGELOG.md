# Changelog

All notable changes to SecureAgent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-01-16

### Added

#### RAG Security Analysis
- **Vector Store Security Scanner** - Comprehensive security analysis for 8 vector stores:
  - Pinecone, Chroma, Weaviate, Qdrant, Milvus, PGVector, Redis, FAISS
  - Access control validation, encryption checks, network exposure detection
  - 10 security rules (RAG-VS-001 to RAG-VS-010)
- **Document Ingestion Scanner** - Security checks for document processing pipelines:
  - Malicious document detection, metadata injection, format exploitation
  - 10 security rules (RAG-DOC-001 to RAG-DOC-010)
- **RAG Poisoning Detector** - Detect and prevent RAG poisoning attacks:
  - Embedding manipulation, knowledge base poisoning, retrieval hijacking
  - 10 security rules (RAG-POISON-001 to RAG-POISON-010)
- **RAG CLI Commands** - New `secureagent rag` command group:
  - `rag scan` - Full RAG system security scan
  - `rag vector-stores` - Vector store security analysis
  - `rag documents` - Document ingestion security
  - `rag poisoning` - RAG poisoning detection
  - `rag test` - Active security testing with payloads

#### Multi-Agent Security
- **Orchestration Security Analyzer** - Workflow and orchestration security:
  - Workflow cycle detection, privilege escalation paths, state corruption
  - 10 security rules (MA-ORCH-001 to MA-ORCH-010)
- **Communication Security Analyzer** - Agent communication channel security:
  - Encryption validation, authentication checks, message injection detection
  - Replay attack protection, channel isolation verification
  - 10 security rules (MA-COMM-001 to MA-COMM-010)
- **Delegation Attack Detector** - Detect delegation-based attacks:
  - Circular delegation, privilege escalation via delegation
  - Task injection, unauthorized delegation chains
  - 10 security rules (MA-DEL-001 to MA-DEL-010)
- **Framework Support** - Built-in analyzers for popular frameworks:
  - LangGraph workflow analysis
  - AutoGen conversation pattern analysis
  - CrewAI crew configuration analysis
  - AutoGPT agent configuration analysis
- **Multi-Agent CLI Commands** - New `secureagent multiagent` command group:
  - `multiagent scan` - Full multi-agent system scan
  - `multiagent orchestration` - Orchestration security analysis
  - `multiagent communication` - Communication channel analysis
  - `multiagent delegation` - Delegation attack detection
  - `multiagent frameworks` - Framework detection and analysis
  - `multiagent test` - Active security testing

#### AutoGPT/CrewAI Scanner Improvements
- Added comprehensive test coverage (23 tests)
- Fixed FindingDomain integration
- All 10 AG rules now properly tested:
  - AG-001: Hardcoded API Keys
  - AG-002: Unrestricted Agent Autonomy
  - AG-003: Dangerous Tool Access
  - AG-004: Inter-Agent Trust Issues
  - AG-005: No Memory Limits
  - AG-006: Unconstrained Task Delegation
  - AG-007: Web Browsing Without Filters
  - AG-008: Verbose Logging in Production
  - AG-009: No Iteration Limits
  - AG-010: Missing Error Boundaries

#### Security Testing Payloads
- Added RAG-specific payloads (RAG-001 to RAG-010):
  - Knowledge base poisoning, embedding manipulation
  - Retrieval hijacking, context overflow
- Added Multi-Agent payloads (MA-001 to MA-010):
  - Delegation chain injection, agent impersonation
  - Circular delegation, privilege escalation
  - Task injection, communication hijacking
- New PayloadGenerator class with specialized payload retrieval

### Changed
- Updated CLI info command to show all new capabilities
- Updated test suite to 308 passing tests
- Improved scanner registry with new scanner types

### Fixed
- AutoGPT scanner now correctly includes FindingDomain in all findings
- Framework detection for YAML-based configurations

## [0.9.0] - 2026-01-10

### Added
- Initial release with core scanning capabilities
- MCP server configuration scanning
- LangChain agent security scanning
- OpenAI Assistants scanning
- AWS infrastructure scanning
- Azure infrastructure scanning
- Terraform configuration scanning
- Compliance reporting (OWASP LLM Top 10, SOC2, PCI-DSS, HIPAA)
- ML-based risk scoring
- GitHub and Slack integrations

---

[Unreleased]: https://github.com/IParikh1/secureagent/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/IParikh1/secureagent/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/IParikh1/secureagent/releases/tag/v0.9.0
