# SecureAgent GTM Development - Product Requirements Document

**Created:** January 31, 2026
**Last Updated:** January 31, 2026
**Status:** In Progress

## Overview

Build the P0 development priorities for SecureAgent's Go-to-Market strategy to close critical gaps between current state and ideal state. This includes telemetry, VS Code extension, and landing page with email capture.

## Goals

1. Enable product-led growth through usage telemetry and PQL identification
2. Expand developer reach through VS Code Marketplace presence
3. Establish commercial foundation with landing page and email capture

## Requirements

### Functional Requirements

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-1 | Implement opt-in anonymous telemetry system | High | Pending |
| FR-2 | Track CLI usage events (scan_start, scan_complete, feature_used) | High | Pending |
| FR-3 | Support SECUREAGENT_TELEMETRY=false opt-out | High | Pending |
| FR-4 | Create VS Code extension with MCP file detection | High | Pending |
| FR-5 | Implement inline diagnostics for security findings | High | Pending |
| FR-6 | Add "Run SecureAgent Scan" command in VS Code | High | Pending |
| FR-7 | Build landing page with clear value proposition | High | Pending |
| FR-8 | Implement email capture for waitlist | High | Pending |
| FR-9 | Display CLI demo/terminal animation on landing page | Medium | Pending |
| FR-10 | Show feature grid and social proof sections | Medium | Pending |

### Non-Functional Requirements

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| NFR-1 | Telemetry must never block CLI execution | High | Pending |
| NFR-2 | Telemetry timeout max 2 seconds | High | Pending |
| NFR-3 | No PII collection in telemetry | High | Pending |
| NFR-4 | VS Code extension must work offline | High | Pending |
| NFR-5 | Landing page load time < 3 seconds | High | Pending |
| NFR-6 | Landing page must be responsive | High | Pending |
| NFR-7 | All code must have tests | High | Pending |

## Technical Specifications

### Tech Stack

**Telemetry System (Python):**
- Async HTTP with httpx (existing dependency)
- SHA256 hashing for anonymous session IDs
- YAML config file support for opt-out
- Environment variable opt-out support

**VS Code Extension (TypeScript):**
- VS Code Extension API
- Node.js child_process for CLI execution
- Diagnostics API for inline warnings
- File system watcher for MCP configs

**Landing Page:**
- Astro framework (fast, static-first)
- Tailwind CSS for styling
- Vercel for deployment
- ConvertKit for email capture

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     SecureAgent Ecosystem                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   CLI        │    │  VS Code     │    │  Landing     │       │
│  │   + Telemetry│    │  Extension   │    │  Page        │       │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘       │
│         │                   │                   │                │
│         │                   │                   │                │
│         ▼                   ▼                   ▼                │
│  ┌──────────────────────────────────────────────────────┐       │
│  │            Telemetry Endpoint (Future)                │       │
│  │            Email List (ConvertKit)                    │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Success Criteria

- [ ] Telemetry system integrated into CLI and tracking events
- [ ] SECUREAGENT_TELEMETRY=false disables telemetry
- [ ] First-run notice informs users about telemetry
- [ ] VS Code extension published to marketplace
- [ ] Extension detects MCP config files and shows diagnostics
- [ ] Landing page deployed and accessible
- [ ] Email capture form functional
- [ ] All new code has test coverage > 80%

## Deliverables

### 1. Telemetry System
- `src/secureagent/telemetry/__init__.py`
- `src/secureagent/telemetry/tracker.py`
- `src/secureagent/telemetry/config.py`
- Integration into CLI app.py
- Tests in `tests/test_telemetry.py`

### 2. VS Code Extension
- `extension/` directory with full extension
- `extension/package.json` with extension manifest
- `extension/src/extension.ts` main extension code
- `extension/src/diagnostics.ts` diagnostic provider
- `extension/README.md` for marketplace
- Extension icon and screenshots

### 3. Landing Page
- `website/` directory with Astro project
- `website/src/pages/index.astro` main page
- `website/src/components/` reusable components
- Email capture integration
- Deployment configuration for Vercel

## Timeline

| Milestone | Target | Status |
|-----------|--------|--------|
| Telemetry system complete | Session 1 | Pending |
| VS Code extension MVP | Session 1-2 | Pending |
| Landing page deployed | Session 2 | Pending |
| All tests passing | Session 2 | Pending |

## Notes

- Reference implementation details in `/Users/ishan/Desktop/SecureAgent_Development_Priorities.md`
- Follow existing code patterns in the codebase
- Maintain backward compatibility with existing CLI
