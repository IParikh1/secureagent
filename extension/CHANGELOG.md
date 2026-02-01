# Changelog

All notable changes to the SecureAgent VS Code Extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Code actions for automatic fixes
- Integration with SecureAgent cloud dashboard
- Custom rule configuration
- Workspace trust support

## [0.1.0] - 2026-01-31

### Added
- Initial release of SecureAgent VS Code Extension
- MCP configuration file detection (`.mcp.json`, `claude_desktop_config.json`, `mcp_config.json`)
- Real-time scanning on file save
- "SecureAgent: Scan Workspace" command
- "SecureAgent: Scan Current File" command
- "SecureAgent: Show Output Panel" command
- "SecureAgent: Clear All Diagnostics" command
- Inline diagnostics in the editor
- Problems panel integration
- Status bar item showing scan status
- Configuration options:
  - `secureagent.enabled` - Enable/disable scanning
  - `secureagent.cliPath` - Custom CLI path
  - `secureagent.scanOnSave` - Auto-scan on save
  - `secureagent.scanTimeout` - Scan timeout
  - `secureagent.severityFilter` - Minimum severity level
  - `secureagent.telemetryEnabled` - Anonymous telemetry
- File system watcher for MCP config files
- Context menu integration for supported files
- Error handling for missing CLI
- Helpful error messages with installation instructions

### Security
- No sensitive data collection
- All scanning performed locally via CLI
- Optional anonymous telemetry with opt-out

[Unreleased]: https://github.com/secureagent/secureagent/compare/extension-v0.1.0...HEAD
[0.1.0]: https://github.com/secureagent/secureagent/releases/tag/extension-v0.1.0
