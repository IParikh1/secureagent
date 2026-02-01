# SecureAgent VS Code Extension

Security scanner for MCP configurations, AI agent setups, and cloud infrastructure. Detect vulnerabilities in your AI-powered applications directly in VS Code.

## Features

- **MCP Config Detection**: Automatically detects `.mcp.json`, `claude_desktop_config.json`, and `mcp_config.json` files
- **Real-time Scanning**: Scans files on save and shows inline diagnostics
- **Workspace Scanning**: Scan your entire workspace for security issues
- **Problems Panel Integration**: All findings appear in VS Code's Problems panel
- **Output Panel**: Detailed scan results and logs
- **Status Bar**: Quick status indicator showing scan state

## Installation

### From VS Code Marketplace

1. Open VS Code
2. Press `Ctrl+P` (or `Cmd+P` on macOS)
3. Type `ext install secureagent.secureagent`
4. Press Enter

### From VSIX File

1. Download the `.vsix` file from [releases](https://github.com/secureagent/secureagent/releases)
2. Open VS Code
3. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS)
4. Type "Install from VSIX" and select the command
5. Choose the downloaded `.vsix` file

## Prerequisites

The SecureAgent CLI must be installed for this extension to work:

```bash
# Install with pip
pip install secureagent

# Or with pipx (recommended)
pipx install secureagent

# Verify installation
secureagent --version
```

## Commands

| Command | Description |
|---------|-------------|
| `SecureAgent: Scan Workspace` | Scan all MCP config files in the workspace |
| `SecureAgent: Scan Current File` | Scan the currently open file |
| `SecureAgent: Show Output Panel` | Open the SecureAgent output panel |
| `SecureAgent: Clear All Diagnostics` | Remove all SecureAgent warnings from Problems panel |

## Configuration

Configure the extension in VS Code settings (`Ctrl+,` or `Cmd+,`):

| Setting | Default | Description |
|---------|---------|-------------|
| `secureagent.enabled` | `true` | Enable/disable SecureAgent scanning |
| `secureagent.cliPath` | `"secureagent"` | Path to the SecureAgent CLI executable |
| `secureagent.scanOnSave` | `true` | Automatically scan files on save |
| `secureagent.scanTimeout` | `30000` | Timeout for scan operations (ms) |
| `secureagent.severityFilter` | `"all"` | Minimum severity to display (`all`, `critical`, `high`, `medium`, `low`) |
| `secureagent.telemetryEnabled` | `true` | Enable anonymous usage telemetry |

### Example Settings

```json
{
  "secureagent.enabled": true,
  "secureagent.scanOnSave": true,
  "secureagent.severityFilter": "medium",
  "secureagent.cliPath": "/usr/local/bin/secureagent"
}
```

## Supported File Types

The extension watches for and scans the following file types:

- `*.mcp.json` - MCP configuration files
- `claude_desktop_config.json` - Claude Desktop configuration
- `mcp_config.json` - Generic MCP configuration

## Severity Levels

| Level | VS Code Display | Description |
|-------|-----------------|-------------|
| Critical | Error (red) | Immediate action required |
| High | Error (red) | Significant security risk |
| Medium | Warning (yellow) | Potential security concern |
| Low | Information (blue) | Minor issue or best practice |
| Info | Hint (gray) | Informational note |

## Status Bar

The extension shows its status in the VS Code status bar:

- **$(shield) SecureAgent** - Ready and no issues
- **$(sync~spin) Scanning...** - Scan in progress
- **$(warning) SecureAgent** - Issues found (yellow background)
- **$(error) SecureAgent** - Error occurred (red background)

Click the status bar item to open the output panel.

## Troubleshooting

### "SecureAgent CLI not found"

The CLI is not installed or not in your PATH:

1. Install the CLI: `pip install secureagent`
2. Verify: `secureagent --version`
3. If using a virtual environment, set the full path in `secureagent.cliPath`

### No diagnostics appearing

1. Check that `secureagent.enabled` is `true`
2. Verify the file is a supported type
3. Check the Output panel for errors
4. Try running the CLI manually: `secureagent scan <file>`

### Scan timeout

Increase the timeout in settings:

```json
{
  "secureagent.scanTimeout": 60000
}
```

## Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/secureagent/secureagent.git
cd secureagent/extension

# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Package extension
npm run package
```

### Running Tests

```bash
npm test
```

## Contributing

Contributions are welcome! Please see the [main repository](https://github.com/secureagent/secureagent) for contribution guidelines.

## License

Apache-2.0 - see [LICENSE](../LICENSE) for details.

## Support

- **Documentation**: https://secureagent.dev/docs
- **Issues**: https://github.com/secureagent/secureagent/issues
- **Discussions**: https://github.com/secureagent/secureagent/discussions
