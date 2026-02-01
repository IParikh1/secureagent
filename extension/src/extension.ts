/**
 * SecureAgent VS Code Extension
 *
 * Main entry point for the VS Code extension that provides security scanning
 * for MCP configurations, AI agent setups, and cloud infrastructure.
 */

import * as vscode from 'vscode';
import { DiagnosticsProvider } from './diagnostics';
import { Scanner, ScanResult } from './scanner';

/** Output channel for logging scan results and messages */
let outputChannel: vscode.OutputChannel;

/** Status bar item showing scan status */
let statusBarItem: vscode.StatusBarItem;

/** Diagnostics provider instance */
let diagnosticsProvider: DiagnosticsProvider;

/** Scanner instance */
let scanner: Scanner;

/** Flag to track if a scan is in progress */
let isScanning = false;

/**
 * MCP configuration file patterns to watch
 */
const MCP_FILE_PATTERNS = [
    '**/*.mcp.json',
    '**/claude_desktop_config.json',
    '**/mcp_config.json'
];

/**
 * Activates the extension
 * @param context - The extension context provided by VS Code
 */
export function activate(context: vscode.ExtensionContext): void {
    outputChannel = vscode.window.createOutputChannel('SecureAgent');
    outputChannel.appendLine('SecureAgent extension activated');

    // Initialize status bar
    statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Left,
        100
    );
    statusBarItem.command = 'secureagent.showOutput';
    updateStatusBar('ready');
    statusBarItem.show();

    // Initialize scanner and diagnostics
    const config = vscode.workspace.getConfiguration('secureagent');
    scanner = new Scanner(
        config.get('cliPath', 'secureagent'),
        config.get('scanTimeout', 30000),
        outputChannel
    );
    diagnosticsProvider = new DiagnosticsProvider();

    // Register commands
    const scanWorkspaceCommand = vscode.commands.registerCommand(
        'secureagent.scanWorkspace',
        () => scanWorkspace()
    );

    const scanCurrentFileCommand = vscode.commands.registerCommand(
        'secureagent.scanCurrentFile',
        () => scanCurrentFile()
    );

    const showOutputCommand = vscode.commands.registerCommand(
        'secureagent.showOutput',
        () => outputChannel.show()
    );

    const clearDiagnosticsCommand = vscode.commands.registerCommand(
        'secureagent.clearDiagnostics',
        () => {
            diagnosticsProvider.clearAll();
            outputChannel.appendLine('Cleared all diagnostics');
            vscode.window.showInformationMessage('SecureAgent: Cleared all diagnostics');
        }
    );

    // Register file watchers for MCP config files
    const watchers = MCP_FILE_PATTERNS.map(pattern => {
        const watcher = vscode.workspace.createFileSystemWatcher(pattern);

        watcher.onDidChange(uri => {
            if (config.get('scanOnSave', true)) {
                scanFile(uri);
            }
        });

        watcher.onDidCreate(uri => {
            outputChannel.appendLine(`New MCP config detected: ${uri.fsPath}`);
            if (config.get('scanOnSave', true)) {
                scanFile(uri);
            }
        });

        watcher.onDidDelete(uri => {
            diagnosticsProvider.clearForFile(uri);
            outputChannel.appendLine(`MCP config removed: ${uri.fsPath}`);
        });

        return watcher;
    });

    // Register document save listener
    const saveListener = vscode.workspace.onDidSaveTextDocument(document => {
        if (config.get('enabled', true) && config.get('scanOnSave', true)) {
            if (isMcpConfigFile(document.uri)) {
                scanFile(document.uri);
            }
        }
    });

    // Register configuration change listener
    const configListener = vscode.workspace.onDidChangeConfiguration(e => {
        if (e.affectsConfiguration('secureagent')) {
            const newConfig = vscode.workspace.getConfiguration('secureagent');
            scanner.updateConfig(
                newConfig.get('cliPath', 'secureagent'),
                newConfig.get('scanTimeout', 30000)
            );
            outputChannel.appendLine('Configuration updated');
        }
    });

    // Add all disposables to context
    context.subscriptions.push(
        outputChannel,
        statusBarItem,
        diagnosticsProvider,
        scanWorkspaceCommand,
        scanCurrentFileCommand,
        showOutputCommand,
        clearDiagnosticsCommand,
        saveListener,
        configListener,
        ...watchers
    );

    // Initial scan of workspace if enabled
    if (config.get('enabled', true)) {
        scanWorkspaceOnStartup();
    }
}

/**
 * Checks if a URI points to an MCP configuration file
 */
function isMcpConfigFile(uri: vscode.Uri): boolean {
    const filename = uri.fsPath.toLowerCase();
    return (
        filename.endsWith('.mcp.json') ||
        filename.endsWith('claude_desktop_config.json') ||
        filename.endsWith('mcp_config.json')
    );
}

/**
 * Updates the status bar with current state
 */
function updateStatusBar(state: 'ready' | 'scanning' | 'error' | 'issues'): void {
    switch (state) {
        case 'ready':
            statusBarItem.text = '$(shield) SecureAgent';
            statusBarItem.tooltip = 'SecureAgent: Ready - Click to show output';
            statusBarItem.backgroundColor = undefined;
            break;
        case 'scanning':
            statusBarItem.text = '$(sync~spin) Scanning...';
            statusBarItem.tooltip = 'SecureAgent: Scanning in progress...';
            statusBarItem.backgroundColor = undefined;
            break;
        case 'error':
            statusBarItem.text = '$(error) SecureAgent';
            statusBarItem.tooltip = 'SecureAgent: Error occurred - Click to show output';
            statusBarItem.backgroundColor = new vscode.ThemeColor(
                'statusBarItem.errorBackground'
            );
            break;
        case 'issues':
            statusBarItem.text = '$(warning) SecureAgent';
            statusBarItem.tooltip = 'SecureAgent: Issues found - Click to show output';
            statusBarItem.backgroundColor = new vscode.ThemeColor(
                'statusBarItem.warningBackground'
            );
            break;
    }
}

/**
 * Scans the entire workspace for security issues
 */
async function scanWorkspace(): Promise<void> {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showWarningMessage('SecureAgent: No workspace folder open');
        return;
    }

    if (isScanning) {
        vscode.window.showInformationMessage('SecureAgent: Scan already in progress');
        return;
    }

    isScanning = true;
    updateStatusBar('scanning');
    outputChannel.appendLine(`\n${'='.repeat(60)}`);
    outputChannel.appendLine(`Workspace scan started: ${new Date().toISOString()}`);
    outputChannel.appendLine(`Scanning: ${workspaceFolder.uri.fsPath}`);
    outputChannel.appendLine('='.repeat(60));

    try {
        const result = await scanner.scanDirectory(workspaceFolder.uri.fsPath);
        handleScanResult(result, 'Workspace');
    } catch (error) {
        handleScanError(error);
    } finally {
        isScanning = false;
    }
}

/**
 * Scans the currently active file
 */
async function scanCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('SecureAgent: No file is currently open');
        return;
    }

    const uri = editor.document.uri;
    if (!isMcpConfigFile(uri)) {
        const proceed = await vscode.window.showWarningMessage(
            'This file does not appear to be an MCP config file. Scan anyway?',
            'Yes',
            'No'
        );
        if (proceed !== 'Yes') {
            return;
        }
    }

    await scanFile(uri);
}

/**
 * Scans a specific file
 */
async function scanFile(uri: vscode.Uri): Promise<void> {
    if (isScanning) {
        outputChannel.appendLine(`Queued scan for: ${uri.fsPath}`);
        return;
    }

    isScanning = true;
    updateStatusBar('scanning');
    outputChannel.appendLine(`\nScanning file: ${uri.fsPath}`);

    try {
        const result = await scanner.scanFile(uri.fsPath);

        // Update diagnostics for this file
        const config = vscode.workspace.getConfiguration('secureagent');
        const severityFilter = config.get<string>('severityFilter', 'all');
        diagnosticsProvider.updateDiagnostics(uri, result.findings, severityFilter);

        handleScanResult(result, uri.fsPath);
    } catch (error) {
        handleScanError(error);
        diagnosticsProvider.clearForFile(uri);
    } finally {
        isScanning = false;
    }
}

/**
 * Handles scan results and updates UI accordingly
 */
function handleScanResult(result: ScanResult, scanTarget: string): void {
    const issueCount = result.findings.length;

    outputChannel.appendLine(`\nScan completed: ${scanTarget}`);
    outputChannel.appendLine(`Duration: ${result.duration}ms`);
    outputChannel.appendLine(`Issues found: ${issueCount}`);

    if (issueCount > 0) {
        updateStatusBar('issues');

        // Group by severity
        const bySeverity = result.findings.reduce((acc, f) => {
            acc[f.severity] = (acc[f.severity] || 0) + 1;
            return acc;
        }, {} as Record<string, number>);

        outputChannel.appendLine('\nIssues by severity:');
        Object.entries(bySeverity)
            .sort((a, b) => severityOrder(a[0]) - severityOrder(b[0]))
            .forEach(([severity, count]) => {
                outputChannel.appendLine(`  ${severity.toUpperCase()}: ${count}`);
            });

        outputChannel.appendLine('\nFindings:');
        result.findings.forEach((finding, index) => {
            outputChannel.appendLine(`\n[${index + 1}] ${finding.severity.toUpperCase()}: ${finding.message}`);
            if (finding.file) {
                outputChannel.appendLine(`    File: ${finding.file}:${finding.line}`);
            }
            if (finding.rule) {
                outputChannel.appendLine(`    Rule: ${finding.rule}`);
            }
            if (finding.recommendation) {
                outputChannel.appendLine(`    Fix: ${finding.recommendation}`);
            }
        });

        vscode.window.showWarningMessage(
            `SecureAgent: Found ${issueCount} security issue${issueCount > 1 ? 's' : ''}`,
            'Show Output'
        ).then(selection => {
            if (selection === 'Show Output') {
                outputChannel.show();
            }
        });
    } else {
        updateStatusBar('ready');
        outputChannel.appendLine('No security issues found.');
        vscode.window.showInformationMessage('SecureAgent: No security issues found');
    }
}

/**
 * Handles scan errors
 */
function handleScanError(error: unknown): void {
    updateStatusBar('error');
    const errorMessage = error instanceof Error ? error.message : String(error);
    outputChannel.appendLine(`\nError during scan: ${errorMessage}`);

    if (errorMessage.includes('ENOENT') || errorMessage.includes('not found')) {
        vscode.window.showErrorMessage(
            'SecureAgent CLI not found. Please install it with: pip install secureagent',
            'View Installation Guide'
        ).then(selection => {
            if (selection === 'View Installation Guide') {
                vscode.env.openExternal(
                    vscode.Uri.parse('https://github.com/secureagent/secureagent#installation')
                );
            }
        });
    } else {
        vscode.window.showErrorMessage(`SecureAgent: ${errorMessage}`);
    }
}

/**
 * Returns numeric order for severity (lower = more severe)
 */
function severityOrder(severity: string): number {
    const order: Record<string, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 4
    };
    return order[severity.toLowerCase()] ?? 5;
}

/**
 * Performs initial scan of workspace on startup
 */
async function scanWorkspaceOnStartup(): Promise<void> {
    // Delay startup scan to not block extension activation
    setTimeout(async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            return;
        }

        // Find all MCP config files
        const files: vscode.Uri[] = [];
        for (const pattern of MCP_FILE_PATTERNS) {
            const found = await vscode.workspace.findFiles(pattern);
            files.push(...found);
        }

        if (files.length > 0) {
            outputChannel.appendLine(`Found ${files.length} MCP config file(s) on startup`);
            for (const file of files) {
                await scanFile(file);
            }
        }
    }, 2000);
}

/**
 * Deactivates the extension
 */
export function deactivate(): void {
    outputChannel?.appendLine('SecureAgent extension deactivated');
}
