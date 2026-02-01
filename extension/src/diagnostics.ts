/**
 * Diagnostics Provider for SecureAgent VS Code Extension
 *
 * Manages VS Code diagnostic messages (warnings, errors) that appear
 * in the Problems panel and as inline editor decorations.
 */

import * as vscode from 'vscode';
import { Finding } from './scanner';

/**
 * Manages diagnostics (problems) for scanned files
 */
export class DiagnosticsProvider implements vscode.Disposable {
    private readonly diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('secureagent');
    }

    /**
     * Updates diagnostics for a specific file based on scan findings
     * @param uri - The file URI
     * @param findings - Array of security findings
     * @param severityFilter - Minimum severity to display ('all', 'critical', 'high', 'medium', 'low')
     */
    updateDiagnostics(
        uri: vscode.Uri,
        findings: Finding[],
        severityFilter: string = 'all'
    ): void {
        const filteredFindings = this.filterBySeverity(findings, severityFilter);
        const diagnostics = filteredFindings.map(finding => this.findingToDiagnostic(finding));
        this.diagnosticCollection.set(uri, diagnostics);
    }

    /**
     * Clears diagnostics for a specific file
     */
    clearForFile(uri: vscode.Uri): void {
        this.diagnosticCollection.delete(uri);
    }

    /**
     * Clears all diagnostics
     */
    clearAll(): void {
        this.diagnosticCollection.clear();
    }

    /**
     * Disposes of the diagnostic collection
     */
    dispose(): void {
        this.diagnosticCollection.dispose();
    }

    /**
     * Filters findings based on severity threshold
     */
    private filterBySeverity(findings: Finding[], filter: string): Finding[] {
        if (filter === 'all') {
            return findings;
        }

        const severityLevels: Record<string, number> = {
            critical: 4,
            high: 3,
            medium: 2,
            low: 1,
            info: 0
        };

        const threshold = severityLevels[filter.toLowerCase()] ?? 0;

        return findings.filter(finding => {
            const level = severityLevels[finding.severity.toLowerCase()] ?? 0;
            return level >= threshold;
        });
    }

    /**
     * Converts a Finding to a VS Code Diagnostic
     */
    private findingToDiagnostic(finding: Finding): vscode.Diagnostic {
        // Calculate the range for the diagnostic
        const line = Math.max(0, (finding.line || 1) - 1);
        const startColumn = finding.column ? Math.max(0, finding.column - 1) : 0;
        const endColumn = finding.endColumn || 1000; // Highlight to end of line if not specified

        const range = new vscode.Range(
            new vscode.Position(line, startColumn),
            new vscode.Position(line, endColumn)
        );

        // Create the diagnostic
        const diagnostic = new vscode.Diagnostic(
            range,
            finding.message,
            this.severityToVscodeSeverity(finding.severity)
        );

        // Add metadata
        diagnostic.source = 'SecureAgent';
        diagnostic.code = finding.rule ? {
            value: finding.rule,
            target: vscode.Uri.parse(`https://secureagent.dev/rules/${finding.rule}`)
        } : undefined;

        // Add related information if available
        if (finding.recommendation) {
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(
                        vscode.Uri.parse('https://secureagent.dev/docs/remediation'),
                        new vscode.Position(0, 0)
                    ),
                    `Recommendation: ${finding.recommendation}`
                )
            ];
        }

        // Add tags for special cases
        if (finding.severity === 'info') {
            diagnostic.tags = [vscode.DiagnosticTag.Unnecessary];
        }

        return diagnostic;
    }

    /**
     * Converts SecureAgent severity to VS Code DiagnosticSeverity
     */
    private severityToVscodeSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toLowerCase()) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            case 'info':
                return vscode.DiagnosticSeverity.Hint;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }
}

/**
 * Creates a quick fix code action for a diagnostic
 * This can be expanded to provide automatic fixes for common issues
 */
export class SecureAgentCodeActionProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        _token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        // Filter to only SecureAgent diagnostics
        const secureAgentDiagnostics = context.diagnostics.filter(
            d => d.source === 'SecureAgent'
        );

        for (const diagnostic of secureAgentDiagnostics) {
            // Add a "Learn more" action
            const learnMoreAction = new vscode.CodeAction(
                'Learn more about this security issue',
                vscode.CodeActionKind.QuickFix
            );
            learnMoreAction.diagnostics = [diagnostic];
            learnMoreAction.command = {
                command: 'vscode.open',
                title: 'Learn More',
                arguments: [
                    vscode.Uri.parse(
                        diagnostic.code && typeof diagnostic.code === 'object'
                            ? (diagnostic.code.target as vscode.Uri).toString()
                            : 'https://secureagent.dev/docs'
                    )
                ]
            };
            actions.push(learnMoreAction);

            // Add severity-specific actions
            if (diagnostic.severity === vscode.DiagnosticSeverity.Error) {
                const suppressAction = new vscode.CodeAction(
                    'Suppress this warning (add inline comment)',
                    vscode.CodeActionKind.QuickFix
                );
                suppressAction.diagnostics = [diagnostic];
                suppressAction.edit = new vscode.WorkspaceEdit();

                // Add suppress comment at the beginning of the line
                const suppressComment = '// secureagent-ignore-next-line\n';
                const lineStart = new vscode.Position(diagnostic.range.start.line, 0);
                suppressAction.edit.insert(document.uri, lineStart, suppressComment);

                actions.push(suppressAction);
            }
        }

        return actions;
    }
}
