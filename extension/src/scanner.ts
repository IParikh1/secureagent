/**
 * Scanner - CLI Wrapper for SecureAgent VS Code Extension
 *
 * Provides an interface to the SecureAgent CLI tool for scanning
 * MCP configurations and detecting security vulnerabilities.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import * as vscode from 'vscode';

const execFileAsync = promisify(execFile);

/**
 * Represents a security finding from a scan
 */
export interface Finding {
    /** Unique identifier for the finding */
    id?: string;

    /** Rule that triggered this finding */
    rule?: string;

    /** Severity level */
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';

    /** Human-readable message describing the issue */
    message: string;

    /** File path where the issue was found */
    file?: string;

    /** Line number (1-indexed) */
    line?: number;

    /** Column number (1-indexed) */
    column?: number;

    /** End column for highlighting */
    endColumn?: number;

    /** Category of the finding */
    category?: string;

    /** Recommended fix */
    recommendation?: string;

    /** Additional context or evidence */
    context?: string;

    /** CWE identifier if applicable */
    cwe?: string;
}

/**
 * Result of a scan operation
 */
export interface ScanResult {
    /** Whether the scan completed successfully */
    success: boolean;

    /** List of security findings */
    findings: Finding[];

    /** Scan duration in milliseconds */
    duration: number;

    /** Scanner version */
    version?: string;

    /** Error message if scan failed */
    error?: string;

    /** Files that were scanned */
    filesScanned?: number;
}

/**
 * Scanner configuration options
 */
export interface ScannerConfig {
    /** Path to the CLI executable */
    cliPath: string;

    /** Timeout in milliseconds */
    timeout: number;

    /** Additional CLI arguments */
    extraArgs?: string[];
}

/**
 * Wrapper for the SecureAgent CLI scanner
 */
export class Scanner {
    private cliPath: string;
    private timeout: number;
    private outputChannel: vscode.OutputChannel;

    constructor(
        cliPath: string = 'secureagent',
        timeout: number = 30000,
        outputChannel: vscode.OutputChannel
    ) {
        this.cliPath = cliPath;
        this.timeout = timeout;
        this.outputChannel = outputChannel;
    }

    /**
     * Updates scanner configuration
     */
    updateConfig(cliPath: string, timeout: number): void {
        this.cliPath = cliPath;
        this.timeout = timeout;
    }

    /**
     * Scans a single file for security issues
     */
    async scanFile(filePath: string): Promise<ScanResult> {
        return this.runScan([filePath]);
    }

    /**
     * Scans a directory for security issues
     */
    async scanDirectory(dirPath: string): Promise<ScanResult> {
        return this.runScan([dirPath, '--recursive']);
    }

    /**
     * Runs the scan with the given arguments
     */
    private async runScan(args: string[]): Promise<ScanResult> {
        const startTime = Date.now();

        try {
            // Build command arguments
            const scanArgs = [
                'scan',
                ...args,
                '--output', 'json',
                '--no-color'
            ];

            this.outputChannel.appendLine(`Executing: ${this.cliPath} ${scanArgs.join(' ')}`);

            const { stdout, stderr } = await execFileAsync(this.cliPath, scanArgs, {
                timeout: this.timeout,
                maxBuffer: 10 * 1024 * 1024, // 10MB buffer
                encoding: 'utf-8'
            });

            if (stderr) {
                this.outputChannel.appendLine(`CLI stderr: ${stderr}`);
            }

            const duration = Date.now() - startTime;

            // Parse JSON output
            const result = this.parseOutput(stdout);
            result.duration = duration;

            return result;
        } catch (error) {
            const duration = Date.now() - startTime;

            // Check if it's a CLI error with findings (exit code 1 means issues found)
            if (this.isExecError(error) && error.stdout) {
                try {
                    const result = this.parseOutput(error.stdout);
                    result.duration = duration;
                    return result;
                } catch {
                    // Fall through to error handling
                }
            }

            return this.handleError(error, duration);
        }
    }

    /**
     * Parses CLI JSON output into a ScanResult
     */
    private parseOutput(output: string): ScanResult {
        // Handle empty output
        if (!output || output.trim() === '') {
            return {
                success: true,
                findings: [],
                duration: 0
            };
        }

        try {
            const parsed = JSON.parse(output);

            // Handle different output formats
            if (Array.isArray(parsed)) {
                // Array of findings
                return {
                    success: true,
                    findings: parsed.map(f => this.normalizeFinding(f)),
                    duration: 0
                };
            } else if (parsed.findings) {
                // Object with findings array
                return {
                    success: parsed.success !== false,
                    findings: parsed.findings.map((f: unknown) => this.normalizeFinding(f)),
                    duration: 0,
                    version: parsed.version,
                    filesScanned: parsed.files_scanned || parsed.filesScanned
                };
            } else if (parsed.results) {
                // Object with results array
                return {
                    success: true,
                    findings: parsed.results.map((f: unknown) => this.normalizeFinding(f)),
                    duration: 0,
                    version: parsed.version
                };
            } else {
                // Single finding or unknown format
                return {
                    success: true,
                    findings: parsed.message ? [this.normalizeFinding(parsed)] : [],
                    duration: 0
                };
            }
        } catch (parseError) {
            this.outputChannel.appendLine(`Failed to parse CLI output: ${parseError}`);
            this.outputChannel.appendLine(`Raw output: ${output.substring(0, 500)}`);

            // Try to extract findings from non-JSON output
            return {
                success: false,
                findings: [],
                duration: 0,
                error: 'Failed to parse scanner output'
            };
        }
    }

    /**
     * Normalizes a finding object to the expected format
     */
    private normalizeFinding(raw: unknown): Finding {
        if (typeof raw !== 'object' || raw === null) {
            return {
                severity: 'info',
                message: String(raw)
            };
        }

        const finding = raw as Record<string, unknown>;

        return {
            id: this.getString(finding, 'id'),
            rule: this.getString(finding, 'rule') || this.getString(finding, 'rule_id'),
            severity: this.normalizeSeverity(
                this.getString(finding, 'severity') ||
                this.getString(finding, 'level') ||
                'medium'
            ),
            message: this.getString(finding, 'message') ||
                     this.getString(finding, 'description') ||
                     'Security issue detected',
            file: this.getString(finding, 'file') ||
                  this.getString(finding, 'path') ||
                  this.getString(finding, 'filename'),
            line: this.getNumber(finding, 'line') ||
                  this.getNumber(finding, 'line_number'),
            column: this.getNumber(finding, 'column') ||
                    this.getNumber(finding, 'col'),
            endColumn: this.getNumber(finding, 'end_column') ||
                       this.getNumber(finding, 'endColumn'),
            category: this.getString(finding, 'category') ||
                      this.getString(finding, 'type'),
            recommendation: this.getString(finding, 'recommendation') ||
                           this.getString(finding, 'fix') ||
                           this.getString(finding, 'remediation'),
            context: this.getString(finding, 'context') ||
                     this.getString(finding, 'evidence'),
            cwe: this.getString(finding, 'cwe') ||
                 this.getString(finding, 'cwe_id')
        };
    }

    /**
     * Normalizes severity string to standard values
     */
    private normalizeSeverity(severity: string): Finding['severity'] {
        const normalized = severity.toLowerCase().trim();

        switch (normalized) {
            case 'critical':
            case 'crit':
                return 'critical';
            case 'high':
            case 'error':
            case 'severe':
                return 'high';
            case 'medium':
            case 'moderate':
            case 'warning':
            case 'warn':
                return 'medium';
            case 'low':
            case 'minor':
                return 'low';
            case 'info':
            case 'informational':
            case 'note':
                return 'info';
            default:
                return 'medium';
        }
    }

    /**
     * Safely gets a string value from an object
     */
    private getString(obj: Record<string, unknown>, key: string): string | undefined {
        const value = obj[key];
        return typeof value === 'string' ? value : undefined;
    }

    /**
     * Safely gets a number value from an object
     */
    private getNumber(obj: Record<string, unknown>, key: string): number | undefined {
        const value = obj[key];
        if (typeof value === 'number') {
            return value;
        }
        if (typeof value === 'string') {
            const parsed = parseInt(value, 10);
            return isNaN(parsed) ? undefined : parsed;
        }
        return undefined;
    }

    /**
     * Type guard for exec errors
     */
    private isExecError(error: unknown): error is { stdout?: string; stderr?: string; code?: number } {
        return typeof error === 'object' && error !== null;
    }

    /**
     * Handles scan errors and returns appropriate result
     */
    private handleError(error: unknown, duration: number): ScanResult {
        let errorMessage = 'Unknown error occurred';

        if (error instanceof Error) {
            errorMessage = error.message;

            // Check for common error conditions
            if (errorMessage.includes('ENOENT')) {
                errorMessage = `SecureAgent CLI not found at "${this.cliPath}". Please install it with: pip install secureagent`;
            } else if (errorMessage.includes('ETIMEDOUT') || errorMessage.includes('timeout')) {
                errorMessage = `Scan timed out after ${this.timeout}ms. Try increasing the timeout in settings.`;
            } else if (errorMessage.includes('EACCES')) {
                errorMessage = 'Permission denied. Check file permissions.';
            }
        }

        this.outputChannel.appendLine(`Scan error: ${errorMessage}`);

        return {
            success: false,
            findings: [],
            duration,
            error: errorMessage
        };
    }
}

/**
 * Mock scanner for testing without the CLI
 */
export class MockScanner extends Scanner {
    private mockFindings: Finding[];

    constructor(outputChannel: vscode.OutputChannel, mockFindings: Finding[] = []) {
        super('mock', 30000, outputChannel);
        this.mockFindings = mockFindings;
    }

    async scanFile(_filePath: string): Promise<ScanResult> {
        return {
            success: true,
            findings: this.mockFindings,
            duration: 100,
            version: '1.0.0-mock'
        };
    }

    async scanDirectory(_dirPath: string): Promise<ScanResult> {
        return {
            success: true,
            findings: this.mockFindings,
            duration: 500,
            version: '1.0.0-mock',
            filesScanned: 10
        };
    }

    setMockFindings(findings: Finding[]): void {
        this.mockFindings = findings;
    }
}
