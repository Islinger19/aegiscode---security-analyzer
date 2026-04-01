/**
 * Diagnostics manager for displaying security warnings in VS Code
 */

import * as vscode from 'vscode';
import { Vulnerability } from './client';

export class DiagnosticsManager {
    public readonly diagnosticCollection: vscode.DiagnosticCollection;
    private vulnerabilityMap: Map<string, Vulnerability[]> = new Map();

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('pythonSecurity');
    }

    /**
     * Update diagnostics for a document
     */
    updateDiagnostics(uri: vscode.Uri, vulnerabilities: Vulnerability[]): void {
        const diagnostics: vscode.Diagnostic[] = [];

        for (const vuln of vulnerabilities) {
            const range = new vscode.Range(
                vuln.line_number - 1,
                vuln.column_start,
                (vuln.end_line_number || vuln.line_number) - 1,
                vuln.column_end || 1000
            );

            const severity = this.mapSeverity(vuln.severity);
            
            const diagnostic = new vscode.Diagnostic(
                range,
                this.formatMessage(vuln),
                severity
            );

            diagnostic.code = {
                value: vuln.cwe_id || vuln.vulnerability_type,
                target: vuln.learn_more_url 
                    ? vscode.Uri.parse(vuln.learn_more_url) 
                    : vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${vuln.cwe_id?.replace('CWE-', '')}.html`)
            };

            diagnostic.source = 'Python Security Analyzer';
            
            // Add related information
            if (vuln.fix_suggestion) {
                diagnostic.relatedInformation = [
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(uri, range),
                        `💡 Fix: ${vuln.fix_suggestion}`
                    )
                ];
            }

            // Add tags for better UI
            if (vuln.severity === 'critical' || vuln.severity === 'high') {
                diagnostic.tags = [vscode.DiagnosticTag.Deprecated];
            }

            diagnostics.push(diagnostic);
        }

        this.diagnosticCollection.set(uri, diagnostics);
        this.vulnerabilityMap.set(uri.toString(), vulnerabilities);
    }

    /**
     * Get vulnerability at a specific position
     */
    getVulnerabilityAtPosition(uri: vscode.Uri, position: vscode.Position): Vulnerability | undefined {
        const vulnerabilities = this.vulnerabilityMap.get(uri.toString());
        if (!vulnerabilities) {
            return undefined;
        }

        const line = position.line + 1;
        return vulnerabilities.find(v => 
            v.line_number === line || 
            (v.line_number <= line && (v.end_line_number || v.line_number) >= line)
        );
    }

    /**
     * Get all vulnerabilities for a document
     */
    getVulnerabilities(uri: vscode.Uri): Vulnerability[] {
        return this.vulnerabilityMap.get(uri.toString()) || [];
    }

    /**
     * Clear all diagnostics
     */
    clear(): void {
        this.diagnosticCollection.clear();
        this.vulnerabilityMap.clear();
    }

    /**
     * Clear diagnostics for a specific document
     */
    clearDocument(uri: vscode.Uri): void {
        this.diagnosticCollection.delete(uri);
        this.vulnerabilityMap.delete(uri.toString());
    }

    /**
     * Map severity string to VS Code DiagnosticSeverity
     */
    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toLowerCase()) {
            case 'critical':
                return vscode.DiagnosticSeverity.Error;
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }

    /**
     * Format vulnerability message for display
     */
    private formatMessage(vuln: Vulnerability): string {
        const severityEmoji = this.getSeverityEmoji(vuln.severity);
        return `${severityEmoji} [${vuln.severity.toUpperCase()}] ${vuln.title}\n${vuln.description}`;
    }

    /**
     * Get emoji for severity level
     */
    private getSeverityEmoji(severity: string): string {
        switch (severity.toLowerCase()) {
            case 'critical':
                return '🔴';
            case 'high':
                return '🟠';
            case 'medium':
                return '🟡';
            case 'low':
                return '🟢';
            default:
                return '⚪';
        }
    }
}
