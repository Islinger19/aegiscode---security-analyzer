/**
 * Hover provider for detailed vulnerability information
 */

import * as vscode from 'vscode';
import { DiagnosticsManager } from '../diagnostics';

export class HoverProvider implements vscode.HoverProvider {
    constructor(private diagnosticsManager: DiagnosticsManager) {}

    provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        _token: vscode.CancellationToken
    ): vscode.ProviderResult<vscode.Hover> {
        const vulnerability = this.diagnosticsManager.getVulnerabilityAtPosition(
            document.uri,
            position
        );

        if (!vulnerability) {
            return null;
        }

        const markdown = new vscode.MarkdownString();
        markdown.isTrusted = true;
        markdown.supportHtml = true;

        // Header with severity
        const severityColor = this.getSeverityColor(vulnerability.severity);
        markdown.appendMarkdown(`## ${this.getSeverityEmoji(vulnerability.severity)} ${vulnerability.title}\n\n`);
        
        // Severity badge
        markdown.appendMarkdown(`**Severity:** \`${vulnerability.severity.toUpperCase()}\`\n\n`);

        // Description
        markdown.appendMarkdown(`### What's Wrong?\n${vulnerability.description}\n\n`);

        // Why dangerous
        if (vulnerability.why_dangerous) {
            markdown.appendMarkdown(`### Why is this Dangerous?\n${vulnerability.why_dangerous}\n\n`);
        }

        // Attack scenario
        if (vulnerability.attack_scenario) {
            markdown.appendMarkdown(`### How Could This Be Exploited?\n${vulnerability.attack_scenario}\n\n`);
        }

        // Fix suggestion
        if (vulnerability.fix_suggestion) {
            markdown.appendMarkdown(`### How to Fix\n${vulnerability.fix_suggestion}\n\n`);
        }

        // Fixed code example
        if (vulnerability.fixed_code) {
            markdown.appendMarkdown(`### Secure Code Example\n\`\`\`python\n${vulnerability.fixed_code}\n\`\`\`\n\n`);
        }

        // References
        const references: string[] = [];
        if (vulnerability.cwe_id) {
            references.push(`[${vulnerability.cwe_id}](https://cwe.mitre.org/data/definitions/${vulnerability.cwe_id.replace('CWE-', '')}.html)`);
        }
        if (vulnerability.owasp_category) {
            references.push(`[OWASP: ${vulnerability.owasp_category}](https://owasp.org/Top10/)`);
        }
        if (vulnerability.learn_more_url) {
            references.push(`[Learn More](${vulnerability.learn_more_url})`);
        }

        if (references.length > 0) {
            markdown.appendMarkdown(`### References\n${references.join(' | ')}\n`);
        }

        return new vscode.Hover(markdown);
    }

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

    private getSeverityColor(severity: string): string {
        switch (severity.toLowerCase()) {
            case 'critical':
                return '#ff0000';
            case 'high':
                return '#ff6600';
            case 'medium':
                return '#ffcc00';
            case 'low':
                return '#00cc00';
            default:
                return '#888888';
        }
    }
}
