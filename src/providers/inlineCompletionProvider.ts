/**
 * Inline completion provider for security fix suggestions
 * Provides Copilot-like Tab-to-accept functionality for security fixes
 */

import * as vscode from 'vscode';
import { Vulnerability } from '../client';
import { DiagnosticsManager } from '../diagnostics';

/**
 * Represents a cached security fix for inline completion
 */
interface SecurityFix {
    lineNumber: number;          // 1-indexed (from backend)
    endLineNumber: number;       // 1-indexed (from backend)
    originalCode: string;
    fixedCode: string;
    title: string;
    description: string;
    vulnerability: Vulnerability;
}

/**
 * Provides inline completion items (ghost text) for security fixes.
 * Shows secure code suggestions that can be accepted with Tab.
 */
export class SecurityInlineCompletionProvider implements vscode.InlineCompletionItemProvider {
    private diagnosticsManager: DiagnosticsManager;
    private fixCache: Map<string, SecurityFix[]> = new Map();

    constructor(diagnosticsManager: DiagnosticsManager) {
        this.diagnosticsManager = diagnosticsManager;
    }

    /**
     * Store fixes for a document after analysis
     */
    updateFixes(uri: vscode.Uri, vulnerabilities: Vulnerability[]): void {
        const fixes: SecurityFix[] = [];

        for (const vuln of vulnerabilities) {
            if (vuln.fixed_code && vuln.fixed_code.trim()) {
                fixes.push({
                    lineNumber: vuln.line_number,
                    endLineNumber: vuln.end_line_number || vuln.line_number,
                    originalCode: vuln.code_snippet,
                    fixedCode: vuln.fixed_code,
                    title: vuln.title,
                    description: vuln.fix_suggestion || `Fix: ${vuln.title}`,
                    vulnerability: vuln
                });
            }
        }

        this.fixCache.set(uri.toString(), fixes);
        console.log(`[SecurityInlineCompletion] Cached ${fixes.length} fixes for ${uri.fsPath}`);
    }

    clearFixes(uri: vscode.Uri): void {
        this.fixCache.delete(uri.toString());
    }

    clearAllFixes(): void {
        this.fixCache.clear();
    }

    /**
     * Get all fixes for a document (used by commands to apply fixes)
     */
    getFixesForDocument(uri: vscode.Uri): SecurityFix[] | undefined {
        return this.fixCache.get(uri.toString());
    }

    /**
     * Provide inline completions when cursor is on a vulnerable line.
     * 
     * Note: VS Code inline completions typically only show when the user types.
     * For cursor-movement-only triggers, use the Quick Fix (lightbulb) instead.
     */
    provideInlineCompletionItems(
        document: vscode.TextDocument,
        position: vscode.Position,
        context: vscode.InlineCompletionContext,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<vscode.InlineCompletionItem[] | vscode.InlineCompletionList> {
        
        const fixes = this.fixCache.get(document.uri.toString());
        if (!fixes || fixes.length === 0) {
            return undefined;
        }

        // Convert 0-indexed position.line to 1-indexed for comparison with backend data
        const cursorLine1Based = position.line + 1;
        
        // Find fix for the current line (must match exactly)
        const fix = fixes.find(f => f.lineNumber === cursorLine1Based);
        if (!fix) {
            return undefined;
        }

        // Get the full document text to check for existing imports
        const documentText = document.getText();
        
        // Process the fixed code (remove duplicate imports, apply indentation)
        const currentLine = document.lineAt(position.line);
        const indent = currentLine.text.match(/^(\s*)/)?.[1] || '';
        const processedFix = this.processFixedCode(fix.fixedCode, documentText, indent);
        
        if (!processedFix.trim()) {
            return undefined;
        }

        // Create the inline completion item
        // For best results, don't specify a range - let VS Code handle it
        // The text will be inserted/shown from the cursor position
        const item = new vscode.InlineCompletionItem(processedFix);

        // Command to run after acceptance
        const endLine0Based = fix.endLineNumber - 1;
        if (endLine0Based > position.line) {
            // Multi-line vulnerability: need to delete extra lines after accepting
            item.command = {
                command: 'pythonSecurityAnalyzer.cleanupAfterInlineFix',
                title: 'Cleanup extra lines',
                arguments: [document.uri.toString(), position.line, endLine0Based, fix.description]
            };
        } else {
            item.command = {
                command: 'pythonSecurityAnalyzer.showFixApplied',
                title: 'Fix Applied',
                arguments: [fix.description]
            };
        }

        return { items: [item] };
    }

    /**
     * Process the fixed code:
     * - Remove imports that already exist in the document
     * - Apply proper indentation
     */
    private processFixedCode(fixedCode: string, documentText: string, indent: string): string {
        const lines = fixedCode.split('\n');
        const result: string[] = [];

        for (const line of lines) {
            const trimmed = line.trim();
            
            // Skip leading empty lines
            if (result.length === 0 && trimmed === '') {
                continue;
            }

            // Check if this is an import that already exists
            if (this.isImportLine(trimmed) && this.importExistsInDocument(trimmed, documentText)) {
                continue;
            }

            // Add line with appropriate indentation
            if (trimmed === '') {
                result.push('');
            } else if (this.isImportLine(trimmed)) {
                // Top-level imports don't need extra indentation
                result.push(trimmed);
            } else {
                result.push(indent + trimmed);
            }
        }

        // Remove any leading empty lines that resulted from stripping imports
        while (result.length > 0 && result[0].trim() === '') {
            result.shift();
        }

        return result.join('\n');
    }

    private isImportLine(line: string): boolean {
        const t = line.trim();
        return t.startsWith('import ') || t.startsWith('from ');
    }

    private importExistsInDocument(importLine: string, documentText: string): boolean {
        const trimmed = importLine.trim();
        
        // Check for "import X" style
        if (trimmed.startsWith('import ')) {
            const moduleName = trimmed.replace('import ', '').split(' ')[0].trim();
            // Check if "import moduleName" exists
            if (new RegExp(`^import\\s+${this.escapeRegex(moduleName)}(\\s|$)`, 'm').test(documentText)) {
                return true;
            }
            // Check if "from moduleName import" exists
            if (new RegExp(`^from\\s+${this.escapeRegex(moduleName)}\\s+import`, 'm').test(documentText)) {
                return true;
            }
        }
        
        // Check for "from X import Y" style
        if (trimmed.startsWith('from ')) {
            const match = trimmed.match(/^from\s+(\S+)\s+import/);
            if (match) {
                const moduleName = match[1];
                // Check if module is imported in any form
                if (new RegExp(`^import\\s+${this.escapeRegex(moduleName)}(\\s|$)`, 'm').test(documentText)) {
                    return true;
                }
                if (new RegExp(`^from\\s+${this.escapeRegex(moduleName)}\\s+import`, 'm').test(documentText)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private escapeRegex(str: string): string {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
}

/**
 * Code action provider for Quick Fix menu (lightbulb)
 * This is the reliable way to apply fixes - always works!
 */
export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
    private diagnosticsManager: DiagnosticsManager;

    constructor(diagnosticsManager: DiagnosticsManager) {
        this.diagnosticsManager = diagnosticsManager;
    }

    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix,
        vscode.CodeActionKind.Refactor
    ];

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<(vscode.CodeAction | vscode.Command)[]> {
        const actions: vscode.CodeAction[] = [];
        const vulnerabilities = this.diagnosticsManager.getVulnerabilities(document.uri);
        const documentText = document.getText();
        
        // Find vulnerabilities on the selected line (1-indexed)
        const line1Based = range.start.line + 1;
        const relevantVulns = vulnerabilities.filter(v => 
            v.line_number === line1Based || 
            (v.line_number <= line1Based && (v.end_line_number || v.line_number) >= line1Based)
        );

        for (const vuln of relevantVulns) {
            if (!vuln.fixed_code || !vuln.fixed_code.trim()) {
                continue;
            }

            // Create quick fix action
            const fixAction = new vscode.CodeAction(
                `🔒 Fix: ${vuln.title}`,
                vscode.CodeActionKind.QuickFix
            );

            const edit = new vscode.WorkspaceEdit();
            const startLine = vuln.line_number - 1;  // 0-indexed
            const endLine = (vuln.end_line_number || vuln.line_number) - 1;  // 0-indexed
            
            const startLineObj = document.lineAt(startLine);
            const endLineObj = document.lineAt(endLine);
            const indent = startLineObj.text.match(/^(\s*)/)?.[1] || '';
            
            // Process the fix (deduplicate imports)
            const processedFix = this.processFixedCode(vuln.fixed_code, documentText, indent);
            
            // Replace the entire vulnerable block
            const replaceRange = new vscode.Range(
                startLine, 0,
                endLine, endLineObj.text.length
            );
            edit.replace(document.uri, replaceRange, processedFix);
            
            fixAction.edit = edit;
            fixAction.isPreferred = true;
            fixAction.diagnostics = context.diagnostics.filter(d => 
                d.range.start.line >= startLine && d.range.start.line <= endLine
            );
            
            actions.push(fixAction);

            // Add "Learn More" action
            const learnAction = new vscode.CodeAction(
                `📚 Learn: ${vuln.vulnerability_type_display}`,
                vscode.CodeActionKind.Empty
            );
            const learnUrl = vuln.learn_more_url || 
                `https://owasp.org/www-community/vulnerabilities/${vuln.vulnerability_type}`;
            learnAction.command = {
                command: 'vscode.open',
                title: 'Learn More',
                arguments: [vscode.Uri.parse(learnUrl)]
            };
            actions.push(learnAction);
        }

        return actions;
    }

    private processFixedCode(fixedCode: string, documentText: string, indent: string): string {
        const lines = fixedCode.split('\n');
        const result: string[] = [];

        for (const line of lines) {
            const trimmed = line.trim();
            
            if (result.length === 0 && trimmed === '') {
                continue;
            }

            if (this.isImportLine(trimmed) && this.importExistsInDocument(trimmed, documentText)) {
                continue;
            }

            if (trimmed === '') {
                result.push('');
            } else if (this.isImportLine(trimmed)) {
                result.push(trimmed);
            } else {
                result.push(indent + trimmed);
            }
        }

        while (result.length > 0 && result[0].trim() === '') {
            result.shift();
        }

        return result.join('\n');
    }

    private isImportLine(line: string): boolean {
        const t = line.trim();
        return t.startsWith('import ') || t.startsWith('from ');
    }

    private importExistsInDocument(importLine: string, documentText: string): boolean {
        const trimmed = importLine.trim();
        
        if (trimmed.startsWith('import ')) {
            const moduleName = trimmed.replace('import ', '').split(' ')[0].trim();
            if (new RegExp(`^import\\s+${this.escapeRegex(moduleName)}(\\s|$)`, 'm').test(documentText)) {
                return true;
            }
            if (new RegExp(`^from\\s+${this.escapeRegex(moduleName)}\\s+import`, 'm').test(documentText)) {
                return true;
            }
        }
        
        if (trimmed.startsWith('from ')) {
            const match = trimmed.match(/^from\s+(\S+)\s+import/);
            if (match) {
                const moduleName = match[1];
                if (new RegExp(`^import\\s+${this.escapeRegex(moduleName)}(\\s|$)`, 'm').test(documentText)) {
                    return true;
                }
                if (new RegExp(`^from\\s+${this.escapeRegex(moduleName)}\\s+import`, 'm').test(documentText)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private escapeRegex(str: string): string {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
}
