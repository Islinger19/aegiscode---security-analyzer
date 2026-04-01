/**
 * Python Security Analyzer - VS Code Extension
 * Main extension entry point
 */

import * as vscode from 'vscode';
import { SecurityAnalyzerClient } from './client';
import { DiagnosticsManager } from './diagnostics';
import { VulnerabilityTreeProvider } from './views/vulnerabilityTree';
import { SummaryTreeProvider } from './views/summaryTree';
import { AccountTreeProvider } from './views/accountTree';
import { HoverProvider } from './providers/hoverProvider';
import { SecurityInlineCompletionProvider, SecurityCodeActionProvider } from './providers/inlineCompletionProvider';
import { AuthService, AuthUriHandler } from './services/authService';
import { HistoryService } from './services/historyService';
import { CacheService } from './services/cacheService';

let client: SecurityAnalyzerClient;
let diagnosticsManager: DiagnosticsManager;
let vulnerabilityTreeProvider: VulnerabilityTreeProvider;
let summaryTreeProvider: SummaryTreeProvider;
let accountTreeProvider: AccountTreeProvider;
let inlineCompletionProvider: SecurityInlineCompletionProvider;
let authService: AuthService;
let historyService: HistoryService;
let cacheService: CacheService;

// Debounce and deduplication tracking
const pendingAnalysis: Map<string, NodeJS.Timeout> = new Map();
const inProgressAnalysis: Set<string> = new Set();
const lastContentHash: Map<string, string> = new Map();
const DEBOUNCE_DELAY = 1500; // ms to wait before analyzing after changes

export function activate(context: vscode.ExtensionContext) {
    console.log('Python Security Analyzer is now active');

    // Initialize components
    const config = vscode.workspace.getConfiguration('pythonSecurityAnalyzer');
    const serverUrl = config.get<string>('serverUrl', 'http://127.0.0.1:8000');

    client = new SecurityAnalyzerClient(serverUrl);
    diagnosticsManager = new DiagnosticsManager();
    vulnerabilityTreeProvider = new VulnerabilityTreeProvider();
    summaryTreeProvider = new SummaryTreeProvider();
    inlineCompletionProvider = new SecurityInlineCompletionProvider(diagnosticsManager);

    // Initialize authentication service
    authService = AuthService.getInstance(context);
    historyService = HistoryService.getInstance(authService);

    // Initialize cache service for persistent local caching
    cacheService = CacheService.getInstance(context);
    cacheService.initialize().catch(err => console.error('Failed to initialize cache:', err));

    // Register URI handler for auth callback (vscode://publisher.extension-name/auth-callback)
    const uriHandler = new AuthUriHandler(authService);
    context.subscriptions.push(vscode.window.registerUriHandler(uriHandler));

    // Initialize account tree provider
    accountTreeProvider = new AccountTreeProvider(authService);
    accountTreeProvider.setHistoryService(historyService);

    // Register tree views
    vscode.window.registerTreeDataProvider('securityAccount', accountTreeProvider);
    vscode.window.registerTreeDataProvider('securityVulnerabilities', vulnerabilityTreeProvider);
    vscode.window.registerTreeDataProvider('securitySummary', summaryTreeProvider);

    // Register hover provider for detailed vulnerability info
    context.subscriptions.push(
        vscode.languages.registerHoverProvider('python', new HoverProvider(diagnosticsManager))
    );

    // Register inline completion provider for Tab-to-accept security fixes
    context.subscriptions.push(
        vscode.languages.registerInlineCompletionItemProvider(
            'python',
            inlineCompletionProvider
        )
    );

    // Register code action provider for Quick Fix menu
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            'python',
            new SecurityCodeActionProvider(diagnosticsManager),
            {
                providedCodeActionKinds: SecurityCodeActionProvider.providedCodeActionKinds
            }
        )
    );

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('pythonSecurityAnalyzer.analyzeFile', () => analyzeCurrentFile()),
        vscode.commands.registerCommand('pythonSecurityAnalyzer.analyzeWorkspace', () => analyzeWorkspace()),
        vscode.commands.registerCommand('pythonSecurityAnalyzer.showPanel', () => showSecurityPanel()),
        vscode.commands.registerCommand('pythonSecurityAnalyzer.clearDiagnostics', () => clearDiagnostics()),
        vscode.commands.registerCommand('pythonSecurityAnalyzer.clearCache', () => {
            cacheService.clearCache();
            lastContentHash.clear();
            vscode.window.showInformationMessage('Security analysis cache cleared');
        }),
        vscode.commands.registerCommand('pythonSecurityAnalyzer.showFixApplied', (message: string) => {
            vscode.window.showInformationMessage(`🔒 ${message}`);
        }),
        // Apply fix for current line via keyboard shortcut (Ctrl+Shift+. or Cmd+Shift+.)
        vscode.commands.registerCommand('pythonSecurityAnalyzer.applyCurrentLineFix', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor || editor.document.languageId !== 'python') {
                return;
            }

            const cursorLine1Based = editor.selection.active.line + 1;
            const fixes = inlineCompletionProvider.getFixesForDocument(editor.document.uri);

            if (!fixes || fixes.length === 0) {
                vscode.window.showInformationMessage('No security issues found in this file');
                return;
            }

            const fix = fixes.find(f => f.lineNumber === cursorLine1Based);
            if (!fix) {
                vscode.window.showInformationMessage('No security fix available for this line');
                return;
            }

            // Apply the fix
            await applySecurityFix(
                editor.document.uri,
                fix.lineNumber,
                fix.fixedCode,
                fix.endLineNumber
            );
            vscode.window.showInformationMessage(`🔒 ${fix.description}`);
        }),
        vscode.commands.registerCommand('pythonSecurityAnalyzer.applyFix', async (uri: vscode.Uri, line: number, fixedCode: string) => {
            await applySecurityFix(uri, line, fixedCode);
        }),
        // After an inline-completion is accepted, this command deletes extra lines
        // from multi-line vulnerability blocks
        vscode.commands.registerCommand(
            'pythonSecurityAnalyzer.cleanupAfterInlineFix',
            async (uriString: string, replacedLine0: number, endLine0: number, description: string) => {
                try {
                    const uri = vscode.Uri.parse(uriString);
                    const doc = await vscode.workspace.openTextDocument(uri);

                    // Delete lines after the replaced line up to endLine
                    const firstToDelete = replacedLine0 + 1;
                    if (firstToDelete > endLine0 || endLine0 >= doc.lineCount) {
                        vscode.window.showInformationMessage(`🔒 ${description}`);
                        return;
                    }

                    const edit = new vscode.WorkspaceEdit();
                    const deleteRange = new vscode.Range(
                        firstToDelete, 0,
                        endLine0 + 1, 0
                    );
                    edit.delete(uri, deleteRange);
                    await vscode.workspace.applyEdit(edit);
                    vscode.window.showInformationMessage(`🔒 ${description}`);
                } catch (error) {
                    console.error('Error cleaning up after inline fix:', error);
                }
            }
        ),
        // Auth commands
        vscode.commands.registerCommand('pythonSecurityAnalyzer.login', () => authService.login()),
        vscode.commands.registerCommand('pythonSecurityAnalyzer.logout', () => authService.logout()),
        vscode.commands.registerCommand('pythonSecurityAnalyzer.showAuthMenu', () => authService.showAuthMenu()),
        vscode.commands.registerCommand('pythonSecurityAnalyzer.refreshAccountView', () => accountTreeProvider.refreshStats()),
        vscode.commands.registerCommand('pythonSecurityAnalyzer.showStats', () => historyService.showStatsPanel()),
        vscode.commands.registerCommand('pythonSecurityAnalyzer.showHistory', async () => {
            // Quick pick to show recent files
            const data = await historyService.getFiles(0, 20);
            if (!data || data.files.length === 0) {
                vscode.window.showInformationMessage('No analysis history found');
                return;
            }

            const items = data.files.map(f => ({
                label: f.filename,
                description: `${f.vulnerability_summary.total} vulnerabilities`,
                detail: `Analyzed: ${new Date(f.last_analyzed_at).toLocaleString()}`
            }));

            await vscode.window.showQuickPick(items, {
                placeHolder: 'Recent Security Analyses'
            });
        })
    );

    // Auto-analyze on save (debounced and deduplicated)
    if (config.get<boolean>('analyzeOnSave', true)) {
        context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument((document) => {
                if (document.languageId === 'python') {
                    scheduleAnalysis(document, true); // immediate=true for save
                }
            })
        );
    }

    // Auto-analyze on type (debounced)
    if (config.get<boolean>('analyzeOnType', false)) {
        context.subscriptions.push(
            vscode.workspace.onDidChangeTextDocument((event) => {
                if (event.document.languageId === 'python') {
                    scheduleAnalysis(event.document, false); // debounced
                }
            })
        );
    }

    // Analyze on open (debounced to avoid startup flood)
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument((document) => {
            if (document.languageId === 'python' && document.uri.scheme === 'file') {
                scheduleAnalysis(document, false);
            }
        })
    );

    // Analyze currently open Python files (staggered to avoid overwhelming the server)
    let delay = 0;
    vscode.workspace.textDocuments.forEach((document) => {
        if (document.languageId === 'python' && document.uri.scheme === 'file') {
            setTimeout(() => scheduleAnalysis(document, false), delay);
            delay += 500; // Stagger requests
        }
    });

    // Show status bar item
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.text = '$(shield) Security';
    statusBarItem.tooltip = 'Python Security Analyzer';
    statusBarItem.command = 'pythonSecurityAnalyzer.showPanel';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Register diagnostics collection
    context.subscriptions.push(diagnosticsManager.diagnosticCollection);
}

/**
 * Schedule an analysis with debouncing and deduplication
 */
function scheduleAnalysis(document: vscode.TextDocument, immediate: boolean = false): void {
    const uri = document.uri.toString();

    // Cancel any pending analysis for this document
    const pending = pendingAnalysis.get(uri);
    if (pending) {
        clearTimeout(pending);
        pendingAnalysis.delete(uri);
    }

    // Check if content has changed
    const content = document.getText();
    const contentHash = cacheService.computeHash(content);
    const lastHash = lastContentHash.get(uri);

    if (lastHash === contentHash) {
        console.log('[SecurityAnalyzer] Content unchanged, skipping analysis');
        return;
    }

    // Skip if analysis already in progress for this document
    if (inProgressAnalysis.has(uri)) {
        console.log('[SecurityAnalyzer] Analysis already in progress, will retry after completion');
        // Schedule a retry after a delay
        const timeout = setTimeout(() => {
            pendingAnalysis.delete(uri);
            scheduleAnalysis(document, false);
        }, 2000);
        pendingAnalysis.set(uri, timeout);
        return;
    }

    if (immediate) {
        // Immediate analysis (e.g., on save)
        analyzeDocument(document);
    } else {
        // Debounced analysis
        const timeout = setTimeout(() => {
            pendingAnalysis.delete(uri);
            analyzeDocument(document);
        }, DEBOUNCE_DELAY);
        pendingAnalysis.set(uri, timeout);
    }
}

async function analyzeDocument(document: vscode.TextDocument): Promise<void> {
    const config = vscode.workspace.getConfiguration('pythonSecurityAnalyzer');
    const uri = document.uri.toString();
    const filePath = document.uri.fsPath;

    // Get document text and compute hash
    const documentText = document.getText();
    const contentHash = cacheService.computeHash(documentText);

    // Check if content is the same as last analyzed (in-memory check)
    const lastHash = lastContentHash.get(uri);
    if (lastHash === contentHash) {
        console.log('[SecurityAnalyzer] Content unchanged since last analysis, skipping');
        return;
    }

    // Check persistent cache for pre-existing results
    const cachedResult = cacheService.getCachedAnalysis(filePath, contentHash);
    if (cachedResult) {
        console.log('[SecurityAnalyzer] Using cached analysis result');
        
        // Update UI with cached results
        lastContentHash.set(uri, contentHash);
        diagnosticsManager.updateDiagnostics(document.uri, cachedResult.vulnerabilities);
        vulnerabilityTreeProvider.updateVulnerabilities(document.uri, cachedResult.vulnerabilities);
        summaryTreeProvider.updateSummary(cachedResult.summary);
        inlineCompletionProvider.updateFixes(document.uri, cachedResult.vulnerabilities);
        
        return;
    }

    // Mark as in-progress
    inProgressAnalysis.add(uri);

    console.log('[SecurityAnalyzer] analyzeDocument called');
    console.log('[SecurityAnalyzer] document.uri:', uri);
    console.log('[SecurityAnalyzer] document.fileName:', document.fileName);
    console.log('[SecurityAnalyzer] document.getText() length:', documentText.length);
    console.log('[SecurityAnalyzer] contentHash:', contentHash);

    if (!documentText || documentText.trim().length === 0) {
        console.error('[SecurityAnalyzer] ERROR: Document text is empty!');
        inProgressAnalysis.delete(uri);
        return;
    }

    try {
        const result = await client.analyzeCode(
            documentText,
            document.fileName,
            config.get<boolean>('enableAiExplanations', true),
            config.get<string>('minSeverity', 'low')
        );

        if (result.success) {
            // Update cached hash only on success
            lastContentHash.set(uri, contentHash);

            diagnosticsManager.updateDiagnostics(document.uri, result.vulnerabilities);
            vulnerabilityTreeProvider.updateVulnerabilities(document.uri, result.vulnerabilities);
            summaryTreeProvider.updateSummary(result.summary);

            // Update inline completion provider with fixes
            inlineCompletionProvider.updateFixes(document.uri, result.vulnerabilities);

            // Cache the result locally (works for both logged-in and logged-out users)
            cacheService.cacheAnalysis(filePath, contentHash, result).catch(err => 
                console.error('Failed to cache analysis:', err)
            );

            // Save to history if authenticated (MongoDB storage)
            if (historyService && historyService.canSaveHistory()) {
                const shouldSaveCode = config.get<boolean>('saveCodeSnippetsToHistory', true);
                historyService.saveAnalysis(
                    result,
                    document.fileName,
                    document.uri.fsPath,
                    shouldSaveCode ? documentText : undefined
                ).catch(err => console.error('Failed to save to history:', err));
            }

            console.log('[SecurityAnalyzer] Analysis complete, found', result.vulnerabilities.length, 'vulnerabilities');
        } else {
            vscode.window.showErrorMessage(`Security analysis failed: ${result.error_message}`);
        }
    } catch (error) {
        // Server might not be running - show info message once
        console.error('Security analyzer error:', error);
    } finally {
        // Remove from in-progress
        inProgressAnalysis.delete(uri);
    }
}

async function analyzeCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }

    if (editor.document.languageId !== 'python') {
        vscode.window.showWarningMessage('Current file is not a Python file');
        return;
    }

    // Clear cached hash to force re-analysis
    lastContentHash.delete(editor.document.uri.toString());
    cacheService.invalidateFile(editor.document.uri.toString());

    vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: 'Analyzing for security vulnerabilities...',
            cancellable: false
        },
        async () => {
            await analyzeDocument(editor.document);
        }
    );
}

async function analyzeWorkspace(): Promise<void> {
    const pythonFiles = await vscode.workspace.findFiles('**/*.py', '**/node_modules/**');

    if (pythonFiles.length === 0) {
        vscode.window.showInformationMessage('No Python files found in workspace');
        return;
    }

    // Check if server is available
    const available = await client.isServerAvailable();
    if (!available) {
        vscode.window.showErrorMessage(
            'Security analyzer backend is not running. Please start the backend server.',
            'Start Server'
        ).then(selection => {
            if (selection === 'Start Server') {
                vscode.env.openExternal(vscode.Uri.parse('http://127.0.0.1:8000/docs'));
            }
        });
        return;
    }

    const config = vscode.workspace.getConfiguration('pythonSecurityAnalyzer');
    const useMultiFileAnalysis = config.get<boolean>('multiFileAnalysis', true);
    const includeAi = config.get<boolean>('enableAiExplanations', true);

    // Multi-file analysis mode (cross-file vulnerability detection)
    if (useMultiFileAnalysis && pythonFiles.length > 1) {
        vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'Analyzing workspace (multi-file mode)...',
                cancellable: true
            },
            async (progress, token) => {
                // Phase 1: Collect all files
                progress.report({ message: 'Collecting Python files...' });
                
                const files: Record<string, string> = {};
                const uriMap: Record<string, vscode.Uri> = {};
                let totalLines = 0;

                for (const file of pythonFiles) {
                    if (token.isCancellationRequested) {
                        return;
                    }
                    try {
                        const document = await vscode.workspace.openTextDocument(file);
                        const relativePath = vscode.workspace.asRelativePath(file);
                        files[relativePath] = document.getText();
                        uriMap[relativePath] = file;
                        totalLines += document.lineCount;
                    } catch (err) {
                        console.error(`Failed to read ${file.fsPath}:`, err);
                    }
                }

                const fileCount = Object.keys(files).length;
                if (fileCount === 0) {
                    vscode.window.showWarningMessage('Could not read any Python files');
                    return;
                }

                // Phase 2: Send to multi-file analysis endpoint
                progress.report({ message: `Analyzing ${fileCount} files (${totalLines} lines)...` });

                const result = await client.analyzeMultipleFiles(
                    files,
                    undefined, // Entry points auto-detected
                    includeAi,
                    true // Include CVE lookup
                );

                if (token.isCancellationRequested) {
                    return;
                }

                if (!result.success) {
                    vscode.window.showErrorMessage(
                        `Multi-file analysis failed: ${result.error_message}`
                    );
                    return;
                }

                // Phase 3: Process results
                progress.report({ message: 'Processing results...' });

                // Clear previous diagnostics
                diagnosticsManager.clear();
                vulnerabilityTreeProvider.clear();
                summaryTreeProvider.clear();
                inlineCompletionProvider.clearAllFixes();

                // Process standard vulnerabilities by file
                const vulnerabilitiesByFile = new Map<string, typeof result.vulnerabilities>();
                for (const vuln of result.vulnerabilities) {
                    const filePath = vuln.file_path || 'unknown';
                    if (!vulnerabilitiesByFile.has(filePath)) {
                        vulnerabilitiesByFile.set(filePath, []);
                    }
                    vulnerabilitiesByFile.get(filePath)!.push(vuln);
                }

                // Update diagnostics for each file
                for (const [filePath, vulns] of vulnerabilitiesByFile) {
                    const uri = uriMap[filePath];
                    if (uri) {
                        diagnosticsManager.updateDiagnostics(uri, vulns);
                        inlineCompletionProvider.updateFixes(uri, vulns);
                        vulnerabilityTreeProvider.updateVulnerabilities(uri, vulns);
                    }
                }

                // Update summary tree
                summaryTreeProvider.updateSummary(result.summary);

                // Show summary notification
                let summaryMsg = `✅ Workspace analysis complete: ${result.summary.total} vulnerabilities found`;
                
                // Add cross-file vulnerability info
                if (result.cross_file_analysis?.vulnerabilities?.length) {
                    const crossFileCount = result.cross_file_analysis.vulnerabilities.length;
                    summaryMsg += ` (${crossFileCount} cross-file)`;
                    
                    // Show cross-file vulnerabilities as informational messages
                    for (const cfVuln of result.cross_file_analysis.vulnerabilities) {
                        const cfMsg = `🔗 Cross-file ${cfVuln.type}: ${cfVuln.source_file}:${cfVuln.source_line} → ${cfVuln.sink_file}:${cfVuln.sink_line}`;
                        vscode.window.showWarningMessage(cfMsg);
                    }
                }

                // Add CVE info
                if (result.package_security?.cve_findings?.length) {
                    const cveCount = result.package_security.cve_findings.length;
                    summaryMsg += `, ${cveCount} CVE(s) for packages`;
                }

                vscode.window.showInformationMessage(summaryMsg);
            }
        );
    } else {
        // Single-file mode (analyze each file individually)
        vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'Analyzing workspace (file by file)...',
                cancellable: true
            },
            async (progress, token) => {
                const total = pythonFiles.length;
                let processed = 0;

                for (const file of pythonFiles) {
                    if (token.isCancellationRequested) {
                        break;
                    }

                    const document = await vscode.workspace.openTextDocument(file);
                    await analyzeDocument(document);

                    processed++;
                    progress.report({
                        increment: (1 / total) * 100,
                        message: `${processed}/${total} files`
                    });
                }

                vscode.window.showInformationMessage(
                    `Security analysis complete: ${processed} files analyzed`
                );
            }
        );
    }
}

function showSecurityPanel(): void {
    vscode.commands.executeCommand('workbench.view.extension.pythonSecurityAnalyzer');
}

function clearDiagnostics(): void {
    diagnosticsManager.clear();
    vulnerabilityTreeProvider.clear();
    summaryTreeProvider.clear();
    inlineCompletionProvider.clearAllFixes();
    vscode.window.showInformationMessage('Security warnings cleared');
}

async function applySecurityFix(
    uri: vscode.Uri,
    line: number,
    fixedCode: string,
    endLine?: number
): Promise<void> {
    const document = await vscode.workspace.openTextDocument(uri);
    const edit = new vscode.WorkspaceEdit();

    const startLineIndex = line - 1;
    const endLineIndex = endLine ? endLine - 1 : startLineIndex;
    const currentLine = document.lineAt(startLineIndex);

    // Get indentation from current line
    const indent = currentLine.text.match(/^(\s*)/)?.[1] || '';
    const formattedFix = fixedCode.split('\n').map((l, i) =>
        i === 0 ? indent + l.trimStart() : indent + l.trimStart()
    ).join('\n');

    // Replace from start of vulnerable code to end of vulnerable code
    const endLineObj = document.lineAt(endLineIndex);
    const range = new vscode.Range(startLineIndex, 0, endLineIndex, endLineObj.text.length);
    edit.replace(uri, range, formattedFix);

    await vscode.workspace.applyEdit(edit);
}

export function deactivate() {
    // Clear all pending timers
    pendingAnalysis.forEach((timeout) => clearTimeout(timeout));
    pendingAnalysis.clear();
    inProgressAnalysis.clear();
    lastContentHash.clear();

    diagnosticsManager?.clear();
    inlineCompletionProvider?.clearAllFixes();
}
