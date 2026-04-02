/**
 * History Service for AegisCode VS Code Extension
 * Handles saving and retrieving analysis history from the backend
 */

import * as vscode from 'vscode';
import axios from 'axios';
import { AuthService } from './authService';
import { AnalysisResult, Vulnerability } from '../client';

export interface SavedFile {
    id: string;
    user_id: string;
    filename: string;
    file_path: string;
    total_lines: number;
    vulnerability_summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
    security_score: number;
    total_analyses: number;
    last_analyzed_at: string;
    created_at: string;
}

export interface UserStats {
    total_analyses: number;
    total_files_analyzed: number;
    total_vulnerabilities_found: number;
    total_fixes_applied: number;
    vulnerabilities_by_severity: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
    top_vulnerability_types: Record<string, number>;
    daily_analyses: Record<string, number>;
    first_analysis_at?: string;
    last_analysis_at?: string;
}

export class HistoryService {
    private static instance: HistoryService;
    private authService: AuthService;
    private serverUrl: string = '';

    private constructor(authService: AuthService) {
        this.authService = authService;
        this.updateServerUrl();

        // Listen for config changes
        vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('pythonSecurityAnalyzer.serverUrl')) {
                this.updateServerUrl();
            }
        });
    }

    public static getInstance(authService?: AuthService): HistoryService {
        if (!HistoryService.instance) {
            if (!authService) {
                throw new Error('HistoryService must be initialized with authService first');
            }
            HistoryService.instance = new HistoryService(authService);
        }
        return HistoryService.instance;
    }

    private updateServerUrl(): void {
        const config = vscode.workspace.getConfiguration('pythonSecurityAnalyzer');
        this.serverUrl = config.get<string>('serverUrl') || '';
    }

    private getAuthHeaders(): Record<string, string> {
        const headers: Record<string, string> = {
            'Content-Type': 'application/json'
        };

        if (this.authService.token) {
            headers['Authorization'] = `Bearer ${this.authService.token}`;
        }

        return headers;
    }

    /**
     * Check if history saving is enabled and user is authenticated
     */
    public canSaveHistory(): boolean {
        const config = vscode.workspace.getConfiguration('pythonSecurityAnalyzer');
        const saveHistoryEnabled = config.get<boolean>('saveAnalysisHistory', true);
        return saveHistoryEnabled && this.authService.isAuthenticated;
    }

    /**
     * Save an analysis result to history
     * Source code is always saved to enable web app vulnerability display
     */
    public async saveAnalysis(
        result: AnalysisResult,
        filename: string,
        filePath?: string,
        sourceCode?: string
    ): Promise<boolean> {
        if (!this.canSaveHistory()) {
            return false;
        }

        try {
            const config = vscode.workspace.getConfiguration('pythonSecurityAnalyzer');

            // Always include source code for web app display
            const payload = {
                filename,
                file_path: filePath || filename,
                source_code: sourceCode || '',  // Always include for web app vulnerability display
                total_lines: result.metadata.total_lines,
                vulnerabilities: result.vulnerabilities.map(v => ({
                    vulnerability_type: v.vulnerability_type,
                    vulnerability_type_display: v.vulnerability_type_display,
                    severity: v.severity,
                    line_number: v.line_number,
                    end_line_number: v.end_line_number,
                    column_start: v.column_start,
                    column_end: v.column_end,
                    code_snippet: v.code_snippet,
                    title: v.title,
                    description: v.description,
                    why_dangerous: v.why_dangerous,
                    attack_scenario: v.attack_scenario,
                    fix_suggestion: v.fix_suggestion,
                    fixed_code: v.fixed_code,
                    cwe_id: v.cwe_id,
                    owasp_category: v.owasp_category,
                    confidence: v.confidence,
                    detector: v.detector
                })),
                analysis_time_ms: result.metadata.analysis_time_ms,
                ai_explanation_enabled: config.get<boolean>('enableAiExplanations', true),
                severity_threshold: config.get<string>('minSeverity', 'low'),
                source: 'vscode_extension',
                extension_version: vscode.extensions.getExtension('aegiscode---security-analyzer')?.packageJSON.version
            };

            await axios.post(
                `${this.serverUrl}/history/file`,
                payload,
                {
                    headers: this.getAuthHeaders(),
                    timeout: 10000
                }
            );

            console.log(`Analysis saved to history: ${filename}`);
            return true;
        } catch (error) {
            console.error('Failed to save analysis to history:', error);
            return false;
        }
    }

    /**
     * Record a fix that was applied
     */
    public async recordFix(
        filename: string,
        filePath: string | undefined,
        vulnerability: Vulnerability,
        originalCode: string,
        fixedCode: string
    ): Promise<boolean> {
        if (!this.canSaveHistory()) {
            return false;
        }

        try {
            await axios.post(
                `${this.serverUrl}/history/fix`,
                null,
                {
                    params: {
                        filename,
                        file_path: filePath,
                        vulnerability_type: vulnerability.vulnerability_type,
                        severity: vulnerability.severity,
                        line_number: vulnerability.line_number,
                        original_code: originalCode,
                        fixed_code: fixedCode
                    },
                    headers: this.getAuthHeaders(),
                    timeout: 10000
                }
            );

            console.log(`Fix recorded: ${vulnerability.vulnerability_type} in ${filename}`);
            return true;
        } catch (error) {
            console.error('Failed to record fix:', error);
            return false;
        }
    }

    /**
     * Get user's analyzed files
     */
    public async getFiles(
        skip: number = 0,
        limit: number = 50,
        search?: string
    ): Promise<{ files: SavedFile[]; total: number } | null> {
        if (!this.authService.isAuthenticated) {
            return null;
        }

        try {
            const params: Record<string, any> = { skip, limit };
            if (search) {
                params.search = search;
            }

            const response = await axios.get(`${this.serverUrl}/history/files`, {
                params,
                headers: this.getAuthHeaders(),
                timeout: 10000
            });

            return response.data;
        } catch (error) {
            console.error('Failed to get files:', error);
            return null;
        }
    }

    /**
     * Get detailed file with code and vulnerabilities
     */
    public async getFileDetail(fileId: string): Promise<any | null> {
        if (!this.authService.isAuthenticated) {
            return null;
        }

        try {
            const response = await axios.get(`${this.serverUrl}/history/files/${fileId}`, {
                headers: this.getAuthHeaders(),
                timeout: 10000
            });

            return response.data;
        } catch (error) {
            console.error('Failed to get file detail:', error);
            return null;
        }
    }

    /**
     * Get dashboard data
     */
    public async getDashboard(): Promise<any | null> {
        if (!this.authService.isAuthenticated) {
            return null;
        }

        try {
            const response = await axios.get(`${this.serverUrl}/history/dashboard`, {
                headers: this.getAuthHeaders(),
                timeout: 10000
            });

            return response.data;
        } catch (error) {
            console.error('Failed to get dashboard:', error);
            return null;
        }
    }

    /**
     * Get user statistics
     */
    public async getStats(): Promise<UserStats | null> {
        if (!this.authService.isAuthenticated) {
            return null;
        }

        try {
            const response = await axios.get(`${this.serverUrl}/history/stats`, {
                headers: this.getAuthHeaders(),
                timeout: 10000
            });

            return response.data;
        } catch (error) {
            console.error('Failed to get stats:', error);
            return null;
        }
    }

    /**
     * Get recent vulnerabilities
     */
    public async getRecentVulnerabilities(
        limit: number = 50
    ): Promise<any[] | null> {
        if (!this.authService.isAuthenticated) {
            return null;
        }

        try {
            const response = await axios.get(`${this.serverUrl}/history/recent-vulnerabilities`, {
                params: { limit },
                headers: this.getAuthHeaders(),
                timeout: 10000
            });

            return response.data.vulnerabilities;
        } catch (error) {
            console.error('Failed to get recent vulnerabilities:', error);
            return null;
        }
    }

    /**
     * Show statistics in a webview panel
     */
    public async showStatsPanel(): Promise<void> {
        if (!this.authService.isAuthenticated) {
            vscode.window.showInformationMessage(
                'Please login to view your statistics',
                'Login'
            ).then(selection => {
                if (selection === 'Login') {
                    this.authService.login();
                }
            });
            return;
        }

        const stats = await this.getStats();
        if (!stats) {
            vscode.window.showErrorMessage('Failed to load statistics');
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'aegiscodeStats',
            'AegisCode Statistics',
            vscode.ViewColumn.One,
            { enableScripts: true }
        );

        panel.webview.html = this.getStatsHtml(stats);
    }

    private getStatsHtml(stats: UserStats): string {
        const topTypes = Object.entries(stats.top_vulnerability_types)
            .slice(0, 5)
            .map(([type, count]) => `<li>${type.replace(/_/g, ' ')}: ${count}</li>`)
            .join('');

        return `
<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: var(--vscode-font-family);
            padding: 20px;
            color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: var(--vscode-sideBar-background);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: var(--vscode-textLink-foreground);
        }
        .stat-label {
            font-size: 0.9em;
            opacity: 0.8;
            margin-top: 5px;
        }
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin-top: 20px;
        }
        .severity-card {
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .severity-critical { background: rgba(255, 0, 0, 0.2); }
        .severity-high { background: rgba(255, 128, 0, 0.2); }
        .severity-medium { background: rgba(255, 255, 0, 0.2); }
        .severity-low { background: rgba(0, 255, 0, 0.2); }
        .section-title {
            font-size: 1.2em;
            font-weight: bold;
            margin: 30px 0 15px 0;
            border-bottom: 1px solid var(--vscode-panel-border);
            padding-bottom: 5px;
        }
        ul {
            list-style: none;
            padding: 0;
        }
        li {
            padding: 8px 0;
            border-bottom: 1px solid var(--vscode-panel-border);
            text-transform: capitalize;
        }
    </style>
</head>
<body>
    <h1>🛡️ Your Security Statistics</h1>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">${stats.total_analyses}</div>
            <div class="stat-label">Total Analyses</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.total_vulnerabilities_found}</div>
            <div class="stat-label">Vulnerabilities Found</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.total_fixes_applied}</div>
            <div class="stat-label">Fixes Applied</div>
        </div>
    </div>
    
    <div class="section-title">Vulnerabilities by Severity</div>
    <div class="severity-grid">
        <div class="severity-card severity-critical">
            <div class="stat-value" style="font-size: 1.5em; color: #f44;">${stats.vulnerabilities_by_severity.critical}</div>
            <div>Critical</div>
        </div>
        <div class="severity-card severity-high">
            <div class="stat-value" style="font-size: 1.5em; color: #f80;">${stats.vulnerabilities_by_severity.high}</div>
            <div>High</div>
        </div>
        <div class="severity-card severity-medium">
            <div class="stat-value" style="font-size: 1.5em; color: #fc0;">${stats.vulnerabilities_by_severity.medium}</div>
            <div>Medium</div>
        </div>
        <div class="severity-card severity-low">
            <div class="stat-value" style="font-size: 1.5em; color: #4c4;">${stats.vulnerabilities_by_severity.low}</div>
            <div>Low</div>
        </div>
    </div>
    
    <div class="section-title">Top Vulnerability Types</div>
    <ul>${topTypes || '<li>No vulnerabilities detected yet</li>'}</ul>
    
    ${stats.first_analysis_at ? `
    <div class="section-title">Timeline</div>
    <p>First analysis: ${new Date(stats.first_analysis_at).toLocaleDateString()}</p>
    <p>Last analysis: ${stats.last_analysis_at ? new Date(stats.last_analysis_at).toLocaleDateString() : 'N/A'}</p>
    ` : ''}
</body>
</html>`;
    }
}
