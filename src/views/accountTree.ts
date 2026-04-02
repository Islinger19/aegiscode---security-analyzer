/**
 * Tree view provider for displaying account information and login status
 */

import * as vscode from 'vscode';
import { AuthService, User } from '../services/authService';
import { HistoryService, UserStats } from '../services/historyService';

export class AccountTreeProvider implements vscode.TreeDataProvider<AccountTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<AccountTreeItem | undefined | null | void> =
        new vscode.EventEmitter<AccountTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<AccountTreeItem | undefined | null | void> =
        this._onDidChangeTreeData.event;

    private authService: AuthService;
    private historyService: HistoryService | null = null;
    private stats: UserStats | null = null;
    private isLoadingStats: boolean = false;

    constructor(authService: AuthService) {
        this.authService = authService;

        // Listen for auth state changes
        authService.onAuthStateChanged(() => {
            this.stats = null; // Clear stats when auth changes
            this.refresh();

            // Load stats if authenticated
            if (authService.isAuthenticated) {
                this.loadStats();
            }
        });
    }

    setHistoryService(historyService: HistoryService): void {
        this.historyService = historyService;
        if (this.authService.isAuthenticated) {
            this.loadStats();
        }
    }

    private async loadStats(): Promise<void> {
        if (!this.historyService || !this.authService.isAuthenticated || this.isLoadingStats) {
            return;
        }

        this.isLoadingStats = true;
        try {
            this.stats = await this.historyService.getStats();
            this.refresh();
        } catch (error) {
            console.error('Failed to load stats:', error);
        } finally {
            this.isLoadingStats = false;
        }
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    async refreshStats(): Promise<void> {
        if (this.authService.isAuthenticated) {
            this.stats = null;
            this.isLoadingStats = false;
            await this.loadStats();
        }
        this.refresh();
    }

    getTreeItem(element: AccountTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: AccountTreeItem): vscode.ProviderResult<AccountTreeItem[]> {
        if (element) {
            // Return children for expandable items
            return element.children || [];
        }

        const items: AccountTreeItem[] = [];

        if (!this.authService.isAuthenticated) {
            // Not logged in - show login prompt
            const loginItem = new AccountTreeItem(
                'Sign in to AegisCode',
                'Login to save analysis history and view stats',
                new vscode.ThemeIcon('sign-in', new vscode.ThemeColor('charts.blue')),
                vscode.TreeItemCollapsibleState.None
            );
            loginItem.command = {
                command: 'pythonSecurityAnalyzer.login',
                title: 'Login'
            };
            items.push(loginItem);

            items.push(new AccountTreeItem(
                'Benefits of signing in:',
                '',
                new vscode.ThemeIcon('info'),
                vscode.TreeItemCollapsibleState.None
            ));

            items.push(new AccountTreeItem(
                '• Save analysis history',
                'Track your security improvements',
                new vscode.ThemeIcon('history'),
                vscode.TreeItemCollapsibleState.None
            ));

            items.push(new AccountTreeItem(
                '• View security statistics',
                'See trends and insights',
                new vscode.ThemeIcon('graph'),
                vscode.TreeItemCollapsibleState.None
            ));

            items.push(new AccountTreeItem(
                '• Access web dashboard',
                'View your data anywhere',
                new vscode.ThemeIcon('globe'),
                vscode.TreeItemCollapsibleState.None
            ));
        } else {
            // Logged in - show user info and stats
            const user = this.authService.user;

            // User profile section
            const profileItem = new AccountTreeItem(
                user?.name || 'User',
                user?.email || '',
                new vscode.ThemeIcon('account', new vscode.ThemeColor('charts.green')),
                vscode.TreeItemCollapsibleState.None
            );
            items.push(profileItem);

            // Divider
            items.push(new AccountTreeItem(
                '─────────────────',
                '',
                new vscode.ThemeIcon('blank'),
                vscode.TreeItemCollapsibleState.None
            ));

            // Stats section
            if (this.stats) {
                // Files analyzed
                items.push(new AccountTreeItem(
                    `📁 Files Analyzed: ${this.stats.total_files_analyzed}`,
                    'Total unique files',
                    new vscode.ThemeIcon('file-code'),
                    vscode.TreeItemCollapsibleState.None
                ));

                // Total analyses
                items.push(new AccountTreeItem(
                    `🔍 Total Analyses: ${this.stats.total_analyses}`,
                    'Including re-analyses',
                    new vscode.ThemeIcon('search'),
                    vscode.TreeItemCollapsibleState.None
                ));

                // Vulnerabilities found
                items.push(new AccountTreeItem(
                    `🛡️ Vulnerabilities: ${this.stats.total_vulnerabilities_found}`,
                    'Total found across all files',
                    new vscode.ThemeIcon('shield'),
                    vscode.TreeItemCollapsibleState.None
                ));

                // Fixes applied
                items.push(new AccountTreeItem(
                    `✅ Fixes Applied: ${this.stats.total_fixes_applied}`,
                    'Security improvements made',
                    new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed')),
                    vscode.TreeItemCollapsibleState.None
                ));

                // Severity breakdown
                if (this.stats.vulnerabilities_by_severity) {
                    const sev = this.stats.vulnerabilities_by_severity;
                    const severityItem = new AccountTreeItem(
                        '📊 By Severity',
                        'Breakdown of vulnerabilities',
                        new vscode.ThemeIcon('pie-chart'),
                        vscode.TreeItemCollapsibleState.Collapsed
                    );

                    severityItem.children = [
                        new AccountTreeItem(
                            `Critical: ${sev.critical || 0}`,
                            '',
                            new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground')),
                            vscode.TreeItemCollapsibleState.None
                        ),
                        new AccountTreeItem(
                            `High: ${sev.high || 0}`,
                            '',
                            new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground')),
                            vscode.TreeItemCollapsibleState.None
                        ),
                        new AccountTreeItem(
                            `Medium: ${sev.medium || 0}`,
                            '',
                            new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground')),
                            vscode.TreeItemCollapsibleState.None
                        ),
                        new AccountTreeItem(
                            `Low: ${sev.low || 0}`,
                            '',
                            new vscode.ThemeIcon('lightbulb'),
                            vscode.TreeItemCollapsibleState.None
                        )
                    ];
                    items.push(severityItem);
                }

                // Last analysis time
                if (this.stats.last_analysis_at) {
                    const lastDate = new Date(this.stats.last_analysis_at);
                    items.push(new AccountTreeItem(
                        `Last analyzed: ${lastDate.toLocaleDateString()}`,
                        lastDate.toLocaleTimeString(),
                        new vscode.ThemeIcon('clock'),
                        vscode.TreeItemCollapsibleState.None
                    ));
                }
            } else if (this.isLoadingStats) {
                items.push(new AccountTreeItem(
                    'Loading statistics...',
                    '',
                    new vscode.ThemeIcon('loading~spin'),
                    vscode.TreeItemCollapsibleState.None
                ));
            } else {
                items.push(new AccountTreeItem(
                    'No statistics yet',
                    'Analyze some files to see stats',
                    new vscode.ThemeIcon('info'),
                    vscode.TreeItemCollapsibleState.None
                ));
            }

            // Divider
            items.push(new AccountTreeItem(
                '─────────────────',
                '',
                new vscode.ThemeIcon('blank'),
                vscode.TreeItemCollapsibleState.None
            ));

            // Actions
            const dashboardConfig = vscode.workspace.getConfiguration('pythonSecurityAnalyzer');
            const dashboardBaseUrl = dashboardConfig.get<string>('dashboardUrl') || dashboardConfig.get<string>('serverUrl') || '';
            const viewDashboardItem = new AccountTreeItem(
                '🌐 Open Web Dashboard',
                'View detailed analytics online',
                new vscode.ThemeIcon('link-external'),
                vscode.TreeItemCollapsibleState.None
            );
            viewDashboardItem.command = {
                command: 'vscode.open',
                title: 'Open Dashboard',
                arguments: [vscode.Uri.parse(`${dashboardBaseUrl}/dashboard`)]
            };
            items.push(viewDashboardItem);

            const refreshItem = new AccountTreeItem(
                '🔄 Refresh Stats',
                'Reload your statistics',
                new vscode.ThemeIcon('refresh'),
                vscode.TreeItemCollapsibleState.None
            );
            refreshItem.command = {
                command: 'pythonSecurityAnalyzer.refreshAccountView',
                title: 'Refresh'
            };
            items.push(refreshItem);

            const logoutItem = new AccountTreeItem(
                '🚪 Sign Out',
                'Logout from AegisCode',
                new vscode.ThemeIcon('sign-out', new vscode.ThemeColor('errorForeground')),
                vscode.TreeItemCollapsibleState.None
            );
            logoutItem.command = {
                command: 'pythonSecurityAnalyzer.logout',
                title: 'Logout'
            };
            items.push(logoutItem);
        }

        return items;
    }
}

export class AccountTreeItem extends vscode.TreeItem {
    children: AccountTreeItem[] | undefined;

    constructor(
        public readonly label: string,
        public readonly description: string,
        public readonly iconPath: vscode.ThemeIcon,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState
    ) {
        super(label, collapsibleState);
        this.tooltip = description || label;
        this.description = description;
    }
}
