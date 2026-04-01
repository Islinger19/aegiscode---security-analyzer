/**
 * Tree view provider for displaying analysis summary
 */

import * as vscode from 'vscode';
import { AnalysisSummary } from '../client';

export class SummaryTreeProvider implements vscode.TreeDataProvider<SummaryTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<SummaryTreeItem | undefined | null | void> = 
        new vscode.EventEmitter<SummaryTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<SummaryTreeItem | undefined | null | void> = 
        this._onDidChangeTreeData.event;

    private summary: AnalysisSummary | null = null;
    private lastAnalyzedAt: Date | null = null;

    constructor() {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    updateSummary(summary: AnalysisSummary): void {
        this.summary = summary;
        this.lastAnalyzedAt = new Date();
        this.refresh();
    }

    clear(): void {
        this.summary = null;
        this.lastAnalyzedAt = null;
        this.refresh();
    }

    getTreeItem(element: SummaryTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: SummaryTreeItem): vscode.ProviderResult<SummaryTreeItem[]> {
        if (element) {
            return [];
        }

        if (!this.summary) {
            return [
                new SummaryTreeItem(
                    'No analysis results yet',
                    'Open a Python file to analyze',
                    new vscode.ThemeIcon('info')
                )
            ];
        }

        const items: SummaryTreeItem[] = [];

        // Total vulnerabilities
        const totalIcon = this.summary.total === 0 
            ? new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'))
            : new vscode.ThemeIcon('shield', new vscode.ThemeColor('errorForeground'));
        
        items.push(new SummaryTreeItem(
            `Total Issues: ${this.summary.total}`,
            this.summary.total === 0 ? 'No vulnerabilities found! 🎉' : 'Click items below for details',
            totalIcon
        ));

        // Breakdown by severity
        if (this.summary.critical > 0) {
            items.push(new SummaryTreeItem(
                `Critical: ${this.summary.critical}`,
                'Immediate attention required',
                new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'))
            ));
        }

        if (this.summary.high > 0) {
            items.push(new SummaryTreeItem(
                `High: ${this.summary.high}`,
                'Should be fixed soon',
                new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'))
            ));
        }

        if (this.summary.medium > 0) {
            items.push(new SummaryTreeItem(
                `Medium: ${this.summary.medium}`,
                'Fix when possible',
                new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'))
            ));
        }

        if (this.summary.low > 0) {
            items.push(new SummaryTreeItem(
                `Low: ${this.summary.low}`,
                'Good to fix for best practices',
                new vscode.ThemeIcon('lightbulb', new vscode.ThemeColor('editorHint.foreground'))
            ));
        }

        // Last analyzed
        if (this.lastAnalyzedAt) {
            items.push(new SummaryTreeItem(
                `Last analyzed: ${this.formatTime(this.lastAnalyzedAt)}`,
                '',
                new vscode.ThemeIcon('clock')
            ));
        }

        return items;
    }

    private formatTime(date: Date): string {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
}

export class SummaryTreeItem extends vscode.TreeItem {
    constructor(
        label: string,
        desc: string,
        icon: vscode.ThemeIcon
    ) {
        super(label, vscode.TreeItemCollapsibleState.None);
        this.tooltip = desc;
        this.description = desc;
        this.iconPath = icon;
    }
}
