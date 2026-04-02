/**
 * Authentication Service for AegisCode VS Code Extension
 * Handles Google OAuth flow with vscode:// URI callback
 */

import * as vscode from 'vscode';
import axios from 'axios';

export interface User {
    id: string;
    email: string;
    name: string;
    picture?: string;
    created_at: string;
    last_login: string;
}

export interface AuthState {
    isAuthenticated: boolean;
    user: User | null;
    token: string | null;
}

export class AuthService {
    private static instance: AuthService;
    private context: vscode.ExtensionContext;
    private _authState: AuthState = {
        isAuthenticated: false,
        user: null,
        token: null
    };

    // Event emitter for auth state changes
    private _onAuthStateChanged = new vscode.EventEmitter<AuthState>();
    public readonly onAuthStateChanged = this._onAuthStateChanged.event;

    // Status bar item
    private statusBarItem: vscode.StatusBarItem;

    private constructor(context: vscode.ExtensionContext) {
        this.context = context;

        // Create status bar item for auth
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            99
        );
        this.statusBarItem.command = 'pythonSecurityAnalyzer.showAuthMenu';
        context.subscriptions.push(this.statusBarItem);

        // Load saved auth state
        this.loadAuthState();
    }

    public static getInstance(context?: vscode.ExtensionContext): AuthService {
        if (!AuthService.instance) {
            if (!context) {
                throw new Error('AuthService must be initialized with context first');
            }
            AuthService.instance = new AuthService(context);
        }
        return AuthService.instance;
    }

    /**
     * Get current authentication state
     */
    public get authState(): AuthState {
        return this._authState;
    }

    /**
     * Get the stored token
     */
    public get token(): string | null {
        return this._authState.token;
    }

    /**
     * Check if user is authenticated
     */
    public get isAuthenticated(): boolean {
        return this._authState.isAuthenticated;
    }

    /**
     * Get current user
     */
    public get user(): User | null {
        return this._authState.user;
    }

    /**
     * Load auth state from VS Code's secure storage
     */
    private async loadAuthState(): Promise<void> {
        try {
            const token = await this.context.secrets.get('aegiscode.authToken');
            const userJson = this.context.globalState.get<string>('aegiscode.user');

            if (token && userJson) {
                const user = JSON.parse(userJson) as User;

                // Verify token is still valid
                const isValid = await this.verifyToken(token);

                if (isValid) {
                    this._authState = {
                        isAuthenticated: true,
                        user,
                        token
                    };
                    this.updateStatusBar();
                    this._onAuthStateChanged.fire(this._authState);
                } else {
                    // Token expired, clear auth state
                    await this.clearAuthState();
                }
            } else {
                this.updateStatusBar();
            }
        } catch (error) {
            console.error('Failed to load auth state:', error);
            this.updateStatusBar();
        }
    }

    /**
     * Save auth state to VS Code's secure storage
     */
    private async saveAuthState(token: string, user: User): Promise<void> {
        await this.context.secrets.store('aegiscode.authToken', token);
        await this.context.globalState.update('aegiscode.user', JSON.stringify(user));

        this._authState = {
            isAuthenticated: true,
            user,
            token
        };

        this.updateStatusBar();
        this._onAuthStateChanged.fire(this._authState);
    }

    /**
     * Clear auth state (logout)
     */
    private async clearAuthState(): Promise<void> {
        await this.context.secrets.delete('aegiscode.authToken');
        await this.context.globalState.update('aegiscode.user', undefined);

        this._authState = {
            isAuthenticated: false,
            user: null,
            token: null
        };

        this.updateStatusBar();
        this._onAuthStateChanged.fire(this._authState);
    }

    /**
     * Update status bar item
     */
    private updateStatusBar(): void {
        if (this._authState.isAuthenticated && this._authState.user) {
            this.statusBarItem.text = `$(account) ${this._authState.user.name}`;
            this.statusBarItem.tooltip = `Logged in as ${this._authState.user.email}\nClick to manage account`;
        } else {
            this.statusBarItem.text = '$(account) Login';
            this.statusBarItem.tooltip = 'Click to login with Google';
        }
        this.statusBarItem.show();
    }

    /**
     * Verify token with backend
     */
    private async verifyToken(token: string): Promise<boolean> {
        try {
            const config = vscode.workspace.getConfiguration('pythonSecurityAnalyzer');
            const serverUrl = config.get<string>('serverUrl') || '';

            const response = await axios.post(
                `${serverUrl}/auth/verify`,
                {},
                {
                    headers: { Authorization: `Bearer ${token}` },
                    timeout: 5000
                }
            );

            return response.data.valid === true;
        } catch (error) {
            console.error('Token verification failed:', error);
            return false;
        }
    }

    /**
     * Initiate Google OAuth login flow
     */
    public async login(): Promise<void> {
        const config = vscode.workspace.getConfiguration('pythonSecurityAnalyzer');
        const serverUrl = config.get<string>('serverUrl') || '';

        try {
            // Check if backend is available
            const healthCheck = await axios.get(`${serverUrl}/health`, { timeout: 5000 });
            if (healthCheck.status !== 200) {
                throw new Error('Backend server not available');
            }
        } catch (error) {
            vscode.window.showErrorMessage(
                'Cannot connect to AegisCode server. Please ensure the backend is running.'
            );
            return;
        }

        // Open the login URL in the system browser
        const loginUrl = `${serverUrl}/auth/google/login?source=vscode`;

        vscode.window.showInformationMessage(
            'Opening Google login in your browser...',
            'Open Browser'
        ).then(selection => {
            if (selection === 'Open Browser') {
                vscode.env.openExternal(vscode.Uri.parse(loginUrl));
            }
        });

        // Also open immediately
        await vscode.env.openExternal(vscode.Uri.parse(loginUrl));
    }

    /**
     * Handle the auth callback from the vscode:// URI
     */
    public async handleAuthCallback(uri: vscode.Uri): Promise<void> {
        console.log('Auth callback received:', uri.toString());

        // Parse the query parameters
        const params = new URLSearchParams(uri.query);
        const token = params.get('token');
        const error = params.get('error');

        if (error) {
            vscode.window.showErrorMessage(`Authentication failed: ${error}`);
            return;
        }

        if (!token) {
            vscode.window.showErrorMessage('No authentication token received');
            return;
        }

        try {
            // Get user info from the backend
            const config = vscode.workspace.getConfiguration('pythonSecurityAnalyzer');
            const serverUrl = config.get<string>('serverUrl') || '';

            const response = await axios.get(`${serverUrl}/auth/me`, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: 5000
            });

            const user = response.data as User;

            // Save auth state
            await this.saveAuthState(token, user);

            vscode.window.showInformationMessage(
                `Welcome to AegisCode, ${user.name}! Your security analyses will now be saved.`
            );
        } catch (error) {
            console.error('Failed to complete authentication:', error);
            vscode.window.showErrorMessage('Failed to complete authentication');
        }
    }

    /**
     * Logout the user
     */
    public async logout(): Promise<void> {
        const confirm = await vscode.window.showWarningMessage(
            'Are you sure you want to logout?',
            { modal: true },
            'Logout'
        );

        if (confirm === 'Logout') {
            // Notify backend (optional, token-based auth doesn't require server-side logout)
            try {
                const config = vscode.workspace.getConfiguration('pythonSecurityAnalyzer');
                const serverUrl = config.get<string>('serverUrl') || '';

                if (this._authState.token) {
                    await axios.post(
                        `${serverUrl}/auth/logout`,
                        {},
                        {
                            headers: { Authorization: `Bearer ${this._authState.token}` },
                            timeout: 5000
                        }
                    );
                }
            } catch (error) {
                // Ignore errors, logout locally anyway
            }

            await this.clearAuthState();
            vscode.window.showInformationMessage('You have been logged out');
        }
    }

    /**
     * Show auth menu (quick pick)
     */
    public async showAuthMenu(): Promise<void> {
        if (this._authState.isAuthenticated && this._authState.user) {
            const items: vscode.QuickPickItem[] = [
                {
                    label: '$(account) ' + this._authState.user.name,
                    description: this._authState.user.email,
                    detail: 'Logged in'
                },
                {
                    label: '$(graph) View Statistics',
                    description: 'See your security analysis statistics'
                },
                {
                    label: '$(history) View Analysis History',
                    description: 'Browse past security analyses'
                },
                {
                    label: '$(sign-out) Logout',
                    description: 'Sign out of your account'
                }
            ];

            const selected = await vscode.window.showQuickPick(items, {
                placeHolder: 'Account Options'
            });

            if (selected) {
                if (selected.label.includes('Logout')) {
                    await this.logout();
                } else if (selected.label.includes('Statistics')) {
                    vscode.commands.executeCommand('pythonSecurityAnalyzer.showStats');
                } else if (selected.label.includes('History')) {
                    vscode.commands.executeCommand('pythonSecurityAnalyzer.showHistory');
                }
            }
        } else {
            const items: vscode.QuickPickItem[] = [
                {
                    label: '$(sign-in) Login with Google',
                    description: 'Sign in to sync your analysis data'
                }
            ];

            const selected = await vscode.window.showQuickPick(items, {
                placeHolder: 'Sign in to AegisCode'
            });

            if (selected && selected.label.includes('Login')) {
                await this.login();
            }
        }
    }
}

/**
 * URI handler for vscode:// callbacks
 */
export class AuthUriHandler implements vscode.UriHandler {
    private authService: AuthService;

    constructor(authService: AuthService) {
        this.authService = authService;
    }

    async handleUri(uri: vscode.Uri): Promise<void> {
        console.log('URI Handler received:', uri.toString());
        console.log('Path:', uri.path);

        // Handle auth callback
        if (uri.path === '/auth-callback' || uri.path === 'auth-callback') {
            await this.authService.handleAuthCallback(uri);
        }
    }
}
