/**
 * HTTP client for communicating with the security analyzer backend
 */

import axios, { AxiosInstance, AxiosError } from 'axios';

export interface Vulnerability {
    line_number: number;
    column_start: number;
    column_end: number;
    end_line_number: number;
    vulnerability_type: string;
    vulnerability_type_display: string;
    severity: string;
    code_snippet: string;
    file_path: string | null;
    title: string;
    description: string;
    why_dangerous: string;
    attack_scenario: string;
    fix_suggestion: string;
    fixed_code: string;
    cwe_id: string | null;
    owasp_category: string | null;
    learn_more_url: string | null;
    confidence: number;
    detected_at: string;
    detector: string;
}

export interface CrossFileVulnerability {
    id: string;
    type: string;
    severity: string;
    source_file: string;
    source_line: number;
    source_function: string;
    sink_file: string;
    sink_line: number;
    sink_function: string;
    tainted_var: string;
    data_flow_path: string[];
    description: string;
    fix_suggestion: string;
}

export interface CVEEntry {
    cve_id: string;
    package: string;
    severity: string;
    cvss_score: number | null;
    description: string;
    affected_versions: string | null;
    published_date: string | null;
    references: string[];
}

export interface PackageRisk {
    package: string;
    risk_level: string;
    cve_count: number;
    has_critical: boolean;
    recommendation: string;
}

export interface AnalysisSummary {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
}

export interface CrossFileAnalysisSection {
    vulnerabilities: CrossFileVulnerability[];
    data_flow_paths: string[][];
    files_analyzed: string[];
}

export interface PackageSecuritySection {
    imported_packages: string[];
    cve_findings: CVEEntry[];
    package_risks: PackageRisk[];
}

export interface AnalysisResult {
    success: boolean;
    error_message?: string;
    vulnerabilities: Vulnerability[];
    summary: AnalysisSummary;
    metadata: {
        total_lines: number;
        analysis_time_ms: number;
        analyzed_at: string;
    };
    // Multi-file analysis results (optional)
    cross_file_analysis?: CrossFileAnalysisSection;
    // CVE/package security results (optional)
    package_security?: PackageSecuritySection;
}

export class SecurityAnalyzerClient {
    private client: AxiosInstance;
    private serverUrl: string;

    constructor(serverUrl: string) {
        this.serverUrl = serverUrl;
        this.client = axios.create({
            baseURL: serverUrl,
            timeout: 120000, // 2 minutes - AI enhancement can be slow
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }

    /**
     * Update the server URL
     */
    setServerUrl(url: string): void {
        this.serverUrl = url;
        this.client.defaults.baseURL = url;
    }

    /**
     * Check if the backend server is available
     */
    async isServerAvailable(): Promise<boolean> {
        try {
            const response = await this.client.get('/health');
            return response.status === 200;
        } catch {
            return false;
        }
    }

    /**
     * Analyze Python code for security vulnerabilities
     */
    async analyzeCode(
        sourceCode: string,
        filename: string = 'untitled.py',
        includeAiExplanation: boolean = true,
        severityThreshold: string = 'low'
    ): Promise<AnalysisResult> {
        // Debug logging to diagnose Windows issues
        console.log('[SecurityAnalyzer] analyzeCode called');
        console.log('[SecurityAnalyzer] sourceCode length:', sourceCode?.length ?? 'undefined');
        console.log('[SecurityAnalyzer] sourceCode first 100 chars:', sourceCode?.substring(0, 100) ?? 'undefined');
        console.log('[SecurityAnalyzer] filename:', filename);
        
        if (!sourceCode || sourceCode.trim().length === 0) {
            console.error('[SecurityAnalyzer] ERROR: Source code is empty or undefined!');
            return {
                success: false,
                error_message: 'No source code provided (client-side check)',
                vulnerabilities: [],
                summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
                metadata: { total_lines: 0, analysis_time_ms: 0, analyzed_at: new Date().toISOString() }
            };
        }
        
        try {
            const requestBody = {
                source_code: sourceCode,
                filename: filename,
                include_ai_explanation: includeAiExplanation,
                severity_threshold: severityThreshold
            };
            console.log('[SecurityAnalyzer] Sending request to:', this.serverUrl + '/analyze');
            console.log('[SecurityAnalyzer] Request body source_code length:', requestBody.source_code.length);
            console.log('[SecurityAnalyzer] AI explanations enabled:', includeAiExplanation);
            
            const response = await this.client.post<AnalysisResult>('/analyze', requestBody);
            
            console.log('[SecurityAnalyzer] Response received, success:', response.data?.success);

            return response.data;
        } catch (error) {
            console.error('[SecurityAnalyzer] Request failed:', error);
            if (axios.isAxiosError(error)) {
                const axiosError = error as AxiosError<{ detail?: string }>;
                console.error('[SecurityAnalyzer] Axios error status:', axiosError.response?.status);
                console.error('[SecurityAnalyzer] Axios error detail:', axiosError.response?.data?.detail);
                console.error('[SecurityAnalyzer] Axios error code:', axiosError.code);
                
                // If timeout occurred and AI was enabled, fallback to quick analysis
                if (axiosError.code === 'ECONNABORTED' && includeAiExplanation) {
                    console.log('[SecurityAnalyzer] Timeout with AI enabled, falling back to quick analysis...');
                    try {
                        const quickResult = await this.analyzeCodeQuick(sourceCode, filename);
                        if (quickResult.success) {
                            console.log('[SecurityAnalyzer] Quick analysis fallback succeeded');
                            return quickResult;
                        }
                    } catch (quickError) {
                        console.error('[SecurityAnalyzer] Quick analysis fallback also failed:', quickError);
                    }
                }
                
                return {
                    success: false,
                    error_message: axiosError.code === 'ECONNABORTED' 
                        ? 'Analysis timed out. The LLM may be slow - try disabling AI explanations in settings.'
                        : (axiosError.response?.data?.detail || axiosError.message),
                    vulnerabilities: [],
                    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
                    metadata: { total_lines: 0, analysis_time_ms: 0, analyzed_at: new Date().toISOString() }
                };
            }
            throw error;
        }
    }

    /**
     * Quick analysis without AI enhancement
     */
    async analyzeCodeQuick(
        sourceCode: string,
        filename: string = 'untitled.py'
    ): Promise<AnalysisResult> {
        try {
            const response = await this.client.post<AnalysisResult>('/analyze/quick', {
                source_code: sourceCode,
                filename: filename
            });

            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const axiosError = error as AxiosError<{ detail?: string }>;
                return {
                    success: false,
                    error_message: axiosError.response?.data?.detail || axiosError.message,
                    vulnerabilities: [],
                    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
                    metadata: { total_lines: 0, analysis_time_ms: 0, analyzed_at: new Date().toISOString() }
                };
            }
            throw error;
        }
    }

    /**
     * Analyze multiple files for cross-file vulnerabilities.
     * Uses the unified /analyze endpoint with files dict.
     * Returns standard vulnerabilities plus cross-file analysis and CVE findings.
     */
    async analyzeMultipleFiles(
        files: Record<string, string>,
        entryPoints?: string[],
        includeAiExplanation: boolean = true,
        includeCveLookup: boolean = true
    ): Promise<AnalysisResult> {
        console.log('[SecurityAnalyzer] analyzeMultipleFiles called');
        console.log('[SecurityAnalyzer] File count:', Object.keys(files).length);
        console.log('[SecurityAnalyzer] Files:', Object.keys(files));

        if (!files || Object.keys(files).length === 0) {
            console.error('[SecurityAnalyzer] ERROR: No files provided!');
            return {
                success: false,
                error_message: 'No files provided for analysis',
                vulnerabilities: [],
                summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
                metadata: { total_lines: 0, analysis_time_ms: 0, analyzed_at: new Date().toISOString() }
            };
        }

        try {
            const requestBody = {
                files: files,
                entry_points: entryPoints,
                include_ai_explanation: includeAiExplanation,
                include_cve_lookup: includeCveLookup
            };
            
            console.log('[SecurityAnalyzer] Sending multi-file request to:', this.serverUrl + '/analyze');
            console.log('[SecurityAnalyzer] AI explanations enabled:', includeAiExplanation);
            console.log('[SecurityAnalyzer] CVE lookup enabled:', includeCveLookup);

            const response = await this.client.post<AnalysisResult>('/analyze', requestBody);

            console.log('[SecurityAnalyzer] Multi-file response received, success:', response.data?.success);
            if (response.data?.cross_file_analysis) {
                console.log('[SecurityAnalyzer] Cross-file vulnerabilities found:', 
                    response.data.cross_file_analysis.vulnerabilities?.length ?? 0);
            }
            if (response.data?.package_security) {
                console.log('[SecurityAnalyzer] CVE findings:', 
                    response.data.package_security.cve_findings?.length ?? 0);
            }

            return response.data;
        } catch (error) {
            console.error('[SecurityAnalyzer] Multi-file request failed:', error);
            if (axios.isAxiosError(error)) {
                const axiosError = error as AxiosError<{ detail?: string }>;
                console.error('[SecurityAnalyzer] Axios error status:', axiosError.response?.status);
                console.error('[SecurityAnalyzer] Axios error detail:', axiosError.response?.data?.detail);

                return {
                    success: false,
                    error_message: axiosError.code === 'ECONNABORTED'
                        ? 'Multi-file analysis timed out. Try with fewer files or disable AI explanations.'
                        : (axiosError.response?.data?.detail || axiosError.message),
                    vulnerabilities: [],
                    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
                    metadata: { total_lines: 0, analysis_time_ms: 0, analyzed_at: new Date().toISOString() }
                };
            }
            throw error;
        }
    }

    /**
     * Look up CVEs for specific packages
     */
    async lookupCVEs(packages: string[]): Promise<{
        packages_queried: string[];
        cve_count: number;
        cves: CVEEntry[];
    }> {
        try {
            const response = await this.client.post('/cve/lookup', {
                packages: packages
            });
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const axiosError = error as AxiosError<{ detail?: string }>;
                throw new Error(axiosError.response?.data?.detail || axiosError.message);
            }
            throw error;
        }
    }

    /**
     * Get server health status
     */
    async getHealth(): Promise<{
        status: string;
        llm_available: boolean;
        llm_provider: string;
        llm_model: string;
    }> {
        const response = await this.client.get('/health');
        return response.data;
    }

    /**
     * Get current server configuration
     */
    async getConfig(): Promise<Record<string, unknown>> {
        const response = await this.client.get('/config');
        return response.data;
    }

    /**
     * Get list of vulnerability types
     */
    async getVulnerabilityTypes(): Promise<Array<{ id: string; name: string }>> {
        const response = await this.client.get('/vulnerability-types');
        return response.data.types;
    }
}
