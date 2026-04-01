/**
 * Cache Service for AegisCode VS Code Extension
 * Provides persistent caching of analysis results for both logged-in and logged-out users.
 * Uses VS Code's globalState for persistence across sessions.
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { AnalysisResult, Vulnerability } from '../client';

interface CachedAnalysis {
    contentHash: string;
    filePath: string;
    result: AnalysisResult;
    cachedAt: number;  // timestamp
    ttl: number;       // time to live in ms
}

interface CacheStore {
    [key: string]: CachedAnalysis;
}

const CACHE_KEY = 'aegiscode.analysisCache';
const DEFAULT_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_CACHE_SIZE = 100; // Maximum number of cached files

export class CacheService {
    private static instance: CacheService;
    private context: vscode.ExtensionContext;
    private memoryCache: CacheStore = {};
    private initialized: boolean = false;

    private constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    public static getInstance(context?: vscode.ExtensionContext): CacheService {
        if (!CacheService.instance) {
            if (!context) {
                throw new Error('CacheService must be initialized with context first');
            }
            CacheService.instance = new CacheService(context);
        }
        return CacheService.instance;
    }

    /**
     * Initialize cache by loading from globalState
     */
    public async initialize(): Promise<void> {
        if (this.initialized) {
            return;
        }
        
        const stored = this.context.globalState.get<CacheStore>(CACHE_KEY, {});
        
        // Filter out expired entries
        const now = Date.now();
        for (const [key, entry] of Object.entries(stored)) {
            if (now - entry.cachedAt < entry.ttl) {
                this.memoryCache[key] = entry;
            }
        }
        
        // If we removed expired entries, save back
        if (Object.keys(this.memoryCache).length !== Object.keys(stored).length) {
            await this.persistCache();
        }
        
        this.initialized = true;
        console.log(`[CacheService] Initialized with ${Object.keys(this.memoryCache).length} cached entries`);
    }

    /**
     * Generate a unique cache key from file path and content hash
     */
    private getCacheKey(filePath: string, contentHash: string): string {
        return `${filePath}:${contentHash}`;
    }

    /**
     * Compute SHA-256 hash of content
     */
    public computeHash(content: string): string {
        return crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
    }

    /**
     * Get cached analysis result if available and not expired
     */
    public getCachedAnalysis(filePath: string, contentHash: string): AnalysisResult | null {
        const key = this.getCacheKey(filePath, contentHash);
        const entry = this.memoryCache[key];
        
        if (!entry) {
            return null;
        }
        
        // Check if expired
        const now = Date.now();
        if (now - entry.cachedAt >= entry.ttl) {
            delete this.memoryCache[key];
            this.persistCache().catch(console.error);
            return null;
        }
        
        console.log(`[CacheService] Cache hit for ${filePath}`);
        return entry.result;
    }

    /**
     * Check if we have a valid cached result for a file with given content
     */
    public hasCachedAnalysis(filePath: string, contentHash: string): boolean {
        return this.getCachedAnalysis(filePath, contentHash) !== null;
    }

    /**
     * Cache an analysis result
     */
    public async cacheAnalysis(
        filePath: string,
        contentHash: string,
        result: AnalysisResult,
        ttl: number = DEFAULT_TTL
    ): Promise<void> {
        // Only cache successful results
        if (!result.success) {
            return;
        }

        const key = this.getCacheKey(filePath, contentHash);
        
        this.memoryCache[key] = {
            contentHash,
            filePath,
            result,
            cachedAt: Date.now(),
            ttl
        };
        
        // Enforce max cache size by removing oldest entries
        const keys = Object.keys(this.memoryCache);
        if (keys.length > MAX_CACHE_SIZE) {
            const sortedEntries = keys
                .map(k => ({ key: k, cachedAt: this.memoryCache[k].cachedAt }))
                .sort((a, b) => a.cachedAt - b.cachedAt);
            
            // Remove oldest entries
            const toRemove = sortedEntries.slice(0, keys.length - MAX_CACHE_SIZE);
            for (const entry of toRemove) {
                delete this.memoryCache[entry.key];
            }
        }
        
        await this.persistCache();
        console.log(`[CacheService] Cached analysis for ${filePath}`);
    }

    /**
     * Invalidate cache for a specific file (all content hashes)
     */
    public async invalidateFile(filePath: string): Promise<void> {
        const keysToDelete: string[] = [];
        
        for (const key of Object.keys(this.memoryCache)) {
            if (this.memoryCache[key].filePath === filePath) {
                keysToDelete.push(key);
            }
        }
        
        for (const key of keysToDelete) {
            delete this.memoryCache[key];
        }
        
        if (keysToDelete.length > 0) {
            await this.persistCache();
            console.log(`[CacheService] Invalidated cache for ${filePath}`);
        }
    }

    /**
     * Clear all cached data
     */
    public async clearCache(): Promise<void> {
        this.memoryCache = {};
        await this.persistCache();
        console.log('[CacheService] Cache cleared');
    }

    /**
     * Get cache statistics
     */
    public getStats(): { totalEntries: number; oldestEntry: Date | null; newestEntry: Date | null } {
        const entries = Object.values(this.memoryCache);
        
        if (entries.length === 0) {
            return { totalEntries: 0, oldestEntry: null, newestEntry: null };
        }
        
        const times = entries.map(e => e.cachedAt);
        return {
            totalEntries: entries.length,
            oldestEntry: new Date(Math.min(...times)),
            newestEntry: new Date(Math.max(...times))
        };
    }

    /**
     * Persist cache to globalState
     */
    private async persistCache(): Promise<void> {
        await this.context.globalState.update(CACHE_KEY, this.memoryCache);
    }
}
