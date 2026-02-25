// ============================================================
// Vibe Security Watchdog — Type Definitions
// ============================================================

export type Severity = 'critical' | 'warning' | 'info';

export type IssueCategory = 'secret-leak' | 'rls-missing' | 'rls-no-auth' | 'general';

/**
 * Bir güvenlik sorununu temsil eder.
 */
export interface SecurityIssue {
    id: string;
    category: IssueCategory;
    severity: Severity;
    title: string;
    message: string;
    file?: string;
    line?: number;
    key?: string;
    table?: string;
    timestamp: number;
}

/**
 * Hassas anahtar kalıbı konfigürasyonu
 */
export interface SensitivePattern {
    pattern: string;
    severity: Severity;
    message: string;
}

/**
 * Secret Scanner konfigürasyonu
 */
export interface SecretScannerConfig {
    envFiles: string[];
    sensitivePatterns: SensitivePattern[];
}

/**
 * RLS Scanner konfigürasyonu
 */
export interface RLSScannerConfig {
    enabled: boolean;
    scanDirs: string[];
    extensions: string[];
    excludeDirs: string[];
    supabaseUrl: string;
    supabaseServiceRoleKey: string;
    whitelistedTables: string[];
}

/**
 * Reporter konfigürasyonu
 */
export interface ReporterConfig {
    terminal: boolean;
    browserOverlay: boolean;
    overlayAutoCloseMs: number;
    soundAlert: boolean;
}

/**
 * Watcher konfigürasyonu
 */
export interface WatcherConfig {
    debounceMs: number;
    additionalWatchPatterns: string[];
}

/**
 * Ana konfigürasyon tipi
 */
export interface VibeSecurityConfig {
    enabled: boolean;
    secretScanner: SecretScannerConfig;
    rlsScanner: RLSScannerConfig;
    reporter: ReporterConfig;
    watcher: WatcherConfig;
}

/**
 * Tarama sonucu
 */
export interface ScanResult {
    issues: SecurityIssue[];
    scannedAt: number;
    duration: number;
}
