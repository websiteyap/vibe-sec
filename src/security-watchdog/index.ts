// ============================================================
// 🛡️ Vibe Security Watchdog — Ana Orkestratör
// ============================================================
// Tüm tarayıcıları koordine eder, dosya değişimlerini izler,
// SQL reçeteleri üretir ve vibe-summary.txt'yi günceller.
// ============================================================

import * as path from 'path';
import * as fs from 'fs';
import chokidar from 'chokidar';
import { scanSecrets } from './scanners/secret-scanner';
import { scanRLS } from './scanners/rls-scanner';
import { scanSQLInjection } from './scanners/sql-injection-scanner';
import { scanAPIKeys } from './scanners/api-key-guardian';
import { reportToTerminal, formatIssuesForBrowser } from './reporter';
import { printRLSRecipes } from './sql-recipes';
import { writeVibeSummary } from './summary-generator';
import type { VibeSecurityConfig, SecurityIssue } from './types';

// Global state — en son tarama sonuçları
let latestIssues: SecurityIssue[] = [];
let isScanning = false;

/**
 * Konfigürasyon dosyasını yükler.
 */
function loadConfig(projectRoot: string): VibeSecurityConfig {
    const configPath = path.join(projectRoot, 'vibe-security.config.js');

    if (!fs.existsSync(configPath)) {
        console.warn(
            '⚠️  vibe-security.config.js bulunamadı. Varsayılan ayarlar kullanılacak.'
        );
        return getDefaultConfig();
    }

    try {
        // Cache'i temizle (hot reload desteği)
        delete require.cache[require.resolve(configPath)];
        const config = require(configPath) as VibeSecurityConfig;
        return config;
    } catch (err) {
        console.error(
            '❌ vibe-security.config.js yüklenirken hata:',
            (err as Error).message
        );
        return getDefaultConfig();
    }
}

/**
 * Varsayılan konfigürasyon
 */
function getDefaultConfig(): VibeSecurityConfig {
    return {
        enabled: true,
        secretScanner: {
            envFiles: ['.env', '.env.local', '.env.development'],
            sensitivePatterns: [
                { pattern: 'SUPABASE_SERVICE_ROLE_KEY', severity: 'critical', message: 'Supabase Service Role Key istemci tarafına ifşa edilmemelidir.' },
                { pattern: 'DATABASE_URL', severity: 'critical', message: 'Veritabanı bağlantı string\'i istemci tarafında görünmemelidir.' },
                { pattern: 'SECRET', severity: 'critical', message: 'SECRET içeren anahtarlar istemci tarafına ifşa edilmemelidir.' },
                { pattern: 'PRIVATE_KEY', severity: 'critical', message: 'Özel anahtarlar istemci tarafına ifşa edilmemelidir.' },
            ],
        },
        rlsScanner: {
            enabled: true,
            scanDirs: ['src'],
            extensions: ['.ts', '.tsx', '.js', '.jsx'],
            excludeDirs: ['node_modules', '.next', 'dist'],
            supabaseUrl: '',
            supabaseServiceRoleKey: '',
            whitelistedTables: [],
        },
        reporter: {
            terminal: true,
            browserOverlay: true,
            overlayAutoCloseMs: 0,
            soundAlert: false,
        },
        watcher: {
            debounceMs: 500,
            additionalWatchPatterns: [],
        },
    };
}

/**
 * Tam tarama çalıştırır — tüm tarayıcıları sırasıyla çağırır.
 */
async function runFullScan(projectRoot: string, config: VibeSecurityConfig): Promise<SecurityIssue[]> {
    if (isScanning) return latestIssues;
    isScanning = true;

    const allIssues: SecurityIssue[] = [];

    try {
        // 1) Secret Scanner — .env dosyalarını tara
        const secretResult = await scanSecrets(projectRoot, config.secretScanner);
        allIssues.push(...secretResult.issues);

        // 2) RLS Scanner — Supabase tablo kullanımlarını tara
        if (config.rlsScanner.enabled) {
            const rlsResult = await scanRLS(projectRoot, config.rlsScanner);
            allIssues.push(...rlsResult.issues);
        }

        // 3) SQL Injection Scanner — Parametresiz sorguları tara
        const sqlResult = await scanSQLInjection(
            projectRoot,
            config.rlsScanner.scanDirs,
            config.rlsScanner.extensions,
            config.rlsScanner.excludeDirs
        );
        allIssues.push(...sqlResult.issues);

        // 4) API Key Guardian — İstemci tarafı API anahtarı kullanımını tara
        const apiKeyResult = await scanAPIKeys(
            projectRoot,
            [], // Ek kurallar config'den gelebilir
            config.rlsScanner.scanDirs,
            config.rlsScanner.extensions,
            config.rlsScanner.excludeDirs
        );
        allIssues.push(...apiKeyResult.issues);

        // 5) Terminal raporu
        if (config.reporter.terminal) {
            reportToTerminal(allIssues);
        }

        // 6) RLS SQL Reçeteleri — terminal'e yazdır
        printRLSRecipes(allIssues);

        // 7) vibe-summary.txt üret
        writeVibeSummary(projectRoot, config, allIssues);

        // Global state güncelle
        latestIssues = allIssues;
    } catch (err) {
        console.error('❌ Tarama sırasında hata:', (err as Error).message);
    } finally {
        isScanning = false;
    }

    return allIssues;
}

/**
 * En son tarama sonuçlarını döndürür (API endpoint'leri tarafından kullanılır).
 */
export function getLatestIssues(): SecurityIssue[] {
    return latestIssues;
}

/**
 * En son sonuçları tarayıcı formatında döndürür.
 */
export function getLatestIssuesForBrowser(): object {
    return formatIssuesForBrowser(latestIssues);
}

/**
 * Dosya izleyiciyi başlatır ve anlık geri bildirim sağlar.
 */
export function startWatchdog(projectRoot: string): void {
    const config = loadConfig(projectRoot);

    if (!config.enabled) {
        console.log('🛡️  Vibe Security Watchdog devre dışı.');
        return;
    }

    console.log('');
    console.log('\x1b[36m\x1b[1m🛡️  Vibe Security Watchdog v2.0 başlatılıyor...\x1b[0m');
    console.log('\x1b[2m   Modüller: Secret Scanner | RLS Denetçisi | SQL Injection | API Key Guardian\x1b[0m');
    console.log('\x1b[2m   Çıktılar: Terminal Rapor | SQL Reçeteleri | vibe-summary.txt\x1b[0m');
    console.log('');

    // İlk taramayı çalıştır
    runFullScan(projectRoot, config);

    // İzlenecek dosya kalıpları
    const watchPatterns = [
        // .env dosyaları
        ...config.secretScanner.envFiles.map((f) => path.join(projectRoot, f)),
        // Kaynak dosyalar
        ...config.rlsScanner.scanDirs.map((dir) =>
            path.join(projectRoot, dir, '**', `*{${config.rlsScanner.extensions.join(',')}}`)
        ),
        // Konfigürasyon dosyası
        path.join(projectRoot, 'vibe-security.config.js'),
        // Ek kalıplar
        ...config.watcher.additionalWatchPatterns.map((p) => path.join(projectRoot, p)),
    ];

    // Debounce mekanizması
    let debounceTimer: NodeJS.Timeout | null = null;

    const watcher = chokidar.watch(watchPatterns, {
        ignored: [
            '**/node_modules/**',
            '**/.next/**',
            '**/.git/**',
            '**/dist/**',
            '**/vibe-summary.txt',  // Kendi çıktısını izleme
        ],
        persistent: true,
        ignoreInitial: true,
        awaitWriteFinish: {
            stabilityThreshold: 200,
            pollInterval: 100,
        },
    });

    const scheduleRescan = (changedPath: string) => {
        if (debounceTimer) clearTimeout(debounceTimer);

        const relativePath = path.relative(projectRoot, changedPath);
        console.log(`\x1b[2m🔄 Değişiklik algılandı: ${relativePath}\x1b[0m`);

        debounceTimer = setTimeout(() => {
            // Config değişmişse yeniden yükle
            const freshConfig = loadConfig(projectRoot);
            runFullScan(projectRoot, freshConfig);
        }, config.watcher.debounceMs);
    };

    watcher
        .on('change', scheduleRescan)
        .on('add', scheduleRescan)
        .on('unlink', scheduleRescan);
}

/**
 * Webpack Plugin olarak kullanım.
 */
export class VibeSecurityWebpackPlugin {
    private projectRoot: string;
    private initialized: boolean = false;

    constructor(projectRoot: string) {
        this.projectRoot = projectRoot;
    }

    apply(compiler: any): void {
        if (compiler.options.mode !== 'development') return;

        compiler.hooks.afterEnvironment.tap('VibeSecurityWatchdog', () => {
            if (!this.initialized) {
                this.initialized = true;
                startWatchdog(this.projectRoot);
            }
        });
    }
}
