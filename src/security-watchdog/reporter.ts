// ============================================================
// 📢 Reporter — Terminal ve Tarayıcı Raporlayıcı
// ============================================================
// Güvenlik sorunlarını terminal ve tarayıcı konsoluna raporlar.
// Tarayıcı overlay'i için API endpoint'e veri gönderir.
// ============================================================

import type { SecurityIssue, ReporterConfig } from './types';

// ANSI renk kodları
const COLORS = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    dim: '\x1b[2m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    bgRed: '\x1b[41m',
    bgYellow: '\x1b[43m',
    bgBlue: '\x1b[44m',
};

const SEVERITY_STYLES = {
    critical: {
        badge: `${COLORS.bgRed}${COLORS.white}${COLORS.bold} CRITICAL ${COLORS.reset}`,
        color: COLORS.red,
        icon: '🚨',
    },
    warning: {
        badge: `${COLORS.bgYellow}${COLORS.bold} WARNING ${COLORS.reset}`,
        color: COLORS.yellow,
        icon: '⚠️',
    },
    info: {
        badge: `${COLORS.bgBlue}${COLORS.white} INFO ${COLORS.reset}`,
        color: COLORS.blue,
        icon: 'ℹ️',
    },
};

const DIVIDER = `${COLORS.dim}${'─'.repeat(70)}${COLORS.reset}`;
const HEADER_LINE = `${COLORS.dim}${'═'.repeat(70)}${COLORS.reset}`;

/**
 * Terminal'e güvenlik uyarılarını yazdırır.
 */
export function reportToTerminal(issues: SecurityIssue[]): void {
    if (issues.length === 0) {
        console.log(
            `\n${COLORS.cyan}${COLORS.bold}🛡️  Vibe Security Watchdog${COLORS.reset} ${COLORS.dim}— Tarama tamamlandı, sorun bulunamadı. ✅${COLORS.reset}\n`
        );
        return;
    }

    const criticalCount = issues.filter((i) => i.severity === 'critical').length;
    const warningCount = issues.filter((i) => i.severity === 'warning').length;
    const infoCount = issues.filter((i) => i.severity === 'info').length;

    console.log('');
    console.log(HEADER_LINE);
    console.log(
        `${COLORS.bold}${COLORS.red}  🛡️  VIBE SECURITY WATCHDOG — GÜVENLİK RAPORU${COLORS.reset}`
    );
    console.log(HEADER_LINE);
    console.log('');

    // Özet
    const summaryParts: string[] = [];
    if (criticalCount > 0) summaryParts.push(`${COLORS.red}${COLORS.bold}${criticalCount} Kritik${COLORS.reset}`);
    if (warningCount > 0) summaryParts.push(`${COLORS.yellow}${warningCount} Uyarı${COLORS.reset}`);
    if (infoCount > 0) summaryParts.push(`${COLORS.blue}${infoCount} Bilgi${COLORS.reset}`);

    console.log(`  📊 Toplam ${issues.length} sorun bulundu: ${summaryParts.join(' · ')}`);
    console.log('');

    // Sorunları sıralı şekilde göster (critical > warning > info)
    const sortedIssues = [...issues].sort((a, b) => {
        const order = { critical: 0, warning: 1, info: 2 };
        return order[a.severity] - order[b.severity];
    });

    sortedIssues.forEach((issue, index) => {
        const style = SEVERITY_STYLES[issue.severity];
        console.log(DIVIDER);
        console.log(`  ${style.badge} ${style.color}${COLORS.bold}${issue.title}${COLORS.reset}`);
        console.log('');

        // Mesajı satır satır yazdır, her satıra girinti ekle
        const messageLines = issue.message.split('\n');
        messageLines.forEach((line) => {
            console.log(`  ${COLORS.dim}${line}${COLORS.reset}`);
        });

        console.log('');
    });

    console.log(HEADER_LINE);
    console.log(
        `  ${COLORS.dim}Tarama zamanı: ${new Date().toLocaleTimeString('tr-TR')}${COLORS.reset}`
    );
    console.log(
        `  ${COLORS.dim}Daha fazla bilgi: vibe-security.config.js${COLORS.reset}`
    );
    console.log(HEADER_LINE);
    console.log('');
}

/**
 * Sorunları JSON formatında döndürür (API ve browser overlay için).
 */
export function formatIssuesForBrowser(issues: SecurityIssue[]): object {
    return {
        timestamp: Date.now(),
        issueCount: issues.length,
        summary: {
            critical: issues.filter((i) => i.severity === 'critical').length,
            warning: issues.filter((i) => i.severity === 'warning').length,
            info: issues.filter((i) => i.severity === 'info').length,
        },
        issues: issues.map((issue) => ({
            id: issue.id,
            category: issue.category,
            severity: issue.severity,
            title: issue.title,
            message: issue.message,
            file: issue.file,
            line: issue.line,
            key: issue.key,
            table: issue.table,
            timestamp: issue.timestamp,
        })),
    };
}
