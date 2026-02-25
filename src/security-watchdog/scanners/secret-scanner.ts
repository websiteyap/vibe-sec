// ============================================================
// 🔑 Secret Scanner — .env Dosyası Tarayıcı
// ============================================================
// .env dosyalarını tarar ve NEXT_PUBLIC_ önekiyle ifşa edilen
// kritik anahtarları tespit eder.
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import type { SecurityIssue, SecretScannerConfig, ScanResult } from '../types';

/**
 * Tek bir .env dosyasını parse eder ve key=value çiftlerini döndürür.
 * Yorumları ve boş satırları atlar.
 */
function parseEnvFile(filePath: string): { key: string; value: string; line: number }[] {
    const entries: { key: string; value: string; line: number }[] = [];

    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const lines = content.split(/\r?\n/);

        lines.forEach((rawLine, index) => {
            const trimmed = rawLine.trim();

            // Boş satır veya yorum satırı
            if (!trimmed || trimmed.startsWith('#')) return;

            // Export kaldır (bash uyumluluğu)
            const cleaned = trimmed.replace(/^export\s+/, '');

            const eqIndex = cleaned.indexOf('=');
            if (eqIndex === -1) return;

            const key = cleaned.substring(0, eqIndex).trim();
            const value = cleaned.substring(eqIndex + 1).trim().replace(/^["']|["']$/g, '');

            entries.push({ key, value, line: index + 1 });
        });
    } catch (err) {
        // Dosya okunamazsa sessizce geç
        console.warn(`⚠️  .env dosyası okunamadı: ${filePath}`, (err as Error).message);
    }

    return entries;
}

/**
 * Bir anahtar adının herhangi bir hassas kalıba uyup uymadığını kontrol eder.
 * NEXT_PUBLIC_ önekini kaldırdıktan sonra kontrol yapar.
 */
function matchesSensitivePattern(
    key: string,
    patterns: SecretScannerConfig['sensitivePatterns']
): SecretScannerConfig['sensitivePatterns'][0] | null {
    // NEXT_PUBLIC_ ile başlamayan anahtarları atla — sorun yok
    if (!key.startsWith('NEXT_PUBLIC_')) return null;

    // NEXT_PUBLIC_ önekini kaldır ve asıl adı al
    const strippedKey = key.replace(/^NEXT_PUBLIC_/, '');

    for (const patternDef of patterns) {
        const regex = new RegExp(patternDef.pattern, 'i');
        // Hem orijinal anahtar hem de temizlenmiş anahtar ile eşleştir
        if (regex.test(key) || regex.test(strippedKey)) {
            return patternDef;
        }
    }

    return null;
}

/**
 * Aynı anahtarın NEXT_PUBLIC_ olmadan da tanımlı olup olmadığını kontrol eder.
 * Tanımlıysa uyarı mesajını buna göre düzenler.
 */
function checkForDuplicateKey(
    key: string,
    allEntries: Map<string, { file: string; line: number }[]>
): string | null {
    const strippedKey = key.replace(/^NEXT_PUBLIC_/, '');

    if (allEntries.has(strippedKey)) {
        const locations = allEntries.get(strippedKey)!;
        const locStr = locations.map((l) => `${l.file}:${l.line}`).join(', ');
        return `Not: Bu anahtar NEXT_PUBLIC_ olmadan şu konumlarda da tanımlı: ${locStr}. İstemci tarafı için NEXT_PUBLIC_ versiyonunu kaldırın ve sunucu tarafı versiyonunu kullanın.`;
    }

    return null;
}

/**
 * Ana tarama fonksiyonu.
 * Proje kök dizinindeki .env dosyalarını tarar.
 */
export async function scanSecrets(
    projectRoot: string,
    config: SecretScannerConfig
): Promise<ScanResult> {
    const startTime = Date.now();
    const issues: SecurityIssue[] = [];
    const allEntries = new Map<string, { file: string; line: number }[]>();

    // 1) Tüm .env dosyalarını bul
    const envFilePaths: string[] = [];
    for (const pattern of config.envFiles) {
        const matches = await glob(pattern, {
            cwd: projectRoot,
            absolute: true,
            dot: true,
            nodir: true,
        });
        envFilePaths.push(...matches);
    }

    // Benzersiz dosyalar
    const uniqueFiles = [...new Set(envFilePaths)];

    if (uniqueFiles.length === 0) {
        return {
            issues: [],
            scannedAt: Date.now(),
            duration: Date.now() - startTime,
        };
    }

    // 2) Tüm dosyaları parse et ve anahtar haritasını oluştur
    const fileEntries = new Map<string, { key: string; value: string; line: number }[]>();

    for (const filePath of uniqueFiles) {
        const entries = parseEnvFile(filePath);
        fileEntries.set(filePath, entries);

        for (const entry of entries) {
            if (!allEntries.has(entry.key)) {
                allEntries.set(entry.key, []);
            }
            allEntries.get(entry.key)!.push({
                file: path.relative(projectRoot, filePath),
                line: entry.line,
            });
        }
    }

    // 3) Her bir giriş için hassas kalıp kontrolü
    for (const [filePath, entries] of fileEntries) {
        const relativeFile = path.relative(projectRoot, filePath);

        for (const entry of entries) {
            const match = matchesSensitivePattern(entry.key, config.sensitivePatterns);

            if (match) {
                // Değerin boş olup olmadığını kontrol et
                const hasValue = entry.value.length > 0;
                const valueWarning = hasValue
                    ? `Değer atanmış (${entry.value.length} karakter). Bu değer istemci JavaScript bundle'ına dahil edilecek!`
                    : 'Değer boş, ancak anahtar tanımı bile risklidir.';

                // Duplicate key kontrolü
                const duplicateNote = checkForDuplicateKey(entry.key, allEntries);

                const issueId = `secret-${relativeFile}-${entry.key}-${entry.line}`;
                const fullMessage = [
                    match.message,
                    '',
                    `📌 Konum: ${relativeFile}:${entry.line}`,
                    `🔑 Anahtar: ${entry.key}`,
                    `📊 ${valueWarning}`,
                    '',
                    `💡 Çözüm: NEXT_PUBLIC_ önekini kaldırın ve bu değişkeni sadece sunucu tarafı kodlarından (API routes, Server Components, Server Actions) erişin.`,
                    duplicateNote ? `\n${duplicateNote}` : '',
                ]
                    .filter(Boolean)
                    .join('\n');

                issues.push({
                    id: issueId,
                    category: 'secret-leak',
                    severity: match.severity,
                    title: `🚨 GÜVENLİK RİSKİ: '${entry.key}' istemci tarafına ifşa ediliyor!`,
                    message: fullMessage,
                    file: relativeFile,
                    line: entry.line,
                    key: entry.key,
                    timestamp: Date.now(),
                });
            }
        }
    }

    // 4) Ek kontrol: .env dosyasının .gitignore'da olup olmadığını kontrol et
    try {
        const gitignorePath = path.join(projectRoot, '.gitignore');
        if (fs.existsSync(gitignorePath)) {
            const gitignoreContent = fs.readFileSync(gitignorePath, 'utf-8');
            const hasEnvLocal = gitignoreContent.includes('.env*.local') || gitignoreContent.includes('.env.local');
            const hasEnv = gitignoreContent.includes('.env');

            if (!hasEnvLocal && !hasEnv) {
                issues.push({
                    id: 'gitignore-env-missing',
                    category: 'general',
                    severity: 'warning',
                    title: '⚠️ .env dosyaları .gitignore\'a eklenmemiş!',
                    message: [
                        '.env dosyalarınız .gitignore dosyasında yer almıyor.',
                        'Bu dosyalar yanlışlıkla git repository\'sine commit edilebilir.',
                        '',
                        '💡 Çözüm: .gitignore dosyanıza şu satırları ekleyin:',
                        '   .env',
                        '   .env.local',
                        '   .env*.local',
                    ].join('\n'),
                    file: '.gitignore',
                    timestamp: Date.now(),
                });
            }
        }
    } catch {
        // .gitignore kontrolü başarısızsa sessizce geç
    }

    return {
        issues,
        scannedAt: Date.now(),
        duration: Date.now() - startTime,
    };
}
