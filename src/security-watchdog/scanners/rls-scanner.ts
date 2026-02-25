// ============================================================
// 🛡️ RLS Scanner — Supabase Row Level Security Denetçisi
// ============================================================
// Kaynak kodda supabase.from('table_name') çağrılarını bulur
// ve bu tablolarda RLS'in aktif olup olmadığını kontrol eder.
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import type { SecurityIssue, RLSScannerConfig, ScanResult } from '../types';

/**
 * supabase.from('table_name') ifadelerini yakalayan regex
 * Çeşitli varyasyonları destekler:
 *  - supabase.from('posts')
 *  - supabase.from("posts")
 *  - supabase.from(`posts`)
 *  - client.from('posts') — supabase client farklı isimle kullanılabilir
 */
const SUPABASE_FROM_REGEX = /\.from\(\s*['"`]([a-zA-Z_][a-zA-Z0-9_]*)['"`]\s*\)/g;

/**
 * Bir dosyadaki tüm supabase.from() çağrılarını bulur.
 */
function findSupabaseQueries(
    filePath: string
): { table: string; line: number; context: string }[] {
    const results: { table: string; line: number; context: string }[] = [];

    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const lines = content.split(/\r?\n/);

        lines.forEach((lineContent, index) => {
            let match: RegExpExecArray | null;
            const regex = new RegExp(SUPABASE_FROM_REGEX.source, 'g');

            while ((match = regex.exec(lineContent)) !== null) {
                results.push({
                    table: match[1],
                    line: index + 1,
                    context: lineContent.trim(),
                });
            }
        });
    } catch (err) {
        console.warn(`⚠️  Dosya okunamadı: ${filePath}`, (err as Error).message);
    }

    return results;
}

/**
 * Supabase Management API aracılığıyla bir tablonun RLS durumunu kontrol eder.
 * pg_tables veya information_schema üzerinden sorgu yapar.
 */
async function checkRLSStatus(
    tableName: string,
    supabaseUrl: string,
    serviceRoleKey: string
): Promise<{ rlsEnabled: boolean; hasAuthPolicy: boolean; error?: string }> {
    if (!supabaseUrl || !serviceRoleKey) {
        return {
            rlsEnabled: false,
            hasAuthPolicy: false,
            error: 'Supabase bağlantı bilgileri eksik. SUPABASE_URL ve SUPABASE_SERVICE_ROLE_KEY ayarlanmalıdır.',
        };
    }

    try {
        // REST API üzerinden pg_tables sorgusu ile RLS durumunu kontrol et
        const rlsCheckUrl = `${supabaseUrl}/rest/v1/rpc/check_rls_status`;

        const response = await fetch(rlsCheckUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'apikey': serviceRoleKey,
                'Authorization': `Bearer ${serviceRoleKey}`,
            },
            body: JSON.stringify({ target_table: tableName }),
        });

        if (!response.ok) {
            // RPC fonksiyonu yoksa, doğrudan pg_catalog ile dene
            return await checkRLSViaDirectQuery(tableName, supabaseUrl, serviceRoleKey);
        }

        const data = await response.json();
        return {
            rlsEnabled: data?.rls_enabled ?? false,
            hasAuthPolicy: data?.has_auth_policy ?? false,
        };
    } catch (err) {
        return {
            rlsEnabled: false,
            hasAuthPolicy: false,
            error: `RLS durumu kontrol edilemedi: ${(err as Error).message}`,
        };
    }
}

/**
 * Alternatif RLS kontrolü — pg_class üzerinden doğrudan sorgu
 */
async function checkRLSViaDirectQuery(
    tableName: string,
    supabaseUrl: string,
    serviceRoleKey: string
): Promise<{ rlsEnabled: boolean; hasAuthPolicy: boolean; error?: string }> {
    try {
        // pg_class üzerinden relrowsecurity kontrolü
        const sqlQuery = `
      SELECT 
        c.relrowsecurity as rls_enabled,
        EXISTS (
          SELECT 1 FROM pg_policies p 
          WHERE p.tablename = '${tableName}' 
          AND p.schemaname = 'public'
          AND (p.qual::text LIKE '%auth.uid()%' OR p.with_check::text LIKE '%auth.uid()%')
        ) as has_auth_policy
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relname = '${tableName}'
      AND n.nspname = 'public'
    `;

        const response = await fetch(`${supabaseUrl}/rest/v1/rpc/exec_sql`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'apikey': serviceRoleKey,
                'Authorization': `Bearer ${serviceRoleKey}`,
            },
            body: JSON.stringify({ query: sqlQuery }),
        });

        if (!response.ok) {
            // SQL fonksiyonları mevcut değil — sadece uyarı ver
            return {
                rlsEnabled: false,
                hasAuthPolicy: false,
                error: `RLS kontrolü için Supabase RPC fonksiyonları mevcut değil. Manuel kontrol önerilir. Detay: Supabase SQL Editor'da "SELECT relrowsecurity FROM pg_class WHERE relname = '${tableName}'" sorgusunu çalıştırın.`,
            };
        }

        const data = await response.json();
        if (Array.isArray(data) && data.length > 0) {
            return {
                rlsEnabled: data[0].rls_enabled ?? false,
                hasAuthPolicy: data[0].has_auth_policy ?? false,
            };
        }

        return {
            rlsEnabled: false,
            hasAuthPolicy: false,
            error: `'${tableName}' tablosu bulunamadı veya erişilemedi.`,
        };
    } catch (err) {
        return {
            rlsEnabled: false,
            hasAuthPolicy: false,
            error: `Doğrudan SQL kontrolü başarısız: ${(err as Error).message}`,
        };
    }
}

/**
 * Ana RLS tarama fonksiyonu.
 * Kaynak koddaki tüm supabase.from() çağrılarını bulur
 * ve her tablo için RLS durumunu kontrol eder.
 */
export async function scanRLS(
    projectRoot: string,
    config: RLSScannerConfig
): Promise<ScanResult> {
    const startTime = Date.now();
    const issues: SecurityIssue[] = [];

    if (!config.enabled) {
        return { issues: [], scannedAt: Date.now(), duration: 0 };
    }

    // 1) Taranacak dosyaları bul
    const sourceFiles: string[] = [];
    for (const dir of config.scanDirs) {
        const dirPath = path.join(projectRoot, dir);
        if (!fs.existsSync(dirPath)) continue;

        const extensionPatterns = config.extensions.map((ext) => `**/*${ext}`);
        for (const pattern of extensionPatterns) {
            const matches = await glob(pattern, {
                cwd: dirPath,
                absolute: true,
                ignore: config.excludeDirs.map((d) => `**/${d}/**`),
            });
            sourceFiles.push(...matches);
        }
    }

    // 2) Tüm dosyalarda supabase.from() çağrılarını bul
    const tableUsages = new Map<string, { file: string; line: number; context: string }[]>();

    for (const filePath of sourceFiles) {
        const queries = findSupabaseQueries(filePath);
        for (const query of queries) {
            if (!tableUsages.has(query.table)) {
                tableUsages.set(query.table, []);
            }
            tableUsages.get(query.table)!.push({
                file: path.relative(projectRoot, filePath),
                line: query.line,
                context: query.context,
            });
        }
    }

    if (tableUsages.size === 0) {
        return { issues: [], scannedAt: Date.now(), duration: Date.now() - startTime };
    }

    // 3) Her benzersiz tablo için RLS durumunu kontrol et
    const checkedTables = new Set<string>();

    for (const [tableName, usages] of tableUsages) {
        if (checkedTables.has(tableName)) continue;
        checkedTables.add(tableName);

        // Beyaz listede mi kontrol et
        if (config.whitelistedTables.includes(tableName)) continue;

        const rlsStatus = await checkRLSStatus(
            tableName,
            config.supabaseUrl,
            config.supabaseServiceRoleKey
        );

        // RLS aktif değilse
        if (!rlsStatus.rlsEnabled) {
            const usageLocations = usages
                .map((u) => `  📄 ${u.file}:${u.line} → ${u.context}`)
                .join('\n');

            issues.push({
                id: `rls-disabled-${tableName}`,
                category: 'rls-missing',
                severity: 'critical',
                title: `🚨 GÜVENLİK RİSKİ: '${tableName}' tablosunda RLS aktif değil! Verilerin ifşa olabilir.`,
                message: [
                    `'${tableName}' tablosunda Row Level Security (RLS) aktif değil.`,
                    'Bu, tüm kullanıcıların bu tablodaki tüm verilere erişebileceği anlamına gelir.',
                    '',
                    '📍 Bu tablo şu dosyalarda kullanılıyor:',
                    usageLocations,
                    '',
                    rlsStatus.error ? `⚠️  ${rlsStatus.error}` : '',
                    '',
                    '💡 Çözüm: Supabase Dashboard → Authentication → Policies bölümünden',
                    `   ALTER TABLE public.${tableName} ENABLE ROW LEVEL SECURITY;`,
                    '   komutuyla RLS\'i aktif edin ve uygun politikalar oluşturun.',
                ]
                    .filter(Boolean)
                    .join('\n'),
                table: tableName,
                timestamp: Date.now(),
            });
        }

        // RLS aktif ama auth.uid() politikası yoksa
        if (rlsStatus.rlsEnabled && !rlsStatus.hasAuthPolicy && !rlsStatus.error) {
            const usageLocations = usages
                .map((u) => `  📄 ${u.file}:${u.line} → ${u.context}`)
                .join('\n');

            issues.push({
                id: `rls-no-auth-${tableName}`,
                category: 'rls-no-auth',
                severity: 'warning',
                title: `⚠️ '${tableName}' tablosunda auth.uid() kontrolü bulunamadı!`,
                message: [
                    `'${tableName}' tablosunda RLS aktif, ancak auth.uid() kontrolü içeren bir politika bulunamadı.`,
                    'Bu, kullanıcıların diğer kullanıcıların verilerine erişebileceği anlamına gelebilir.',
                    '',
                    '📍 Bu tablo şu dosyalarda kullanılıyor:',
                    usageLocations,
                    '',
                    '💡 Çözüm: Tabloya auth.uid() kontrolü içeren bir RLS politikası ekleyin:',
                    `   CREATE POLICY "Users can view own data" ON public.${tableName}`,
                    `     FOR SELECT USING (auth.uid() = user_id);`,
                ].join('\n'),
                table: tableName,
                timestamp: Date.now(),
            });
        }
    }

    return {
        issues,
        scannedAt: Date.now(),
        duration: Date.now() - startTime,
    };
}
