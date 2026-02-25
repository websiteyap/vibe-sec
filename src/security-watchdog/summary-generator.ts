// ============================================================
// 📋 Vibe Summary Generator — AI Context Sıkıştırıcı
// ============================================================
// Tarama sonuçlarından otomatik olarak vibe-summary.txt üretir.
// Diğer AI araçları bu dosyayı okuyarak projenin güvenlik
// kurallarını anlar.
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import type { SecurityIssue, VibeSecurityConfig } from './types';
import { generateBulkRLSRecipes } from './sql-recipes';

/**
 * vibe-summary.txt dosyasını üretir.
 */
export function generateVibeSummary(
    projectRoot: string,
    config: VibeSecurityConfig,
    issues: SecurityIssue[]
): string {
    const now = new Date().toLocaleString('tr-TR');

    // İstatistikler
    const criticalCount = issues.filter((i) => i.severity === 'critical').length;
    const warningCount = issues.filter((i) => i.severity === 'warning').length;
    const infoCount = issues.filter((i) => i.severity === 'info').length;

    // Kategori bazlı grupla
    const secretLeaks = issues.filter((i) => i.category === 'secret-leak');
    const rlsIssues = issues.filter((i) => i.category === 'rls-missing' || i.category === 'rls-no-auth' || i.category === 'rls-check');
    const sqlInjections = issues.filter((i) => i.id.startsWith('sqli-'));
    const apiKeyIssues = issues.filter((i) => i.id.startsWith('apikey-'));
    const generalIssues = issues.filter(
        (i) => i.category === 'general' && !i.id.startsWith('sqli-') && !i.id.startsWith('apikey-')
    );

    // Kullanılan tablolar
    const tables = [...new Set(rlsIssues.map((i) => i.table).filter(Boolean))] as string[];

    // İfşa edilen anahtarlar
    const exposedKeys = [...new Set(secretLeaks.map((i) => i.key).filter(Boolean))] as string[];

    // Özet oluştur
    const sections: string[] = [];

    // ─── Header ───
    sections.push(`# 🛡️ VIBE SECURITY SUMMARY`);
    sections.push(`# Bu dosya Vibe Security Watchdog tarafından otomatik üretilmiştir.`);
    sections.push(`# Son güncelleme: ${now}`);
    sections.push(`# Bu dosyayı AI araçlarına (Cursor, Copilot, vb.) context olarak verin.`);
    sections.push(``);

    // ─── Proje Güvenlik Durumu ───
    sections.push(`## 📊 PROJE GÜVENLİK DURUMU`);
    sections.push(``);
    if (criticalCount === 0 && warningCount === 0) {
        sections.push(`✅ DURUM: TEMİZ — Bilinen güvenlik sorunu yok.`);
    } else if (criticalCount > 0) {
        sections.push(`🚨 DURUM: KRİTİK — ${criticalCount} kritik, ${warningCount} uyarı, ${infoCount} bilgi`);
    } else {
        sections.push(`⚠️ DURUM: UYARI — ${warningCount} uyarı, ${infoCount} bilgi`);
    }
    sections.push(``);

    // ─── Zorunlu Kurallar ───
    sections.push(`## 📜 ZORUNLU GÜVENLİK KURALLARI`);
    sections.push(``);
    sections.push(`Bu projede aşağıdaki kurallar ZORUNLUDUR:`);
    sections.push(``);

    // Rule 1: Secret Management
    sections.push(`### 1. ÇEVRE DEĞİŞKENLERİ (ENV)`);
    sections.push(`- NEXT_PUBLIC_ öneki SADECE istemci tarafında güvenli olan değerler için kullanılır.`);
    sections.push(`- Aşağıdaki kalıplar ASLA NEXT_PUBLIC_ ile kullanılmamalıdır:`);
    for (const pattern of config.secretScanner.sensitivePatterns) {
        sections.push(`  - ${pattern.pattern} → ${pattern.severity.toUpperCase()}: ${pattern.message}`);
    }
    sections.push(``);

    if (exposedKeys.length > 0) {
        sections.push(`⚠️ Şu anda İFŞA EDİLEN anahtarlar:`);
        for (const key of exposedKeys) {
            sections.push(`  - ❌ ${key}`);
        }
        sections.push(``);
    }

    // Rule 2: RLS
    sections.push(`### 2. SUPABASE ROW LEVEL SECURITY (RLS)`);
    sections.push(`- Bu projede RLS ZORUNLUDUR.`);
    sections.push(`- Her tablo için auth.uid() bazlı politikalar oluşturulmalıdır.`);
    sections.push(`- Beyaz listelenmiş tablolar: ${config.rlsScanner.whitelistedTables.length > 0 ? config.rlsScanner.whitelistedTables.join(', ') : 'Yok'}`);
    sections.push(``);

    if (tables.length > 0) {
        sections.push(`📋 Projede kullanılan tablolar:`);
        for (const table of tables) {
            const issue = rlsIssues.find((i) => i.table === table);
            const status = issue?.category === 'rls-missing'
                ? '❌ RLS YOK'
                : issue?.category === 'rls-no-auth'
                    ? '⚠️ auth.uid() eksik'
                    : '🔍 Kontrol gerekli';
            sections.push(`  - ${table}: ${status}`);
        }
        sections.push(``);
    }

    // Rule 3: SQL Injection
    sections.push(`### 3. SQL INJECTION KORUNMASI`);
    sections.push(`- supabase.rpc() çağrılarında template literal (\${}) KULLANILMAZ.`);
    sections.push(`- Ham SQL sorguları string birleştirme (+) ile OLUŞTURULMAZ.`);
    sections.push(`- Parametreli sorgular (prepared statements) ZORUNLUDUR.`);
    sections.push(`- .filter() ve .or() içinde kullanıcı girdisi doğrudan GÖMÜLMEMELİDİR.`);
    sections.push(``);

    if (sqlInjections.length > 0) {
        sections.push(`⚠️ Şu anda ${sqlInjections.length} SQL injection riski tespit edildi.`);
        sections.push(``);
    }

    // Rule 4: API Keys
    sections.push(`### 4. API ANAHTARI GÜVENLİĞİ`);
    sections.push(`- Serper.dev, OpenAI, Anthropic, Google AI anahtarları SADECE sunucu tarafında kullanılır.`);
    sections.push(`- Bu hizmetlere erişim API Route'lar (/api/*) üzerinden proksilemellidir.`);
    sections.push(`- "use client" dosyalarında bu hizmetlere doğrudan erişim YASAKTIR.`);
    sections.push(``);

    // ─── Mimari Kurallar ───
    sections.push(`## 🏗️ MİMARİ KURALLAR`);
    sections.push(``);
    sections.push(`- Next.js App Router kullanılıyor.`);
    sections.push(`- Hassas işlemler: Server Components, API Routes, Server Actions.`);
    sections.push(`- İstemci tarafı: Sadece UI rendering ve kullanıcı etkileşimi.`);
    sections.push(`- Veritabanı erişimi: Her zaman RLS korumalı Supabase client.`);
    sections.push(`- Harici API'ler: Her zaman /api/* proxy üzerinden.`);
    sections.push(``);

    // ─── Aktif Sorunlar ───
    if (issues.length > 0) {
        sections.push(`## 🚨 AKTİF GÜVENLİK SORUNLARI`);
        sections.push(``);

        const sorted = [...issues].sort((a, b) => {
            const order = { critical: 0, warning: 1, info: 2 };
            return (order[a.severity] ?? 2) - (order[b.severity] ?? 2);
        });

        for (const issue of sorted) {
            const icon = issue.severity === 'critical' ? '🔴' : issue.severity === 'warning' ? '🟡' : '🔵';
            sections.push(`${icon} [${issue.severity.toUpperCase()}] ${issue.title}`);
            if (issue.file) {
                sections.push(`   📄 ${issue.file}${issue.line ? `:${issue.line}` : ''}`);
            }
        }
        sections.push(``);
    }

    // ─── SQL Recipes ───
    if (tables.length > 0) {
        sections.push(`## 📝 HAZIR SQL REÇETELERİ`);
        sections.push(``);
        sections.push(`Aşağıdaki SQL'i Supabase SQL Editor'da çalıştırarak RLS'i etkinleştirin:`);
        sections.push(``);
        sections.push('```sql');
        sections.push(generateBulkRLSRecipes(tables));
        sections.push('```');
        sections.push(``);
    }

    // ─── Footer ───
    sections.push(`---`);
    sections.push(`Bu dosya "npm run security" çalıştırıldığında güncellenir.`);
    sections.push(`Kuralları özelleştirmek için: vibe-security.config.js`);
    sections.push(`Kaynak: https://github.com/vibe-sec/watchdog`);

    return sections.join('\n');
}

/**
 * vibe-summary.txt dosyasını diske yazar.
 */
export function writeVibeSummary(
    projectRoot: string,
    config: VibeSecurityConfig,
    issues: SecurityIssue[]
): void {
    const content = generateVibeSummary(projectRoot, config, issues);
    const summaryPath = path.join(projectRoot, 'vibe-summary.txt');

    try {
        fs.writeFileSync(summaryPath, content, 'utf-8');
        console.log(`\x1b[32m\x1b[1m  📋 vibe-summary.txt güncellendi.\x1b[0m`);
        console.log(`\x1b[2m     AI araçlarına bu dosyayı context olarak verin.\x1b[0m`);
    } catch (err) {
        console.error(`❌ vibe-summary.txt yazılırken hata: ${(err as Error).message}`);
    }
}
