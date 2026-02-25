// ============================================================
// 📝 SQL Recipe Generator — Otomatik RLS Reçeteleri
// ============================================================
// RLS eksik tablolar için hazır SQL komutları üretir.
// Terminal'e ve vibe-summary.txt'e yazdırır.
// ============================================================

import type { SecurityIssue } from '../types';

/**
 * Bir tablo için standart RLS politikalarını içeren SQL bloğu üretir.
 */
export function generateRLSRecipe(tableName: string): string {
    return `
-- ============================================================
-- 🛡️ RLS Reçetesi: "${tableName}" tablosu
-- ============================================================
-- Bu SQL bloğunu Supabase SQL Editor'da çalıştırın.
-- ============================================================

-- 1) Row Level Security'yi aktif et
ALTER TABLE public.${tableName} ENABLE ROW LEVEL SECURITY;

-- 2) Tablo sahipliğini doğrula (gerekirse)
-- ALTER TABLE public.${tableName} OWNER TO postgres;

-- ============================================================
-- OKUMA POLİTİKASI (SELECT)
-- Kullanıcılar sadece kendi verilerini görebilir
-- ============================================================
CREATE POLICY "${tableName}_select_own"
  ON public.${tableName}
  FOR SELECT
  USING (auth.uid() = user_id);

-- Alternatif: Herkes okuyabilir (public veri)
-- CREATE POLICY "${tableName}_select_public"
--   ON public.${tableName}
--   FOR SELECT
--   USING (true);

-- ============================================================
-- EKLEME POLİTİKASI (INSERT)
-- Kullanıcılar sadece kendi adlarına kayıt ekleyebilir
-- ============================================================
CREATE POLICY "${tableName}_insert_own"
  ON public.${tableName}
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- ============================================================
-- GÜNCELLEME POLİTİKASI (UPDATE)
-- Kullanıcılar sadece kendi kayıtlarını güncelleyebilir
-- ============================================================
CREATE POLICY "${tableName}_update_own"
  ON public.${tableName}
  FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- ============================================================
-- SİLME POLİTİKASI (DELETE)
-- Kullanıcılar sadece kendi kayıtlarını silebilir
-- ============================================================
CREATE POLICY "${tableName}_delete_own"
  ON public.${tableName}
  FOR DELETE
  USING (auth.uid() = user_id);

-- ============================================================
-- ⚠️ ÖNEMLİ NOTLAR:
-- 1. "user_id" sütunu tablonuzda yoksa, doğru sütun adını kullanın.
-- 2. "auth.uid()" Supabase Auth kullanıcı ID'sini döndürür.
-- 3. Service Role Key bu politikaları ATLAR — dikkatli kullanın.
-- 4. Anon key ile yapılan tüm sorgular bu politikalara tabidir.
-- ============================================================
`.trim();
}

/**
 * Birden fazla tablo için toplu SQL reçetesi üretir.
 */
export function generateBulkRLSRecipes(tableNames: string[]): string {
    const header = `
-- ================================================================
-- 🛡️ VIBE SECURITY WATCHDOG — TOPLU RLS REÇETELERİ
-- ================================================================
-- Oluşturulma: ${new Date().toLocaleString('tr-TR')}
-- Toplam ${tableNames.length} tablo için RLS reçetesi
-- ================================================================
-- Bu dosyayı Supabase SQL Editor'a yapıştırın ve çalıştırın.
-- ⚠️ Çalıştırmadan önce "user_id" sütunlarını kontrol edin!
-- ================================================================
`.trim();

    const recipes = tableNames.map((t) => generateRLSRecipe(t));
    return [header, '', ...recipes].join('\n\n');
}

/**
 * RLS eksik tabloları güvenlik sorunlarından çıkarır
 * ve SQL reçetelerini terminal'e yazdırır.
 */
export function printRLSRecipes(issues: SecurityIssue[]): void {
    const rlsIssues = issues.filter(
        (i) => i.category === 'rls-missing' || i.category === 'rls-check'
    );

    if (rlsIssues.length === 0) return;

    const tableNames = [
        ...new Set(
            rlsIssues
                .map((i) => i.table)
                .filter((t): t is string => !!t)
        ),
    ];

    if (tableNames.length === 0) return;

    const C = {
        reset: '\x1b[0m',
        bold: '\x1b[1m',
        dim: '\x1b[2m',
        cyan: '\x1b[36m',
        green: '\x1b[32m',
        yellow: '\x1b[33m',
    };

    console.log('');
    console.log(`${C.cyan}${C.bold}  📝 OTOMATİK SQL REÇETELERİ${C.reset}`);
    console.log(`${C.dim}  Aşağıdaki SQL'i Supabase SQL Editor'a yapıştırın:${C.reset}`);
    console.log('');

    for (const tableName of tableNames) {
        console.log(`${C.yellow}${C.bold}  ── ${tableName} ──${C.reset}`);
        console.log('');
        console.log(`${C.green}  ALTER TABLE public.${tableName} ENABLE ROW LEVEL SECURITY;${C.reset}`);
        console.log('');
        console.log(`${C.dim}  -- SELECT: Sadece kendi verilerini görsün${C.reset}`);
        console.log(`${C.green}  CREATE POLICY "${tableName}_select_own"${C.reset}`);
        console.log(`${C.green}    ON public.${tableName} FOR SELECT${C.reset}`);
        console.log(`${C.green}    USING (auth.uid() = user_id);${C.reset}`);
        console.log('');
        console.log(`${C.dim}  -- INSERT: Kendi adına kayıt ekleyebilsin${C.reset}`);
        console.log(`${C.green}  CREATE POLICY "${tableName}_insert_own"${C.reset}`);
        console.log(`${C.green}    ON public.${tableName} FOR INSERT${C.reset}`);
        console.log(`${C.green}    WITH CHECK (auth.uid() = user_id);${C.reset}`);
        console.log('');
        console.log(`${C.dim}  -- UPDATE: Kendi kaydını güncelleyebilsin${C.reset}`);
        console.log(`${C.green}  CREATE POLICY "${tableName}_update_own"${C.reset}`);
        console.log(`${C.green}    ON public.${tableName} FOR UPDATE${C.reset}`);
        console.log(`${C.green}    USING (auth.uid() = user_id)${C.reset}`);
        console.log(`${C.green}    WITH CHECK (auth.uid() = user_id);${C.reset}`);
        console.log('');
        console.log(`${C.dim}  -- DELETE: Kendi kaydını silebilsin${C.reset}`);
        console.log(`${C.green}  CREATE POLICY "${tableName}_delete_own"${C.reset}`);
        console.log(`${C.green}    ON public.${tableName} FOR DELETE${C.reset}`);
        console.log(`${C.green}    USING (auth.uid() = user_id);${C.reset}`);
        console.log('');
    }

    console.log(`${C.dim}  ⚠️  "user_id" sütununu tablolarınıza göre düzenleyin.${C.reset}`);
    console.log('');
}
