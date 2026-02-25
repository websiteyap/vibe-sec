#!/usr/bin/env node
// ============================================================
// 🛡️ Vibe Security Watchdog v2.0 — Standalone CLI
// ============================================================
// npm run security        → Tek seferlik tarama
// npm run security:watch  → Sürekli izleme
// ============================================================

const path = require('path');
const fs = require('fs');

// ─── ANSI Colors ───
const C = {
    reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
    red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
    blue: '\x1b[34m', magenta: '\x1b[35m', cyan: '\x1b[36m',
    white: '\x1b[37m', bgRed: '\x1b[41m', bgYellow: '\x1b[43m',
    bgBlue: '\x1b[44m', bgMagenta: '\x1b[45m', bgGreen: '\x1b[42m',
};
const LINE = `${C.dim}${'─'.repeat(70)}${C.reset}`;
const DLINE = `${C.dim}${'═'.repeat(70)}${C.reset}`;

// ─── .env Parser ───
function parseEnvFile(filePath) {
    const entries = [];
    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        content.split(/\r?\n/).forEach((rawLine, index) => {
            const trimmed = rawLine.trim();
            if (!trimmed || trimmed.startsWith('#')) return;
            const cleaned = trimmed.replace(/^export\s+/, '');
            const eqIndex = cleaned.indexOf('=');
            if (eqIndex === -1) return;
            const key = cleaned.substring(0, eqIndex).trim();
            const value = cleaned.substring(eqIndex + 1).trim().replace(/^["']|["']$/g, '');
            entries.push({ key, value, line: index + 1 });
        });
    } catch { }
    return entries;
}

// ─── File Walker ───
function walkDir(currentDir, extensions, excludeDirs) {
    const results = [];
    try {
        const entries = fs.readdirSync(currentDir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(currentDir, entry.name);
            if (entry.isDirectory()) {
                if (!excludeDirs.includes(entry.name)) walkDir(fullPath, extensions, excludeDirs).forEach(r => results.push(r));
            } else if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) {
                results.push(fullPath);
            }
        }
    } catch { }
    return results;
}

// ─── Supabase From Finder ───
function findSupabaseFromCalls(files, projectRoot) {
    const tables = new Map();
    const regex = /\.from\(\s*['"`]([a-zA-Z_][a-zA-Z0-9_]*)['"`]\s*\)/g;
    for (const filePath of files) {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            content.split(/\r?\n/).forEach((line, idx) => {
                let match;
                const lr = new RegExp(regex.source, 'g');
                while ((match = lr.exec(line)) !== null) {
                    const table = match[1];
                    if (!tables.has(table)) tables.set(table, []);
                    tables.get(table).push({ file: path.relative(projectRoot, filePath), line: idx + 1, context: line.trim() });
                }
            });
        } catch { }
    }
    return tables;
}

// ─── SQL Injection Scanner ───
function scanSQLInjection(files, projectRoot) {
    const issues = [];
    const patterns = [
        { regex: /\.rpc\(\s*['"`]\w+['"`]\s*,\s*\{[^}]*`[^`]*\$\{[^}]+\}[^`]*`[^}]*\}/g, id: 'rpc-template', title: 'supabase.rpc() içinde template literal' },
        { regex: /\.rpc\(\s*['"`]\w+['"`]\s*,\s*\{[^}]*:\s*[a-zA-Z_$]\w*\s*\+\s*['"`]/g, id: 'rpc-concat', title: 'supabase.rpc() içinde string birleştirme' },
        { regex: /`\s*(?:SELECT|INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|TRUNCATE)\b[^`]*\$\{[^}]+\}[^`]*`/gi, id: 'raw-sql-tpl', title: 'Ham SQL\'de template literal' },
        { regex: /['"`]\s*(?:SELECT|INSERT|UPDATE|DELETE|ALTER|DROP|CREATE)\b[^'"`]*['"`]\s*\+\s*[a-zA-Z_$]\w*/gi, id: 'raw-sql-concat', title: 'Ham SQL\'de string birleştirme' },
        { regex: /\.(?:filter|or|and)\(\s*`[^`]*\$\{[^}]+\}[^`]*`\s*\)/g, id: 'filter-tpl', title: '.filter()/.or() içinde template literal' },
    ];

    for (const filePath of files) {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const rel = path.relative(projectRoot, filePath);
            // Skip scanner's own files
            if (rel.includes('security-watchdog')) continue;

            content.split(/\r?\n/).forEach((line, idx) => {
                for (const p of patterns) {
                    const r = new RegExp(p.regex.source, p.regex.flags);
                    if (r.test(line)) {
                        issues.push({
                            severity: 'critical', category: 'sql-injection',
                            title: `💉 SQL INJECTION RİSKİ: ${p.title}`,
                            message: `Parametreli sorgu kullanın. String interpolation/concatenation ile SQL oluşturmayın.`,
                            file: rel, line: idx + 1, context: line.trim(),
                        });
                    }
                }
            });
        } catch { }
    }
    return issues;
}

// ─── API Key Guardian ───
function scanAPIKeys(files, projectRoot, envEntries) {
    const issues = [];
    const rules = [
        { id: 'serper', service: 'Serper.dev', envKeys: ['SERPER', 'SERP_API'], codePatterns: [/serper\.dev/gi, /SERPER_API_KEY/g, /SERP_API_KEY/g] },
        { id: 'openai', service: 'OpenAI', envKeys: ['OPENAI_API_KEY', 'OPENAI_SECRET'], codePatterns: [/OPENAI_API_KEY/g, /openai\.com\/v1/gi, /new\s+OpenAI\s*\(/g] },
        { id: 'anthropic', service: 'Anthropic', envKeys: ['ANTHROPIC_API_KEY', 'CLAUDE_API_KEY'], codePatterns: [/ANTHROPIC_API_KEY/g, /anthropic\.com/gi] },
        { id: 'google-ai', service: 'Google AI', envKeys: ['GOOGLE_API_KEY', 'GEMINI_API_KEY'], codePatterns: [/GOOGLE_API_KEY/g, /GEMINI_API_KEY/g, /generativelanguage\.googleapis\.com/gi] },
    ];

    // .env kontrolü
    for (const entry of envEntries) {
        if (!entry.key.startsWith('NEXT_PUBLIC_')) continue;
        for (const rule of rules) {
            for (const keyPattern of rule.envKeys) {
                if (new RegExp(keyPattern, 'i').test(entry.key)) {
                    issues.push({
                        severity: 'critical', category: 'api-key',
                        title: `🔑 ${rule.service} API anahtarı NEXT_PUBLIC_ ile ifşa ediliyor!`,
                        message: `NEXT_PUBLIC_ önekini kaldırın ve API Route üzerinden proksileyin.`,
                        file: entry.file, line: entry.line, key: entry.key,
                    });
                }
            }
        }
    }

    // Kod kontrolü — "use client" dosyaları
    for (const filePath of files) {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const rel = path.relative(projectRoot, filePath).replace(/\\/g, '/');
            if (rel.includes('security-watchdog')) continue;

            const isClient = /^['"`]use client['"`]/m.test(content) ||
                (rel.startsWith('src/components/') || (rel.startsWith('src/app/') && !rel.includes('/api/')));

            if (!isClient) continue;

            for (const rule of rules) {
                for (const cp of rule.codePatterns) {
                    const lines = content.split(/\r?\n/);
                    lines.forEach((line, idx) => {
                        if (new RegExp(cp.source, cp.flags).test(line)) {
                            issues.push({
                                severity: 'warning', category: 'api-key',
                                title: `🔑 ${rule.service} istemci tarafı kodda referans ediliyor!`,
                                message: `API çağrısını sunucu tarafına (API Route) taşıyın.`,
                                file: rel, line: idx + 1,
                            });
                        }
                    });
                }
            }
        } catch { }
    }

    return issues;
}

// ─── RLS SQL Recipe Generator ───
function generateRLSRecipe(tableName) {
    return [
        `-- 🛡️ RLS: "${tableName}"`,
        `ALTER TABLE public.${tableName} ENABLE ROW LEVEL SECURITY;`,
        ``,
        `CREATE POLICY "${tableName}_select_own" ON public.${tableName}`,
        `  FOR SELECT USING (auth.uid() = user_id);`,
        ``,
        `CREATE POLICY "${tableName}_insert_own" ON public.${tableName}`,
        `  FOR INSERT WITH CHECK (auth.uid() = user_id);`,
        ``,
        `CREATE POLICY "${tableName}_update_own" ON public.${tableName}`,
        `  FOR UPDATE USING (auth.uid() = user_id)`,
        `  WITH CHECK (auth.uid() = user_id);`,
        ``,
        `CREATE POLICY "${tableName}_delete_own" ON public.${tableName}`,
        `  FOR DELETE USING (auth.uid() = user_id);`,
    ].join('\n');
}

// ─── Vibe Summary Generator ───
function generateVibeSummary(config, issues, tables) {
    const now = new Date().toLocaleString('tr-TR');
    const criticalCount = issues.filter(i => i.severity === 'critical').length;
    const warningCount = issues.filter(i => i.severity === 'warning').length;
    const infoCount = issues.filter(i => i.severity === 'info').length;
    const exposedKeys = [...new Set(issues.filter(i => i.key).map(i => i.key))];
    const tableNames = [...tables.keys()];

    const lines = [];
    lines.push(`# 🛡️ VIBE SECURITY SUMMARY`);
    lines.push(`# Otomatik üretildi: ${now}`);
    lines.push(`# Bu dosyayı AI araçlarına (Cursor, Copilot, vb.) context olarak verin.`);
    lines.push(``);

    // Durum
    lines.push(`## 📊 PROJE GÜVENLİK DURUMU`);
    if (criticalCount === 0 && warningCount === 0) {
        lines.push(`✅ DURUM: TEMİZ — Bilinen güvenlik sorunu yok.`);
    } else if (criticalCount > 0) {
        lines.push(`🚨 DURUM: KRİTİK — ${criticalCount} kritik, ${warningCount} uyarı, ${infoCount} bilgi`);
    } else {
        lines.push(`⚠️ DURUM: UYARI — ${warningCount} uyarı, ${infoCount} bilgi`);
    }
    lines.push(``);

    // Kurallar
    lines.push(`## 📜 ZORUNLU GÜVENLİK KURALLARI`);
    lines.push(``);

    lines.push(`### 1. ÇEVRE DEĞİŞKENLERİ`);
    lines.push(`- NEXT_PUBLIC_ öneki SADECE istemci tarafında güvenli değerler için kullanılır.`);
    lines.push(`- SUPABASE_SERVICE_ROLE_KEY, DATABASE_URL, *_SECRET, *_PRIVATE_KEY → ASLA NEXT_PUBLIC_ ile kullanılmaz.`);
    if (exposedKeys.length > 0) {
        lines.push(`- ⚠️ İFŞA EDİLEN: ${exposedKeys.join(', ')}`);
    }
    lines.push(``);

    lines.push(`### 2. SUPABASE RLS`);
    lines.push(`- Bu projede RLS ZORUNLUDUR.`);
    lines.push(`- Her tabloda auth.uid() bazlı politikalar olmalıdır.`);
    if (tableNames.length > 0) {
        lines.push(`- Kullanılan tablolar: ${tableNames.join(', ')}`);
    }
    lines.push(``);

    lines.push(`### 3. SQL INJECTION`);
    lines.push(`- Template literal (\${}) ile SQL OLUŞTURULMAZ.`);
    lines.push(`- String concatenation (+) ile SQL OLUŞTURULMAZ.`);
    lines.push(`- Parametreli sorgular ZORUNLUDUR.`);
    lines.push(``);

    lines.push(`### 4. API ANAHTARI GÜVENLİĞİ`);
    lines.push(`- Serper.dev, OpenAI, Anthropic, Google AI → SADECE sunucu tarafında.`);
    lines.push(`- İstemci tarafından erişim: API Route (/api/*) proxy ile.`);
    lines.push(`- "use client" dosyalarında bu servislere doğrudan erişim YASAKTIR.`);
    lines.push(``);

    // Mimari
    lines.push(`## 🏗️ MİMARİ`);
    lines.push(`- Next.js App Router`);
    lines.push(`- Hassas işlemler → Server Components, API Routes, Server Actions`);
    lines.push(`- İstemci → Sadece UI rendering`);
    lines.push(`- Veritabanı → RLS korumalı Supabase client`);
    lines.push(`- Harici API → /api/* proxy`);
    lines.push(``);

    // Aktif sorunlar
    if (issues.length > 0) {
        lines.push(`## 🚨 AKTİF SORUNLAR`);
        const sorted = [...issues].sort((a, b) => {
            const order = { critical: 0, warning: 1, info: 2 };
            return (order[a.severity] ?? 2) - (order[b.severity] ?? 2);
        });
        for (const issue of sorted) {
            const icon = issue.severity === 'critical' ? '🔴' : issue.severity === 'warning' ? '🟡' : '🔵';
            lines.push(`${icon} [${issue.severity.toUpperCase()}] ${issue.title}${issue.file ? ` → ${issue.file}${issue.line ? ':' + issue.line : ''}` : ''}`);
        }
        lines.push(``);
    }

    // SQL Reçeteleri
    if (tableNames.length > 0) {
        lines.push(`## 📝 HAZIR SQL REÇETELERİ`);
        lines.push(`\`\`\`sql`);
        for (const t of tableNames) {
            lines.push(generateRLSRecipe(t));
            lines.push(``);
        }
        lines.push(`\`\`\``);
        lines.push(``);
    }

    lines.push(`---`);
    lines.push(`Güncelleme: npm run security | Config: vibe-security.config.js`);

    return lines.join('\n');
}

// ─── Load Config ───
function loadConfig(projectRoot) {
    const configPath = path.join(projectRoot, 'vibe-security.config.js');
    if (fs.existsSync(configPath)) {
        delete require.cache[require.resolve(configPath)];
        return require(configPath);
    }
    return null;
}

// ================================================================
// ─── MAIN SCAN ───
// ================================================================
function runScan() {
    const projectRoot = process.cwd();
    const config = loadConfig(projectRoot);

    if (!config) { console.error(`${C.red}❌ vibe-security.config.js bulunamadı!${C.reset}`); process.exit(1); }
    if (!config.enabled) { console.log(`${C.dim}🛡️  Devre dışı.${C.reset}`); return; }

    console.log('');
    console.log(DLINE);
    console.log(`${C.bold}${C.cyan}  🛡️  VIBE SECURITY WATCHDOG v2.0 — GÜVENLİK TARAMASI${C.reset}`);
    console.log(`${C.dim}  Modüller: Secret Scanner | RLS Denetçisi | SQL Injection | API Key Guardian${C.reset}`);
    console.log(DLINE);
    console.log('');

    const issues = [];
    const scanDirs = config.rlsScanner?.scanDirs || ['src'];
    const extensions = config.rlsScanner?.extensions || ['.ts', '.tsx', '.js', '.jsx'];
    const excludeDirs = config.rlsScanner?.excludeDirs || ['node_modules', '.next', 'dist', '.git'];

    // Kaynak dosyaları topla
    const allFiles = [];
    for (const dir of scanDirs) {
        const dirPath = path.join(projectRoot, dir);
        if (fs.existsSync(dirPath)) allFiles.push(...walkDir(dirPath, extensions, excludeDirs));
    }

    // ─── 1. Secret Scanner ───
    console.log(`${C.cyan}  🔐 Secret Scanner çalışıyor...${C.reset}`);
    const envPatterns = config.secretScanner?.envFiles || ['.env', '.env.local'];
    const sensitivePatterns = config.secretScanner?.sensitivePatterns || [];
    const allEnvEntries = []; // API Key Guardian'a da geçirilecek

    for (const envPattern of envPatterns) {
        const envPath = path.join(projectRoot, envPattern);
        if (!fs.existsSync(envPath)) continue;
        const entries = parseEnvFile(envPath);
        entries.forEach(e => { e.file = envPattern; allEnvEntries.push(e); });
        console.log(`${C.dim}     ├─ ${envPattern}: ${entries.length} anahtar${C.reset}`);

        for (const entry of entries) {
            if (!entry.key.startsWith('NEXT_PUBLIC_')) continue;
            const strippedKey = entry.key.replace(/^NEXT_PUBLIC_/, '');
            for (const pattern of sensitivePatterns) {
                const regex = new RegExp(pattern.pattern, 'i');
                if (regex.test(entry.key) || regex.test(strippedKey)) {
                    issues.push({
                        severity: pattern.severity, category: 'secret-leak',
                        title: `🚨 GÜVENLİK RİSKİ: '${entry.key}' istemci tarafına ifşa ediliyor!`,
                        message: pattern.message, file: envPattern, line: entry.line, key: entry.key
                    });
                }
            }
        }
    }

    // ─── 2. RLS Scanner ───
    if (config.rlsScanner?.enabled) {
        console.log(`${C.cyan}  🛡️ RLS Denetçisi çalışıyor...${C.reset}`);
        const whitelisted = config.rlsScanner.whitelistedTables || [];
        const tables = findSupabaseFromCalls(allFiles, projectRoot);

        // Yorum satırlarındaki ve scanner dosyalarındaki tablolar filtrelenir
        const filteredTables = new Map();
        for (const [table, usages] of tables) {
            const realUsages = usages.filter(u => !u.file.includes('security-watchdog'));
            if (realUsages.length > 0) filteredTables.set(table, realUsages);
        }

        console.log(`${C.dim}     ├─ ${filteredTables.size} benzersiz tablo bulundu${C.reset}`);

        for (const [tableName, usages] of filteredTables) {
            if (whitelisted.includes(tableName)) continue;
            issues.push({
                severity: 'info', category: 'rls-check', table: tableName,
                title: `📋 '${tableName}' tablosu kullanılıyor — RLS durumu kontrol edilmeli`,
                message: `Bu tablo ${usages.length} yerde kullanılıyor. RLS'in aktif olduğundan emin olun.`,
                file: usages.map(u => `${u.file}:${u.line}`).join(', ')
            });
        }

        // ─── SQL Reçeteleri ───
        if (filteredTables.size > 0) {
            console.log('');
            console.log(`${C.cyan}${C.bold}  📝 OTOMATİK SQL REÇETELERİ${C.reset}`);
            console.log(`${C.dim}  Aşağıdaki SQL'i Supabase SQL Editor'a yapıştırın:${C.reset}`);
            console.log('');

            for (const [tableName] of filteredTables) {
                if (whitelisted.includes(tableName)) continue;
                console.log(`${C.yellow}${C.bold}  ── ${tableName} ──${C.reset}`);
                console.log(`${C.green}  ALTER TABLE public.${tableName} ENABLE ROW LEVEL SECURITY;${C.reset}`);
                console.log(`${C.dim}  CREATE POLICY "${tableName}_select_own" ON public.${tableName}${C.reset}`);
                console.log(`${C.dim}    FOR SELECT USING (auth.uid() = user_id);${C.reset}`);
                console.log(`${C.dim}  CREATE POLICY "${tableName}_insert_own" ON public.${tableName}${C.reset}`);
                console.log(`${C.dim}    FOR INSERT WITH CHECK (auth.uid() = user_id);${C.reset}`);
                console.log(`${C.dim}  CREATE POLICY "${tableName}_update_own" ON public.${tableName}${C.reset}`);
                console.log(`${C.dim}    FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);${C.reset}`);
                console.log(`${C.dim}  CREATE POLICY "${tableName}_delete_own" ON public.${tableName}${C.reset}`);
                console.log(`${C.dim}    FOR DELETE USING (auth.uid() = user_id);${C.reset}`);
                console.log('');
            }
            console.log(`${C.dim}  ⚠️  "user_id" sütununu tablolarınıza göre düzenleyin.${C.reset}`);
        }
    }

    // ─── 3. SQL Injection Scanner ───
    console.log(`${C.cyan}  💉 SQL Injection Scanner çalışıyor...${C.reset}`);
    const sqlIssues = scanSQLInjection(allFiles, projectRoot);
    console.log(`${C.dim}     ├─ ${sqlIssues.length} risk tespit edildi${C.reset}`);
    issues.push(...sqlIssues);

    // ─── 4. API Key Guardian ───
    console.log(`${C.cyan}  🔑 API Key Guardian çalışıyor...${C.reset}`);
    const apiIssues = scanAPIKeys(allFiles, projectRoot, allEnvEntries);
    console.log(`${C.dim}     ├─ ${apiIssues.length} risk tespit edildi${C.reset}`);
    issues.push(...apiIssues);

    // ─── .gitignore Check ───
    const gitignorePath = path.join(projectRoot, '.gitignore');
    if (fs.existsSync(gitignorePath)) {
        const content = fs.readFileSync(gitignorePath, 'utf-8');
        if (!content.includes('.env')) {
            issues.push({
                severity: 'warning', category: 'general',
                title: '⚠️ .env dosyaları .gitignore\'a eklenmemiş!',
                message: '.env dosyalarınız yanlışlıkla commit edilebilir.', file: '.gitignore'
            });
        }
    }

    // ─── Report ───
    console.log('');

    if (issues.length === 0) {
        console.log(`${C.green}${C.bold}  ✅ Güvenlik taraması tamamlandı — sorun bulunamadı!${C.reset}`);
        generateAndWriteSummary(projectRoot, config, issues, new Map());
        return;
    }

    const criticalCount = issues.filter(i => i.severity === 'critical').length;
    const warningCount = issues.filter(i => i.severity === 'warning').length;
    const infoCount = issues.filter(i => i.severity === 'info').length;

    const parts = [];
    if (criticalCount > 0) parts.push(`${C.red}${C.bold}${criticalCount} Kritik${C.reset}`);
    if (warningCount > 0) parts.push(`${C.yellow}${warningCount} Uyarı${C.reset}`);
    if (infoCount > 0) parts.push(`${C.blue}${infoCount} Bilgi${C.reset}`);

    console.log(DLINE);
    console.log(`${C.bold}  📊 SONUÇ: ${issues.length} sorun — ${parts.join(' · ')}${C.reset}`);
    console.log(DLINE);
    console.log('');

    const sorted = [...issues].sort((a, b) => {
        const order = { critical: 0, warning: 1, info: 2 };
        return (order[a.severity] || 2) - (order[b.severity] || 2);
    });

    for (const issue of sorted) {
        const badge = issue.severity === 'critical'
            ? `${C.bgRed}${C.white}${C.bold} CRITICAL ${C.reset}`
            : issue.severity === 'warning'
                ? `${C.bgYellow}${C.bold} WARNING ${C.reset}`
                : `${C.bgBlue}${C.white} INFO ${C.reset}`;

        console.log(LINE);
        console.log(`  ${badge} ${issue.title}`);
        if (issue.file) console.log(`  ${C.dim}📄 ${issue.file}${issue.line ? `:${issue.line}` : ''}${C.reset}`);
        console.log(`  ${C.dim}${issue.message}${C.reset}`);
        if (issue.context) console.log(`  ${C.dim}📝 ${issue.context.substring(0, 120)}${C.reset}`);
        console.log('');
    }

    // ─── vibe-summary.txt ───
    const tables = findSupabaseFromCalls(allFiles, projectRoot);
    const filteredTables = new Map();
    for (const [table, usages] of tables) {
        const realUsages = usages.filter(u => !u.file.includes('security-watchdog'));
        if (realUsages.length > 0) filteredTables.set(table, realUsages);
    }
    generateAndWriteSummary(projectRoot, config, issues, filteredTables);

    console.log(DLINE);
    console.log(`  ${C.dim}Tarama: ${new Date().toLocaleTimeString('tr-TR')} | Config: vibe-security.config.js${C.reset}`);
    console.log(DLINE);
    console.log('');

    if (criticalCount > 0) process.exit(1);
}

function generateAndWriteSummary(projectRoot, config, issues, tables) {
    try {
        const summary = generateVibeSummary(config, issues, tables);
        const summaryPath = path.join(projectRoot, 'vibe-summary.txt');
        fs.writeFileSync(summaryPath, summary, 'utf-8');
        console.log(`${C.green}${C.bold}  📋 vibe-summary.txt güncellendi.${C.reset}`);
        console.log(`${C.dim}     AI araçlarına bu dosyayı context olarak verin.${C.reset}`);
        console.log('');
    } catch (err) {
        console.error(`${C.red}❌ vibe-summary.txt yazılamadı: ${err.message}${C.reset}`);
    }
}

// ─── Init Command ───
if (process.argv.includes('init')) {
    const projectRoot = process.cwd();
    const configPath = path.join(projectRoot, 'vibe-security.config.js');
    if (fs.existsSync(configPath)) {
        console.log(`${C.yellow}⚠️ vibe-security.config.js zaten mevcut.${C.reset}`);
        process.exit(0);
    }

    const defaultConfig = `// Vibe Security Watchdog v2.0 Configuration
module.exports = {
  enabled: true,
  secretScanner: {
    envFiles: ['.env', '.env.local', '.env.development'],
    sensitivePatterns: [
      { pattern: 'SUPABASE_SERVICE_ROLE_KEY', severity: 'critical', message: 'Service Role Key cannot be exposed!' },
      { pattern: 'DATABASE_URL', severity: 'critical', message: 'Database URL cannot be exposed!' },
      { pattern: 'SECRET', severity: 'critical', message: 'Secrets cannot be exposed!' },
      { pattern: 'PRIVATE_KEY', severity: 'critical', message: 'Private keys cannot be exposed!' }
    ]
  },
  rlsScanner: {
    enabled: true,
    scanDirs: ['src', 'app', 'components'],
    extensions: ['.ts', '.tsx', '.js', '.jsx'],
    excludeDirs: ['node_modules', '.next', 'dist', '.git'],
    whitelistedTables: []
  }
};
`;
    try {
        fs.writeFileSync(configPath, defaultConfig, 'utf-8');
        console.log(`${C.green}${C.bold}✅ vibe-security.config.js başarıyla oluşturuldu!${C.reset}`);
        console.log(`${C.dim}Artık özel kurallarınızı yapılandırabilirsiniz.${C.reset}`);
    } catch (err) {
        console.error(`${C.red}❌ vibe-security.config.js oluşturulamadı: ${err.message}${C.reset}`);
    }
    process.exit(0);
}

// ─── Watch Mode ───
if (process.argv.includes('--watch')) {
    const chokidar = require('chokidar');
    const projectRoot = process.cwd();

    console.log(`${C.cyan}${C.bold}🛡️  Vibe Security Watchdog v2.0 — İzleme Modu${C.reset}`);
    console.log(`${C.dim}   Modüller: Secret Scanner | RLS Denetçisi | SQL Injection | API Key Guardian${C.reset}`);
    console.log(`${C.dim}   Dosya değişimleri izleniyor...${C.reset}`);

    runScan();

    let debounce = null;
    const watcher = chokidar.watch([
        path.join(projectRoot, '.env*'),
        path.join(projectRoot, 'src', '**', '*.{ts,tsx,js,jsx}'),
        path.join(projectRoot, 'vibe-security.config.js'),
    ], {
        ignored: ['**/node_modules/**', '**/.next/**', '**/.git/**', '**/vibe-summary.txt'],
        persistent: true,
        ignoreInitial: true,
    });

    watcher.on('all', (event, filePath) => {
        if (debounce) clearTimeout(debounce);
        console.log(`${C.dim}🔄 ${event}: ${path.relative(projectRoot, filePath)}${C.reset}`);
        debounce = setTimeout(() => {
            console.clear();
            runScan();
        }, 500);
    });
} else {
    runScan();
}
