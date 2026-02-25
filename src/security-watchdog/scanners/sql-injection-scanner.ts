// ============================================================
// 💉 SQL Injection Scanner — Parametresiz Sorgu Denetçisi
// ============================================================
// supabase.rpc() ve ham SQL ifadelerinde string interpolation
// veya string concatenation ile değişken gömmeyi tespit eder.
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import type { SecurityIssue, ScanResult } from '../types';

/**
 * Tehlikeli SQL kalıplarını tespit eden regex'ler.
 * Her biri bir anti-pattern'i yakalar.
 */
const SQL_INJECTION_PATTERNS = [
    {
        // supabase.rpc('func_name', { param: `...${variable}...` })
        // Template literal ile değişken gömme
        regex: /\.rpc\(\s*['"`]\w+['"`]\s*,\s*\{[^}]*`[^`]*\$\{[^}]+\}[^`]*`[^}]*\}/g,
        id: 'rpc-template-literal',
        title: 'supabase.rpc() içinde template literal ile değişken gömülüyor',
        message: 'supabase.rpc() parametrelerinde template literal (${ }) kullanmayın. Değişkenleri doğrudan parametre objesi olarak geçirin.',
        fix: `// ❌ Yanlış:
supabase.rpc('search_users', { query: \`%\${userInput}%\` })

// ✅ Doğru:
supabase.rpc('search_users', { query: userInput })`,
    },
    {
        // .rpc('func', { query: variable + "..." }) — string concatenation
        regex: /\.rpc\(\s*['"`]\w+['"`]\s*,\s*\{[^}]*:\s*[a-zA-Z_$]\w*\s*\+\s*['"`]/g,
        id: 'rpc-string-concat',
        title: 'supabase.rpc() içinde string birleştirme (concatenation) tespit edildi',
        message: 'SQL sorgularında string birleştirme (+) yapmayın. Bu SQL injection\'a açık kapı bırakır.',
        fix: `// ❌ Yanlış:
supabase.rpc('search', { term: userInput + '%' })

// ✅ Doğru:
supabase.rpc('search', { term: userInput })
// SQL fonksiyonu içinde: WHERE name LIKE term || '%'`,
    },
    {
        // Doğrudan SQL string'i: `SELECT ... ${variable} ...` veya `INSERT ... ${variable} ...`
        regex: /`\s*(?:SELECT|INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|TRUNCATE)\b[^`]*\$\{[^}]+\}[^`]*`/gi,
        id: 'raw-sql-template-literal',
        title: 'Ham SQL sorgusunda template literal ile değişken gömülüyor',
        message: 'SQL sorgularında doğrudan değişken gömmeyin. Parametreli sorgular (prepared statements) kullanın.',
        fix: `// ❌ Yanlış:
const query = \`SELECT * FROM users WHERE id = '\${userId}'\`

// ✅ Doğru (Supabase):
supabase.from('users').select('*').eq('id', userId)

// ✅ Doğru (Raw SQL with params):
supabase.rpc('get_user', { user_id: userId })`,
    },
    {
        // String concatenation ile SQL: "SELECT ... " + variable + " ..."
        regex: /['"`]\s*(?:SELECT|INSERT|UPDATE|DELETE|ALTER|DROP|CREATE)\b[^'"`]*['"`]\s*\+\s*[a-zA-Z_$]\w*/gi,
        id: 'raw-sql-string-concat',
        title: 'Ham SQL sorgusunda string birleştirme ile değişken gömülüyor',
        message: 'SQL sorgularını string birleştirme (+) ile oluşturmayın. Bu klasik SQL injection vektörüdür.',
        fix: `// ❌ Yanlış:
const query = "SELECT * FROM users WHERE name = '" + userName + "'"

// ✅ Doğru:
supabase.from('users').select('*').eq('name', userName)`,
    },
    {
        // .filter() veya .or() içinde template literal
        regex: /\.(?:filter|or|and)\(\s*`[^`]*\$\{[^}]+\}[^`]*`\s*\)/g,
        id: 'filter-template-literal',
        title: '.filter() / .or() içinde template literal ile değişken gömülüyor',
        message: 'Supabase filter ifadelerinde template literal kullanmak güvensizdir.',
        fix: `// ❌ Yanlış:
supabase.from('posts').select().or(\`author_id.eq.\${userId},public.eq.true\`)

// ✅ Doğru:
supabase.from('posts').select().or('author_id.eq.' + userId + ',public.eq.true')
// Veya daha güvenli:
supabase.from('posts').select().eq('author_id', userId).eq('public', true)`,
    },
    {
        // .textSearch() veya .ilike() içinde doğrudan user input
        regex: /\.(?:textSearch|ilike|like)\(\s*['"`]\w+['"`]\s*,\s*`[^`]*\$\{[^}]+\}[^`]*`\s*\)/g,
        id: 'search-template-literal',
        title: 'Arama sorgusunda template literal ile kullanıcı girişi gömülüyor',
        message: 'textSearch/ilike/like sorgularında kullanıcı girdisini doğrudan template literal ile gömmeyin.',
        fix: `// ❌ Yanlış:
supabase.from('posts').select().ilike('title', \`%\${searchTerm}%\`)

// ✅ Doğru:
supabase.from('posts').select().ilike('title', '%' + searchTerm + '%')
// Veya sanitize edin:
const sanitized = searchTerm.replace(/[%_]/g, '')
supabase.from('posts').select().ilike('title', \`%\${sanitized}%\`)`,
    },
];

/**
 * Tek bir dosyayı SQL injection kalıpları için tarar.
 */
function scanFileForSQLInjection(
    filePath: string,
    projectRoot: string
): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const lines = content.split(/\r?\n/);
        const relativePath = path.relative(projectRoot, filePath);

        // Her satırı her kalıp için kontrol et
        lines.forEach((lineContent, lineIndex) => {
            const lineNum = lineIndex + 1;

            for (const pattern of SQL_INJECTION_PATTERNS) {
                const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
                if (regex.test(lineContent)) {
                    const issueId = `sqli-${pattern.id}-${relativePath}-${lineNum}`;

                    // Aynı sorun zaten eklenmişse atla
                    if (issues.some((i) => i.id === issueId)) continue;

                    issues.push({
                        id: issueId,
                        category: 'general',
                        severity: 'critical',
                        title: `💉 SQL INJECTION RİSKİ: ${pattern.title}`,
                        message: [
                            pattern.message,
                            '',
                            `📄 Konum: ${relativePath}:${lineNum}`,
                            `📝 Satır: ${lineContent.trim()}`,
                            '',
                            '🔧 Düzeltme Örneği:',
                            pattern.fix,
                        ].join('\n'),
                        file: relativePath,
                        line: lineNum,
                        timestamp: Date.now(),
                    });
                }
            }
        });

        // Çok satırlı kalıplar için tam dosya taraması
        for (const pattern of SQL_INJECTION_PATTERNS) {
            const regex = new RegExp(pattern.regex.source, pattern.regex.flags + (pattern.regex.flags.includes('m') ? '' : 'm'));
            let match: RegExpExecArray | null;
            const fullRegex = new RegExp(regex.source, regex.flags.replace('g', '') + 'g');

            while ((match = fullRegex.exec(content)) !== null) {
                // Satır numarasını bul
                const beforeMatch = content.substring(0, match.index);
                const lineNum = beforeMatch.split('\n').length;
                const issueId = `sqli-multi-${pattern.id}-${relativePath}-${lineNum}`;

                if (!issues.some((i) => i.id === issueId) && !issues.some((i) => i.file === relativePath && i.line === lineNum)) {
                    issues.push({
                        id: issueId,
                        category: 'general',
                        severity: 'critical',
                        title: `💉 SQL INJECTION RİSKİ: ${pattern.title}`,
                        message: [
                            pattern.message,
                            '',
                            `📄 Konum: ${relativePath}:${lineNum}`,
                            '',
                            '🔧 Düzeltme Örneği:',
                            pattern.fix,
                        ].join('\n'),
                        file: relativePath,
                        line: lineNum,
                        timestamp: Date.now(),
                    });
                }
            }
        }
    } catch (err) {
        // Dosya okunamazsa sessizce geç
    }

    return issues;
}

/**
 * Ana SQL injection tarama fonksiyonu.
 */
export async function scanSQLInjection(
    projectRoot: string,
    scanDirs: string[] = ['src'],
    extensions: string[] = ['.ts', '.tsx', '.js', '.jsx'],
    excludeDirs: string[] = ['node_modules', '.next', 'dist', '.git']
): Promise<ScanResult> {
    const startTime = Date.now();
    const allIssues: SecurityIssue[] = [];

    for (const dir of scanDirs) {
        const dirPath = path.join(projectRoot, dir);
        if (!fs.existsSync(dirPath)) continue;

        for (const ext of extensions) {
            const matches = await glob(`**/*${ext}`, {
                cwd: dirPath,
                absolute: true,
                ignore: excludeDirs.map((d) => `**/${d}/**`),
            });

            for (const filePath of matches) {
                const issues = scanFileForSQLInjection(filePath, projectRoot);
                allIssues.push(...issues);
            }
        }
    }

    return {
        issues: allIssues,
        scannedAt: Date.now(),
        duration: Date.now() - startTime,
    };
}
