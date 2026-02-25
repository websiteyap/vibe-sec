// ============================================================
// 🔑 API Key Guardian — İstemci Tarafı API Anahtarı Denetçisi
// ============================================================
// Serper.dev ve diğer sunucu-tarafı API anahtarlarının
// istemci tarafı kodlarında kullanılıp kullanılmadığını kontrol eder.
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import type { SecurityIssue, ScanResult } from '../types';

interface APIKeyRule {
    /** Kural kimliği */
    id: string;
    /** Hizmet adı */
    service: string;
    /** .env anahtar adı kalıpları (regex) */
    envKeyPatterns: string[];
    /** Kod içinde aranacak kullanım kalıpları (regex) */
    codePatterns: RegExp[];
    /** İstemci tarafı dosya kalıpları — bu kalıplara uyan dosyalar "istemci tarafı" sayılır */
    clientFilePatterns: RegExp[];
    /** Uyarı mesajı */
    message: string;
    /** Düzeltme önerisi */
    fix: string;
}

/**
 * Varsayılan API anahtarı kuralları.
 * vibe-security.config.js'den genişletilebilir.
 */
const DEFAULT_API_KEY_RULES: APIKeyRule[] = [
    {
        id: 'serper-dev',
        service: 'Serper.dev',
        envKeyPatterns: ['SERPER', 'SERP_API'],
        codePatterns: [
            /['"`]https?:\/\/(?:google\.)?serper\.dev/gi,
            /serper\.dev/gi,
            /SERPER_API_KEY/g,
            /SERP_API_KEY/g,
            /x-api-key['"`]\s*:\s*.*serper/gi,
            /headers\s*:\s*\{[^}]*['"`]X-API-KEY['"`]/gi,
        ],
        clientFilePatterns: [
            /^src\/app\/(?!api\/).*\.(tsx?|jsx?)$/,  // App Router — api/ dışındaki her şey
            /^src\/components\/.*\.(tsx?|jsx?)$/,       // Tüm component'ler
            /^src\/hooks\/.*\.(tsx?|jsx?)$/,            // Client hook'ları
            /^src\/lib\/client/i,                       // client lib'leri
            /^app\/(?!api\/).*\.(tsx?|jsx?)$/,          // app/ altı (api/ hariç)
            /^pages\/(?!api\/).*\.(tsx?|jsx?)$/,        // Pages Router — api/ dışı
            /^components\/.*\.(tsx?|jsx?)$/,             // Root components/
            /['"`]use client['"`]/,                     // "use client" directive
        ],
        message: 'Serper.dev API anahtarı istemci tarafında kullanılıyor! Bu anahtar tarayıcıda görünür olacak ve kötüye kullanılabilir.',
        fix: `// ❌ Yanlış: Client component'te doğrudan Serper.dev çağrısı
'use client'
const res = await fetch('https://google.serper.dev/search', {
  headers: { 'X-API-KEY': process.env.NEXT_PUBLIC_SERPER_API_KEY }
})

// ✅ Doğru: API Route üzerinden proxy
// src/app/api/search/route.ts
export async function POST(req) {
  const { query } = await req.json()
  const res = await fetch('https://google.serper.dev/search', {
    method: 'POST',
    headers: {
      'X-API-KEY': process.env.SERPER_API_KEY, // NEXT_PUBLIC_ yok!
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ q: query }),
  })
  return Response.json(await res.json())
}`,
    },
    {
        id: 'openai',
        service: 'OpenAI',
        envKeyPatterns: ['OPENAI_API_KEY', 'OPENAI_SECRET'],
        codePatterns: [
            /OPENAI_API_KEY/g,
            /openai\.com\/v1/gi,
            /new\s+OpenAI\s*\(/g,
            /sk-[a-zA-Z0-9]{20,}/g, // OpenAI key format
        ],
        clientFilePatterns: [
            /^src\/app\/(?!api\/).*\.(tsx?|jsx?)$/,
            /^src\/components\/.*\.(tsx?|jsx?)$/,
            /['"`]use client['"`]/,
        ],
        message: 'OpenAI API anahtarı istemci tarafında kullanılıyor! API maliyetleri kontrolsüz artabilir.',
        fix: `// ✅ Doğru: OpenAI çağrılarını API Route'a taşıyın
// src/app/api/chat/route.ts dosyasından çağırın.`,
    },
    {
        id: 'anthropic',
        service: 'Anthropic (Claude)',
        envKeyPatterns: ['ANTHROPIC_API_KEY', 'CLAUDE_API_KEY'],
        codePatterns: [
            /ANTHROPIC_API_KEY/g,
            /anthropic\.com/gi,
            /new\s+Anthropic\s*\(/g,
            /sk-ant-[a-zA-Z0-9-]{20,}/g,
        ],
        clientFilePatterns: [
            /^src\/app\/(?!api\/).*\.(tsx?|jsx?)$/,
            /^src\/components\/.*\.(tsx?|jsx?)$/,
            /['"`]use client['"`]/,
        ],
        message: 'Anthropic API anahtarı istemci tarafında kullanılıyor!',
        fix: '// ✅ Doğru: API Route kullanın.',
    },
    {
        id: 'google-ai',
        service: 'Google AI (Gemini)',
        envKeyPatterns: ['GOOGLE_API_KEY', 'GEMINI_API_KEY'],
        codePatterns: [
            /GOOGLE_API_KEY/g,
            /GEMINI_API_KEY/g,
            /generativelanguage\.googleapis\.com/gi,
            /new\s+GoogleGenerativeAI\s*\(/g,
        ],
        clientFilePatterns: [
            /^src\/app\/(?!api\/).*\.(tsx?|jsx?)$/,
            /^src\/components\/.*\.(tsx?|jsx?)$/,
            /['"`]use client['"`]/,
        ],
        message: 'Google AI API anahtarı istemci tarafında kullanılıyor!',
        fix: '// ✅ Doğru: API Route kullanın.',
    },
];

/**
 * Bir dosyanın "istemci tarafı" olup olmadığını kontrol eder.
 */
function isClientSideFile(relativePath: string, content: string, clientPatterns: RegExp[]): boolean {
    // "use client" directive kontrolü
    if (/^['"`]use client['"`]/m.test(content)) {
        return true;
    }

    // Dosya yolu kalıpları kontrolü
    const normalizedPath = relativePath.replace(/\\/g, '/');
    for (const pattern of clientPatterns) {
        if (pattern.source.includes('use client')) continue; // Bu zaten yukarıda kontrol edildi
        if (pattern.test(normalizedPath)) {
            return true;
        }
    }

    return false;
}

/**
 * .env dosyalarında NEXT_PUBLIC_ ile ifşa edilen API anahtarlarını kontrol eder.
 */
function checkEnvForAPIKeys(
    projectRoot: string,
    rules: APIKeyRule[]
): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const envFiles = ['.env', '.env.local', '.env.development', '.env.production'];

    for (const envFile of envFiles) {
        const envPath = path.join(projectRoot, envFile);
        if (!fs.existsSync(envPath)) continue;

        try {
            const content = fs.readFileSync(envPath, 'utf-8');
            const lines = content.split(/\r?\n/);

            lines.forEach((line, index) => {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('#')) return;
                if (!trimmed.startsWith('NEXT_PUBLIC_')) return;

                for (const rule of rules) {
                    for (const keyPattern of rule.envKeyPatterns) {
                        const regex = new RegExp(keyPattern, 'i');
                        if (regex.test(trimmed)) {
                            issues.push({
                                id: `apikey-env-${rule.id}-${envFile}-${index + 1}`,
                                category: 'secret-leak',
                                severity: 'critical',
                                title: `🔑 ${rule.service} API anahtarı NEXT_PUBLIC_ ile ifşa ediliyor!`,
                                message: [
                                    rule.message,
                                    '',
                                    `📄 Konum: ${envFile}:${index + 1}`,
                                    `🔑 Satır: ${trimmed.substring(0, trimmed.indexOf('=') + 1)}***`,
                                    '',
                                    '🔧 Düzeltme:',
                                    `1. NEXT_PUBLIC_ önekini kaldırın`,
                                    `2. API çağrısını sunucu tarafına (API Route) taşıyın`,
                                    '',
                                    rule.fix,
                                ].join('\n'),
                                file: envFile,
                                line: index + 1,
                                key: trimmed.substring(0, trimmed.indexOf('=')),
                                timestamp: Date.now(),
                            });
                        }
                    }
                }
            });
        } catch { }
    }

    return issues;
}

/**
 * Kaynak kodda istemci tarafı API anahtarı kullanımını tarar.
 */
async function checkCodeForAPIKeys(
    projectRoot: string,
    rules: APIKeyRule[],
    scanDirs: string[] = ['src'],
    extensions: string[] = ['.ts', '.tsx', '.js', '.jsx'],
    excludeDirs: string[] = ['node_modules', '.next', 'dist', '.git']
): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

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
                try {
                    const content = fs.readFileSync(filePath, 'utf-8');
                    const relativePath = path.relative(projectRoot, filePath);

                    for (const rule of rules) {
                        // Bu dosya istemci tarafı mı?
                        if (!isClientSideFile(relativePath, content, rule.clientFilePatterns)) continue;

                        // Kod kalıplarını kontrol et
                        for (const codePattern of rule.codePatterns) {
                            const regex = new RegExp(codePattern.source, codePattern.flags);
                            const lines = content.split(/\r?\n/);

                            lines.forEach((lineContent, lineIndex) => {
                                const lineRegex = new RegExp(codePattern.source, codePattern.flags);
                                if (lineRegex.test(lineContent)) {
                                    const issueId = `apikey-code-${rule.id}-${relativePath}-${lineIndex + 1}`;

                                    if (!issues.some((i) => i.id === issueId)) {
                                        issues.push({
                                            id: issueId,
                                            category: 'secret-leak',
                                            severity: 'warning',
                                            title: `🔑 ${rule.service} istemci tarafı kodda referans ediliyor!`,
                                            message: [
                                                `'${relativePath}' dosyası istemci tarafında çalışıyor ve ${rule.service} referansı içeriyor.`,
                                                '',
                                                `📄 Konum: ${relativePath}:${lineIndex + 1}`,
                                                `📝 Satır: ${lineContent.trim().substring(0, 120)}`,
                                                '',
                                                rule.message,
                                                '',
                                                '🔧 Düzeltme:',
                                                rule.fix,
                                            ].join('\n'),
                                            file: relativePath,
                                            line: lineIndex + 1,
                                            timestamp: Date.now(),
                                        });
                                    }
                                }
                            });
                        }
                    }
                } catch { }
            }
        }
    }

    return issues;
}

/**
 * Ana API Key Guardian tarama fonksiyonu.
 */
export async function scanAPIKeys(
    projectRoot: string,
    customRules: APIKeyRule[] = [],
    scanDirs: string[] = ['src'],
    extensions: string[] = ['.ts', '.tsx', '.js', '.jsx'],
    excludeDirs: string[] = ['node_modules', '.next', 'dist', '.git']
): Promise<ScanResult> {
    const startTime = Date.now();
    const rules = [...DEFAULT_API_KEY_RULES, ...customRules];

    // 1) .env dosyalarını kontrol et
    const envIssues = checkEnvForAPIKeys(projectRoot, rules);

    // 2) Kaynak kodları kontrol et
    const codeIssues = await checkCodeForAPIKeys(projectRoot, rules, scanDirs, extensions, excludeDirs);

    return {
        issues: [...envIssues, ...codeIssues],
        scannedAt: Date.now(),
        duration: Date.now() - startTime,
    };
}

export type { APIKeyRule };
