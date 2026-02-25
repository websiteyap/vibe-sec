'use client';

// ============================================================
// 🧪 TEST: SQL Injection ve API Key Guardian test dosyası
// Kasıtlı olarak güvenlik ihlalleri içerir.
// ============================================================

// Simüle edilmiş supabase client
const supabase = {
    from: (table: string) => ({
        select: (columns?: string) => ({ eq: (_c: string, _v: any) => Promise.resolve({ data: [], error: null }) }),
        insert: (data: any) => Promise.resolve({ data: null, error: null }),
    }),
    rpc: (func: string, params: any) => Promise.resolve({ data: null, error: null }),
};

// ─── SQL INJECTION TEST CASES ───

// ❌ Test 1: rpc() içinde template literal — TESPİT EDİLMELİ
async function unsafeSearch(userInput: string) {
    const { data } = await supabase.rpc('search_posts', { query: `%${userInput}%` });
    return data;
}

// ❌ Test 2: Ham SQL'de template literal — TESPİT EDİLMELİ
function buildUnsafeQuery(userId: string) {
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    return query;
}

// ❌ Test 3: String concatenation ile SQL — TESPİT EDİLMELİ
function buildAnotherUnsafeQuery(name: string) {
    const query = "SELECT * FROM products WHERE name = '" + name;
    return query;
}

// ✅ Test 4: Güvenli supabase kullanımı — TESPİT EDİLMEMELİ
async function safeQuery(userId: string) {
    const { data } = await supabase.from('users').select('*').eq('id', userId);
    return data;
}

// ─── API KEY GUARDIAN TEST CASES ───

// ❌ Test 5: Serper.dev istemci tarafında — TESPİT EDİLMELİ
async function searchWithSerper(query: string) {
    const response = await fetch('https://google.serper.dev/search', {
        method: 'POST',
        headers: {
            'X-API-KEY': process.env.NEXT_PUBLIC_SERPER_API_KEY || '',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ q: query }),
    });
    return response.json();
}

// ❌ Test 6: OpenAI istemci tarafında — TESPİT EDİLMELİ
async function chatWithOpenAI(prompt: string) {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
        },
        body: JSON.stringify({ model: 'gpt-4', messages: [{ role: 'user', content: prompt }] }),
    });
    return response.json();
}

export { unsafeSearch, buildUnsafeQuery, buildAnotherUnsafeQuery, safeQuery, searchWithSerper, chatWithOpenAI };
