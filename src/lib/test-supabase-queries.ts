// ============================================================
// 🧪 TEST: Bu dosya RLS tarayıcısını test etmek içindir.
// Kasıtlı olarak supabase.from() çağrıları içerir.
// ============================================================

// Simüle edilmiş supabase client
const supabase = {
    from: (table: string) => ({
        select: (columns?: string) => ({
            eq: (column: string, value: any) => Promise.resolve({ data: [], error: null }),
            single: () => Promise.resolve({ data: null, error: null }),
        }),
        insert: (data: any) => Promise.resolve({ data: null, error: null }),
        update: (data: any) => ({
            eq: (column: string, value: any) => Promise.resolve({ data: null, error: null }),
        }),
        delete: () => ({
            eq: (column: string, value: any) => Promise.resolve({ data: null, error: null }),
        }),
    }),
};

// 🔍 Bu çağrılar RLS tarayıcısı tarafından tespit edilecek:

// Test 1: posts tablosundan veri çekme
async function getPosts() {
    const { data, error } = await supabase.from('posts').select('*');
    return data;
}

// Test 2: users tablosundan veri çekme
async function getUser(userId: string) {
    const { data, error } = await supabase
        .from('users')
        .select('id, name, email')
        .eq('id', userId)
        .single();
    return data;
}

// Test 3: comments tablosuna veri ekleme
async function addComment(postId: string, content: string) {
    const { data, error } = await supabase
        .from('comments')
        .insert({ post_id: postId, content });
    return data;
}

// Test 4: user_settings tablosunu güncelleme
async function updateSettings(userId: string, settings: any) {
    const { data, error } = await supabase
        .from('user_settings')
        .update(settings)
        .eq('user_id', userId);
    return data;
}

// Test 5: private_messages — hassas veri
async function getMessages(userId: string) {
    const { data, error } = await supabase
        .from('private_messages')
        .select('*')
        .eq('recipient_id', userId);
    return data;
}

export { getPosts, getUser, addComment, updateSettings, getMessages };
