const { Client } = require('pg');

async function scanRLS(databaseUrl, whitelisted) {
    const issues = [];
    const filteredTables = new Map();

    if (!databaseUrl) {
        issues.push({
            severity: 'warning',
            category: 'rls-check',
            title: '⚠️ Veritabanı URL bulunamadı!',
            message: 'RLS taraması için DATABASE_URL (ör. .env.local içinde) gerekli.',
            file: '.env.local'
        });
        return { issues, filteredTables };
    }

    let client = new Client({
        connectionString: databaseUrl,
        ssl: { rejectUnauthorized: false }
    });

    try {
        try {
            await client.connect();
        } catch (sslErr) {
            if (sslErr.message && sslErr.message.includes('SSL')) {
                client = new Client({ connectionString: databaseUrl });
                await client.connect();
            } else {
                throw sslErr;
            }
        }

        const query = `
            SELECT 
                c.relname as table_name,
                c.relrowsecurity as rls_enabled,
                (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) as policy_count
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' 
            AND c.relkind = 'r'
            AND c.relname NOT LIKE 'pg_%' 
            AND c.relname NOT LIKE 'sql_%';
        `;

        const res = await client.query(query);

        for (const row of res.rows) {
            const tableName = row.table_name;
            const rlsEnabled = row.rls_enabled;
            const policyCount = parseInt(row.policy_count, 10);

            // Mock file usage for vibe-summary compatibility
            filteredTables.set(tableName, [{ file: 'database -> public', line: 1 }]);

            if (whitelisted && whitelisted.includes(tableName)) continue;

            if (!rlsEnabled) {
                issues.push({
                    severity: 'critical',
                    category: 'rls-check',
                    table: tableName,
                    title: `🔴 RLS KAPALI: '${tableName}' tablosu savunmasız!`,
                    message: `Bu tabloda RLS etkinleştirilmemiş. Herkes veri okuyabilir veya yazabilir.`,
                    file: '(direct db)'
                });
            } else if (policyCount === 0) {
                issues.push({
                    severity: 'warning',
                    category: 'rls-check',
                    table: tableName,
                    title: `🟡 RLS AÇIK AMA POLİTİKA YOK: '${tableName}'`,
                    message: `RLS açık ancak hiç policy tanımlanmamış. Kimse veriye erişemez, bu kasıtlı değilse bir hata olabilir.`,
                    file: '(direct db)'
                });
            } else {
                // Info for standard scan matching legacy behavior
                issues.push({
                    severity: 'info',
                    category: 'rls-check',
                    table: tableName,
                    title: `✅ RLS AÇIK: '${tableName}' tablosunda ${policyCount} politika var.`,
                    message: `Standart kontrol başarılı.`,
                    file: '(direct db)'
                });
            }
        }
    } catch (err) {
        issues.push({
            severity: 'critical',
            category: 'rls-check',
            title: `🔴 Veritabanı Bağlantı Hatası: ${err.message}`,
            message: `RLS taraması için veritabanına bağlanılamadı. IP kısıtlamaları veya yanlış URL olabilir.`,
            file: '.env.local'
        });
    } finally {
        await client.end();
    }

    return { issues, filteredTables };
}

module.exports = {
    scanRLS
};
