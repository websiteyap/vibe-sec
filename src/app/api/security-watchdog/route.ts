// ============================================================
// 🛡️ Security Watchdog API Endpoint
// ============================================================
// Browser overlay'inin güvenlik sorunlarını çektiği endpoint.
// Sadece development ortamında aktif.
// ============================================================

import { NextResponse } from 'next/server';
import { getLatestIssuesForBrowser } from '@/security-watchdog';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function GET() {
    // Sadece development ortamında çalış
    if (process.env.NODE_ENV !== 'development') {
        return NextResponse.json(
            { error: 'Bu endpoint sadece development ortamında kullanılabilir.' },
            { status: 403 }
        );
    }

    try {
        const data = getLatestIssuesForBrowser();
        return NextResponse.json(data, {
            headers: {
                'Cache-Control': 'no-store, no-cache, must-revalidate',
                'Access-Control-Allow-Origin': '*',
            },
        });
    } catch (error) {
        return NextResponse.json(
            {
                error: 'Güvenlik tarama sonuçları alınamadı.',
                detail: (error as Error).message,
            },
            { status: 500 }
        );
    }
}
