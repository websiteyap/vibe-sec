'use client';

// ============================================================
// 🛡️ Security Overlay — Tarayıcı İçi Güvenlik Uyarı Paneli
// ============================================================
// Development ortamında güvenlik sorunlarını overlay olarak gösterir.
// Next.js error overlay benzeri bir deneyim sunar.
// ============================================================

import React, { useEffect, useState, useCallback } from 'react';

interface SecurityIssue {
    id: string;
    category: string;
    severity: 'critical' | 'warning' | 'info';
    title: string;
    message: string;
    file?: string;
    line?: number;
    key?: string;
    table?: string;
    timestamp: number;
}

interface SecurityData {
    timestamp: number;
    issueCount: number;
    summary: {
        critical: number;
        warning: number;
        info: number;
    };
    issues: SecurityIssue[];
}

const POLL_INTERVAL = 3000; // 3 saniye

export default function SecurityOverlay() {
    const [data, setData] = useState<SecurityData | null>(null);
    const [isExpanded, setIsExpanded] = useState(false);
    const [isDismissed, setIsDismissed] = useState(false);
    const [selectedIssue, setSelectedIssue] = useState<SecurityIssue | null>(null);

    const fetchIssues = useCallback(async () => {
        try {
            const response = await fetch('/api/security-watchdog', {
                cache: 'no-store',
            });
            if (response.ok) {
                const result: SecurityData = await response.json();
                setData(result);

                // Yeni kritik sorunlar varsa console'a da yazdır
                if (result.issueCount > 0) {
                    result.issues.forEach((issue) => {
                        if (issue.severity === 'critical') {
                            console.error(`🛡️ ${issue.title}\n${issue.message}`);
                        } else if (issue.severity === 'warning') {
                            console.warn(`🛡️ ${issue.title}\n${issue.message}`);
                        }
                    });
                }
            }
        } catch {
            // API erişilemezse sessizce geç
        }
    }, []);

    useEffect(() => {
        // Sadece development'ta çalış
        if (process.env.NODE_ENV !== 'development') return;

        fetchIssues();
        const interval = setInterval(fetchIssues, POLL_INTERVAL);
        return () => clearInterval(interval);
    }, [fetchIssues]);

    // Sorun yoksa veya dismiss edildiyse gösterme
    if (!data || data.issueCount === 0 || isDismissed) return null;
    if (process.env.NODE_ENV !== 'development') return null;

    const severityColor = {
        critical: '#ff4444',
        warning: '#ffaa00',
        info: '#4488ff',
    };

    const severityBg = {
        critical: 'rgba(255, 68, 68, 0.08)',
        warning: 'rgba(255, 170, 0, 0.08)',
        info: 'rgba(68, 136, 255, 0.08)',
    };

    const hasCritical = data.summary.critical > 0;

    return (
        <>
            {/* Floating Badge */}
            {!isExpanded && (
                <button
                    onClick={() => setIsExpanded(true)}
                    style={{
                        position: 'fixed',
                        bottom: '20px',
                        right: '20px',
                        zIndex: 99999,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        padding: '10px 16px',
                        backgroundColor: hasCritical ? '#1a1a2e' : '#1a1a2e',
                        border: `2px solid ${hasCritical ? '#ff4444' : '#ffaa00'}`,
                        borderRadius: '12px',
                        color: '#fff',
                        fontSize: '13px',
                        fontFamily: "'Inter', 'SF Mono', 'Menlo', monospace",
                        fontWeight: 600,
                        cursor: 'pointer',
                        boxShadow: `0 4px 24px ${hasCritical ? 'rgba(255,68,68,0.3)' : 'rgba(255,170,0,0.2)'}`,
                        transition: 'all 0.2s ease',
                        animation: hasCritical ? 'vibe-sec-pulse 2s infinite' : 'none',
                    }}
                    onMouseEnter={(e) => {
                        e.currentTarget.style.transform = 'scale(1.05)';
                    }}
                    onMouseLeave={(e) => {
                        e.currentTarget.style.transform = 'scale(1)';
                    }}
                >
                    <span style={{ fontSize: '16px' }}>🛡️</span>
                    <span>
                        {data.issueCount} Güvenlik {data.issueCount === 1 ? 'Sorunu' : 'Sorunu'}
                    </span>
                    {data.summary.critical > 0 && (
                        <span
                            style={{
                                backgroundColor: '#ff4444',
                                color: '#fff',
                                padding: '2px 8px',
                                borderRadius: '10px',
                                fontSize: '11px',
                                fontWeight: 700,
                            }}
                        >
                            {data.summary.critical} KRİTİK
                        </span>
                    )}
                </button>
            )}

            {/* Full Overlay Panel */}
            {isExpanded && (
                <div
                    style={{
                        position: 'fixed',
                        inset: 0,
                        zIndex: 99999,
                        backgroundColor: 'rgba(0, 0, 0, 0.7)',
                        backdropFilter: 'blur(4px)',
                        display: 'flex',
                        justifyContent: 'center',
                        alignItems: 'center',
                        fontFamily: "'Inter', 'SF Mono', 'Menlo', -apple-system, sans-serif",
                    }}
                    onClick={(e) => {
                        if (e.target === e.currentTarget) setIsExpanded(false);
                    }}
                >
                    <div
                        style={{
                            width: '90vw',
                            maxWidth: '780px',
                            maxHeight: '85vh',
                            backgroundColor: '#0d1117',
                            borderRadius: '16px',
                            border: `1px solid ${hasCritical ? '#ff4444' : '#30363d'}`,
                            boxShadow: `0 16px 64px rgba(0, 0, 0, 0.6), 0 0 0 1px ${hasCritical ? 'rgba(255,68,68,0.2)' : 'rgba(48,54,61,0.5)'}`,
                            overflow: 'hidden',
                            display: 'flex',
                            flexDirection: 'column',
                        }}
                    >
                        {/* Header */}
                        <div
                            style={{
                                padding: '16px 20px',
                                background: 'linear-gradient(135deg, #161b22, #0d1117)',
                                borderBottom: '1px solid #21262d',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                            }}
                        >
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                <span style={{ fontSize: '22px' }}>🛡️</span>
                                <div>
                                    <div style={{ color: '#f0f6fc', fontWeight: 700, fontSize: '15px' }}>
                                        Vibe Security Watchdog
                                    </div>
                                    <div style={{ color: '#8b949e', fontSize: '11px', marginTop: '2px' }}>
                                        {data.summary.critical > 0 && (
                                            <span style={{ color: '#ff4444', marginRight: '8px' }}>
                                                ● {data.summary.critical} Kritik
                                            </span>
                                        )}
                                        {data.summary.warning > 0 && (
                                            <span style={{ color: '#ffaa00', marginRight: '8px' }}>
                                                ● {data.summary.warning} Uyarı
                                            </span>
                                        )}
                                        {data.summary.info > 0 && (
                                            <span style={{ color: '#4488ff' }}>
                                                ● {data.summary.info} Bilgi
                                            </span>
                                        )}
                                    </div>
                                </div>
                            </div>

                            <div style={{ display: 'flex', gap: '8px' }}>
                                <button
                                    onClick={() => {
                                        setIsDismissed(true);
                                        setIsExpanded(false);
                                    }}
                                    style={{
                                        padding: '6px 12px',
                                        backgroundColor: 'transparent',
                                        border: '1px solid #30363d',
                                        borderRadius: '8px',
                                        color: '#8b949e',
                                        fontSize: '12px',
                                        cursor: 'pointer',
                                        transition: 'all 0.15s',
                                    }}
                                    onMouseEnter={(e) => {
                                        e.currentTarget.style.borderColor = '#ff4444';
                                        e.currentTarget.style.color = '#ff4444';
                                    }}
                                    onMouseLeave={(e) => {
                                        e.currentTarget.style.borderColor = '#30363d';
                                        e.currentTarget.style.color = '#8b949e';
                                    }}
                                >
                                    Kapat
                                </button>
                                <button
                                    onClick={() => setIsExpanded(false)}
                                    style={{
                                        padding: '6px 12px',
                                        backgroundColor: 'transparent',
                                        border: '1px solid #30363d',
                                        borderRadius: '8px',
                                        color: '#8b949e',
                                        fontSize: '12px',
                                        cursor: 'pointer',
                                        transition: 'all 0.15s',
                                    }}
                                    onMouseEnter={(e) => {
                                        e.currentTarget.style.borderColor = '#58a6ff';
                                        e.currentTarget.style.color = '#58a6ff';
                                    }}
                                    onMouseLeave={(e) => {
                                        e.currentTarget.style.borderColor = '#30363d';
                                        e.currentTarget.style.color = '#8b949e';
                                    }}
                                >
                                    Küçült
                                </button>
                            </div>
                        </div>

                        {/* Issue List */}
                        <div
                            style={{
                                flex: 1,
                                overflowY: 'auto',
                                padding: '12px',
                            }}
                        >
                            {data.issues.map((issue) => (
                                <div
                                    key={issue.id}
                                    onClick={() =>
                                        setSelectedIssue(selectedIssue?.id === issue.id ? null : issue)
                                    }
                                    style={{
                                        padding: '14px 16px',
                                        marginBottom: '8px',
                                        backgroundColor:
                                            selectedIssue?.id === issue.id
                                                ? severityBg[issue.severity]
                                                : '#161b22',
                                        border: `1px solid ${selectedIssue?.id === issue.id
                                                ? severityColor[issue.severity]
                                                : '#21262d'
                                            }`,
                                        borderRadius: '10px',
                                        cursor: 'pointer',
                                        transition: 'all 0.15s ease',
                                    }}
                                    onMouseEnter={(e) => {
                                        if (selectedIssue?.id !== issue.id) {
                                            e.currentTarget.style.borderColor = '#30363d';
                                            e.currentTarget.style.backgroundColor = '#1c2128';
                                        }
                                    }}
                                    onMouseLeave={(e) => {
                                        if (selectedIssue?.id !== issue.id) {
                                            e.currentTarget.style.borderColor = '#21262d';
                                            e.currentTarget.style.backgroundColor = '#161b22';
                                        }
                                    }}
                                >
                                    {/* Issue Header */}
                                    <div
                                        style={{
                                            display: 'flex',
                                            alignItems: 'flex-start',
                                            gap: '10px',
                                        }}
                                    >
                                        <span
                                            style={{
                                                display: 'inline-block',
                                                padding: '2px 8px',
                                                backgroundColor: severityColor[issue.severity],
                                                color: '#fff',
                                                borderRadius: '6px',
                                                fontSize: '10px',
                                                fontWeight: 700,
                                                textTransform: 'uppercase',
                                                letterSpacing: '0.5px',
                                                flexShrink: 0,
                                                marginTop: '2px',
                                            }}
                                        >
                                            {issue.severity === 'critical'
                                                ? 'KRİTİK'
                                                : issue.severity === 'warning'
                                                    ? 'UYARI'
                                                    : 'BİLGİ'}
                                        </span>

                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <div
                                                style={{
                                                    color: '#f0f6fc',
                                                    fontWeight: 600,
                                                    fontSize: '13px',
                                                    lineHeight: '1.4',
                                                }}
                                            >
                                                {issue.title}
                                            </div>

                                            {issue.file && (
                                                <div
                                                    style={{
                                                        color: '#8b949e',
                                                        fontSize: '11px',
                                                        marginTop: '4px',
                                                        fontFamily: "'SF Mono', 'Menlo', monospace",
                                                    }}
                                                >
                                                    📄 {issue.file}
                                                    {issue.line ? `:${issue.line}` : ''}
                                                </div>
                                            )}
                                        </div>

                                        <span
                                            style={{
                                                color: '#8b949e',
                                                fontSize: '12px',
                                                transform:
                                                    selectedIssue?.id === issue.id
                                                        ? 'rotate(180deg)'
                                                        : 'rotate(0deg)',
                                                transition: 'transform 0.2s ease',
                                            }}
                                        >
                                            ▼
                                        </span>
                                    </div>

                                    {/* Issue Detail (Expanded) */}
                                    {selectedIssue?.id === issue.id && (
                                        <div
                                            style={{
                                                marginTop: '12px',
                                                padding: '12px',
                                                backgroundColor: '#0d1117',
                                                borderRadius: '8px',
                                                border: '1px solid #21262d',
                                            }}
                                        >
                                            <pre
                                                style={{
                                                    color: '#c9d1d9',
                                                    fontSize: '12px',
                                                    lineHeight: '1.6',
                                                    whiteSpace: 'pre-wrap',
                                                    wordBreak: 'break-word',
                                                    margin: 0,
                                                    fontFamily: "'SF Mono', 'Menlo', 'Cascadia Code', monospace",
                                                }}
                                            >
                                                {issue.message}
                                            </pre>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>

                        {/* Footer */}
                        <div
                            style={{
                                padding: '10px 20px',
                                borderTop: '1px solid #21262d',
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                            }}
                        >
                            <span
                                style={{
                                    color: '#484f58',
                                    fontSize: '11px',
                                    fontFamily: "'SF Mono', 'Menlo', monospace",
                                }}
                            >
                                vibe-security.config.js ile kuralları yapılandırın
                            </span>
                            <span
                                style={{
                                    color: '#484f58',
                                    fontSize: '11px',
                                }}
                            >
                                Son güncelleme:{' '}
                                {new Date(data.timestamp).toLocaleTimeString('tr-TR')}
                            </span>
                        </div>
                    </div>
                </div>
            )}

            {/* Pulse Animation */}
            <style>{`
        @keyframes vibe-sec-pulse {
          0%, 100% { box-shadow: 0 4px 24px rgba(255,68,68,0.3); }
          50% { box-shadow: 0 4px 32px rgba(255,68,68,0.6), 0 0 0 4px rgba(255,68,68,0.1); }
        }
      `}</style>
        </>
    );
}
