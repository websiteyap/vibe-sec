/** @type {import('./src/security-watchdog/types').VibeSecurityConfig} */
const vibeSecurityConfig = {
  /**
   * Etkinleştirme — sadece development ortamında aktif olur.
   * Bu değeri false yaparak watchdog'u tamamen devre dışı bırakabilirsiniz.
   */
  enabled: true,

  /**
   * Secret Scanner Ayarları
   * .env dosyalarındaki hatalı NEXT_PUBLIC_ kullanımlarını tespit eder.
   */
  secretScanner: {
    /** Taranacak .env dosya kalıpları (glob pattern) */
    envFiles: ['.env', '.env.local', '.env.development', '.env.production', '.env.*.local'],

    /**
     * Kritik anahtar kalıpları — bu regex'lerle eşleşen anahtarlar
     * NEXT_PUBLIC_ önekiyle kullanılmamalıdır.
     *
     * Her bir giriş:
     *   - pattern: regex string
     *   - severity: 'critical' | 'warning' | 'info'
     *   - message: kullanıcıya gösterilecek açıklama
     */
    sensitivePatterns: [
      {
        pattern: 'SUPABASE_SERVICE_ROLE_KEY',
        severity: 'critical',
        message: 'Supabase Service Role Key istemci tarafına asla ifşa edilmemelidir! Bu anahtar tüm RLS kurallarını atlar.',
      },
      {
        pattern: 'DATABASE_URL',
        severity: 'critical',
        message: 'Veritabanı bağlantı string\'i istemci tarafında görünür olmamalıdır.',
      },
      {
        pattern: 'SECRET',
        severity: 'critical',
        message: 'SECRET içeren anahtarlar istemci tarafına ifşa edilmemelidir.',
      },
      {
        pattern: 'PRIVATE_KEY',
        severity: 'critical',
        message: 'Özel anahtarlar (private keys) istemci tarafına asla ifşa edilmemelidir.',
      },
      {
        pattern: 'PASSWORD',
        severity: 'warning',
        message: 'Parola içeren değişkenler istemci tarafında görünür olmamalıdır.',
      },
      {
        pattern: 'SMTP',
        severity: 'warning',
        message: 'SMTP ayarları sunucu tarafında kalmalıdır.',
      },
      {
        pattern: 'API_SECRET',
        severity: 'critical',
        message: 'API gizli anahtarları istemci tarafına ifşa edilmemelidir.',
      },
      {
        pattern: 'JWT_SECRET',
        severity: 'critical',
        message: 'JWT secret sunucu tarafında kalmalıdır. İfşa edilmesi token sahteciğine yol açar.',
      },
      {
        pattern: 'STRIPE_SECRET_KEY',
        severity: 'critical',
        message: 'Stripe Secret Key istemci tarafına asla ifşa edilmemelidir.',
      },
      {
        pattern: 'AWS_SECRET_ACCESS_KEY',
        severity: 'critical',
        message: 'AWS gizli erişim anahtarı istemci tarafına ifşa edilmemelidir.',
      },
    ],
  },

  /**
   * Supabase RLS Denetçisi Ayarları
   * Kod içindeki supabase.from() çağrılarını tarar ve
   * RLS durumunu kontrol eder.
   */
  rlsScanner: {
    /** Etkinleştirme */
    enabled: true,

    /** Taranacak kaynak dosya dizinleri */
    scanDirs: ['src'],

    /** Taranacak dosya uzantıları */
    extensions: ['.ts', '.tsx', '.js', '.jsx'],

    /** Hariç tutulacak dizinler */
    excludeDirs: ['node_modules', '.next', 'dist', '.git'],

    /**
     * Supabase bağlantı bilgileri
     * RLS durumunu kontrol etmek için Management API veya doğrudan SQL kullanılır.
     * Bu değerler .env'den okunur (NEXT_PUBLIC_ olmayan versiyonları tercih edilir).
     */
    supabaseUrl: process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '',
    supabaseServiceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY || '',

    /**
     * RLS kontrolünde beyaz listelenecek tablolar
     * (örn: public erişime açık olması gereken tablolar)
     */
    whitelistedTables: [],
  },

  /**
   * Raporlama Ayarları
   */
  reporter: {
    /** Terminal çıktısını etkinleştir */
    terminal: true,

    /** Tarayıcı overlay'ini etkinleştir */
    browserOverlay: true,

    /** Overlay'in otomatik kapanma süresi (ms). 0 = manuel kapatma gerekir */
    overlayAutoCloseMs: 0,

    /** Ses uyarısı (tarayıcı) */
    soundAlert: false,
  },

  /**
   * Dosya İzleme Ayarları (Watcher)
   */
  watcher: {
    /** Debounce süresi (ms) — dosya değişimlerinde yeniden tarama gecikmesi */
    debounceMs: 500,

    /** İzlenecek ek dosya kalıpları */
    additionalWatchPatterns: [],
  },
};

module.exports = vibeSecurityConfig;
