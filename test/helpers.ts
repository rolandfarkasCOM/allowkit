import app from '../src/index';
import type { Env } from '../src/types';
import type { JwtClaims } from '../src/lib/jwt';

export const ALLOWED_ORIGIN = 'https://example.com';

// Stable UUIDv4s for tests.
export const SUBJECT_A = '11111111-1111-4111-8111-111111111111';
export const SUBJECT_B = '22222222-2222-4222-8222-222222222222';

// ─── In-memory KV ─────────────────────────────────────────────────────────────
export interface FakeKv extends KVNamespace {
  _store: Map<string, string>;
  _expirations: Map<string, number>;
}

function makeKv(): FakeKv {
  const store = new Map<string, string>();
  const expirations = new Map<string, number>();

  function alive(key: string): boolean {
    const exp = expirations.get(key);
    if (exp && Date.now() / 1000 > exp) {
      store.delete(key);
      expirations.delete(key);
      return false;
    }
    return store.has(key);
  }

  const kv = {
    _store: store,
    _expirations: expirations,
    get: async (key: string, typeOrOpts?: unknown): Promise<unknown> => {
      if (!alive(key)) return null;
      const raw = store.get(key) ?? null;
      if (raw === null) return null;
      const wantsJson =
        typeOrOpts === 'json' ||
        (typeof typeOrOpts === 'object' &&
          typeOrOpts !== null &&
          (typeOrOpts as { type?: string }).type === 'json');
      return wantsJson ? JSON.parse(raw) : raw;
    },
    put: async (key: string, value: string, opts?: { expirationTtl?: number }): Promise<void> => {
      store.set(key, value);
      if (opts?.expirationTtl) {
        expirations.set(key, Date.now() / 1000 + opts.expirationTtl);
      } else {
        expirations.delete(key);
      }
    },
    delete: async (key: string): Promise<void> => {
      store.delete(key);
      expirations.delete(key);
    },
    list: async (): Promise<unknown> => {
      const keys = [...store.keys()].filter(alive).map((name) => ({ name }));
      return { keys, list_complete: true, cacheStatus: null };
    },
    getWithMetadata: async () => ({ value: null, metadata: null, cacheStatus: null }),
  };
  return kv as unknown as FakeKv;
}

// ─── In-memory D1 ─────────────────────────────────────────────────────────────
export interface AuditRowRecord {
  subject_hash: string;
  app_id: string;
  action: 'grant' | 'withdraw';
  necessary: number;
  functional: number;
  analytics: number;
  marketing: number;
  ip_hash: string | null;
  user_agent: string | null;
  created_at: number;
  id: number;
}

export interface FakeDb extends D1Database {
  _rows: AuditRowRecord[];
}

function makeDb(): FakeDb {
  const rows: AuditRowRecord[] = [];
  let nextId = 1;

  const insert = (binds: unknown[]): void => {
    const [subjectHash, appId, action, n, f, a, m, ipHash, ua, ts] = binds;
    rows.push({
      id: nextId++,
      subject_hash: String(subjectHash),
      app_id: String(appId),
      action: action as 'grant' | 'withdraw',
      necessary: Number(n),
      functional: Number(f),
      analytics: Number(a),
      marketing: Number(m),
      ip_hash: ipHash == null ? null : String(ipHash),
      user_agent: ua == null ? null : String(ua),
      created_at: Number(ts),
    });
  };

  const selectAll = (): unknown[] =>
    rows.map((r) => ({
      app_id: r.app_id,
      action: r.action,
      analytics: r.analytics,
      necessary: r.necessary,
      functional: r.functional,
      marketing: r.marketing,
    }));

  function makeStatement(sql: string, binds: unknown[] = []): D1PreparedStatement {
    const isInsert = sql.trim().toUpperCase().startsWith('INSERT');
    return {
      bind: (...values: unknown[]) => makeStatement(sql, values),
      run: async () => {
        if (isInsert) insert(binds);
        return { success: true, meta: { changes: 1 } } as unknown as D1Result<unknown>;
      },
      all: async () =>
        ({ results: selectAll(), success: true, meta: {} }) as unknown as D1Result<unknown>,
      first: async () => (selectAll()[0] ?? null) as never,
      raw: async () => [],
    } as unknown as D1PreparedStatement;
  }

  const db = {
    _rows: rows,
    prepare: (sql: string) => makeStatement(sql),
    exec: async () => ({ count: 0, duration: 0 }),
    batch: async () => [],
    dump: async () => new ArrayBuffer(0),
    withSession: () => undefined,
  };
  return db as unknown as FakeDb;
}

// ─── Test env factory ─────────────────────────────────────────────────────────
export function makeEnv(overrides: Partial<Env> = {}) {
  const kv = makeKv();
  const db = makeDb();
  const env: Env = {
    CONSENT_KV: kv,
    AUDIT_DB: db,
    APP_IDS: 'web,mobile,desktop',
    ALLOWED_ORIGINS: 'https://example.com,https://www.example.com',
    HASH_SALT: 'test-salt-do-not-use-in-prod',
    APP_SIGNED_IDS: 'mobile,desktop',
    JWT_MAX_AGE_SECONDS: '300',
    APP_SECRET_MOBILE: 'mobile-test-secret-32-chars-min__',
    APP_SECRET_DESKTOP: 'desktop-test-secret-32-chars-min_',
    ...overrides,
  };
  return { env, kv, db };
}

// ─── Fetch helper ─────────────────────────────────────────────────────────────
interface FetchOpts {
  origin?: string | null;
  ip?: string;
  ua?: string;
  body?: unknown;
  rawBody?: string;
  method?: string;
  headers?: Record<string, string>;
  env: Env;
  contentType?: string | null;
}

export async function appFetch(path: string, opts: FetchOpts): Promise<Response> {
  const headers = new Headers(opts.headers ?? {});
  if (opts.origin !== null) {
    headers.set('Origin', opts.origin ?? ALLOWED_ORIGIN);
  }
  headers.set('CF-Connecting-IP', opts.ip ?? '198.51.100.1');
  if (opts.ua) headers.set('User-Agent', opts.ua);

  const isPost = opts.method === 'POST' || (opts.body !== undefined || opts.rawBody !== undefined);
  const init: RequestInit = {
    method: opts.method ?? (isPost ? 'POST' : 'GET'),
    headers,
  };

  if (opts.rawBody !== undefined) {
    if (opts.contentType !== null && !headers.has('Content-Type')) {
      headers.set('Content-Type', opts.contentType ?? 'application/json');
    }
    init.body = opts.rawBody;
  } else if (opts.body !== undefined) {
    if (opts.contentType !== null && !headers.has('Content-Type')) {
      headers.set('Content-Type', opts.contentType ?? 'application/json');
    }
    init.body = JSON.stringify(opts.body);
  }

  return app.fetch(new Request(`http://localhost${path}`, init), opts.env);
}

export const grantConsentBody = (
  overrides: Partial<{
    appId: string;
    subjectId: string;
    consent: { necessary: true; functional: boolean; analytics: boolean; marketing: boolean };
  }> = {},
) => ({
  appId: overrides.appId ?? 'web',
  subjectId: overrides.subjectId ?? SUBJECT_A,
  consent: overrides.consent ?? {
    necessary: true,
    functional: true,
    analytics: true,
    marketing: false,
  },
});

// HS256 JWT signer — test-only. Lives here (not in src/lib/jwt.ts) so the
// production bundle never exports signing capability. Mirrors what a
// customer's backend would do when minting tokens for their app.
const _jwtEncoder = new TextEncoder();

function _base64UrlEncode(bytes: Uint8Array): string {
  let str = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    str += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function signJwt(claims: JwtClaims, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = _base64UrlEncode(_jwtEncoder.encode(JSON.stringify(header)));
  const payloadB64 = _base64UrlEncode(_jwtEncoder.encode(JSON.stringify(claims)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    'raw',
    _jwtEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, _jwtEncoder.encode(signingInput));
  return `${headerB64}.${payloadB64}.${_base64UrlEncode(new Uint8Array(sig))}`;
}

// Convenience wrapper — defaults to a 60-second lifetime, current iat.
export async function signTestJwt(
  secret: string,
  options: {
    iss: string;
    sub: string;
    expSecondsFromNow?: number;
    iatOverride?: number;
  },
): Promise<string> {
  const iat = options.iatOverride ?? Math.floor(Date.now() / 1000);
  const exp = iat + (options.expSecondsFromNow ?? 60);
  return signJwt({ iss: options.iss, sub: options.sub, iat, exp }, secret);
}
