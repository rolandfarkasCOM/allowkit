import type { Env } from '../types';

// Lowercase only — UUIDs are canonically lowercase per RFC 4122. Accepting
// both casings would create a silent record-loss bug: hashWithSalt is
// case-sensitive, so a write with one casing and a read with the other
// would produce different hashes (and therefore different KV keys).
const DEFAULT_SUBJECT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const DEFAULT_JWT_MAX_AGE = 300; // 5 minutes
const HARD_JWT_MAX_AGE_CAP = 900; // 15 minutes — refuse longer no matter what env says

const subjectIdPatternCache = new Map<string, RegExp>();

export class SubjectIdPatternError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SubjectIdPatternError';
  }
}

export class AppIdAmbiguityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AppIdAmbiguityError';
  }
}

// Throws SubjectIdPatternError if the operator-supplied SUBJECT_ID_PATTERN
// fails to compile. Callers must fail closed on this — never silently fall
// back to the default, since the operator believes their pattern is enforced.
export function getSubjectIdPattern(env: Env): RegExp {
  const raw = env.SUBJECT_ID_PATTERN;
  if (!raw) return DEFAULT_SUBJECT_ID_PATTERN;
  const cached = subjectIdPatternCache.get(raw);
  if (cached) return cached;
  let regex: RegExp;
  try {
    regex = new RegExp(raw);
  } catch (err) {
    throw new SubjectIdPatternError(
      `SUBJECT_ID_PATTERN failed to compile: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  subjectIdPatternCache.set(raw, regex);
  return regex;
}

export function parseAppList(raw: string | undefined): Set<string> {
  if (!raw) return new Set();
  return new Set(
    raw
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

// Origin comparison is ASCII case-insensitive per RFC 6454 §6.1, so the
// allowlist is normalised to lowercase. Callers must lowercase the inbound
// `Origin` header before lookup. Empty input → empty Set → fail-closed.
export function parseOriginList(raw: string | undefined): Set<string> {
  if (!raw) return new Set();
  return new Set(
    raw
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

export function appRequiresSignature(appId: string, env: Env): boolean {
  return parseAppList(env.APP_SIGNED_IDS).has(appId);
}

// Per-app secrets live in env vars named `APP_SECRET_<UPPER_APPID>`. AppIds
// that contain BOTH `-` and `_` collide when normalized (e.g. `mobile-x` and
// `mobile_x` both → `APP_SECRET_MOBILE_X`) and are rejected outright.
//
// Minimum secret length: HMAC-SHA256 has a 256-bit MAC, so a secret shorter
// than 32 bytes leaves the construction trivially brute-forceable. Reject
// short / whitespace-only secrets at use rather than letting WebCrypto
// silently import a degenerate key.
const MIN_SECRET_BYTES = 32;

export class AppSecretTooShortError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AppSecretTooShortError';
  }
}

export function getAppSecret(appId: string, env: Env): string | null {
  if (appId.includes('-') && appId.includes('_')) {
    throw new AppIdAmbiguityError(
      `appId '${appId}' contains both '-' and '_' — env-var name is ambiguous`,
    );
  }
  const key = `APP_SECRET_${appId.toUpperCase().replace(/-/g, '_')}` as const;
  const raw = env[key];
  if (typeof raw !== 'string') return null;
  const value = raw.trim();
  if (value.length === 0) return null;
  if (value.length < MIN_SECRET_BYTES) {
    throw new AppSecretTooShortError(
      `${key} is ${value.length} bytes; minimum is ${MIN_SECRET_BYTES}`,
    );
  }
  return value;
}

const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

export function isValidIdempotencyKey(key: string | undefined): key is string {
  return typeof key === 'string' && IDEMPOTENCY_KEY_PATTERN.test(key);
}

export function parseJwtMaxAge(raw: string | undefined): number {
  const n = Number(raw);
  if (Number.isFinite(n) && n > 0 && n <= HARD_JWT_MAX_AGE_CAP) return Math.floor(n);
  return DEFAULT_JWT_MAX_AGE;
}

// Truncate to 256 chars and strip control chars before storing or logging.
// Defends against D1 storage amplification and log injection.
export function sanitizeUserAgent(raw: string | undefined): string | null {
  if (!raw) return null;
  // eslint-disable-next-line no-control-regex
  const sanitized = raw.slice(0, 256).replace(/[\x00-\x1F\x7F]/g, '');
  return sanitized.length > 0 ? sanitized : null;
}
