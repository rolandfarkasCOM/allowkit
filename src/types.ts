export interface Env {
  CONSENT_KV: KVNamespace;
  AUDIT_DB: D1Database;
  APP_IDS: string;
  ALLOWED_ORIGINS: string;
  HASH_SALT: string;
  // Comma-separated list of appIds whose POST requests must carry a JWT
  // bearer token signed with the per-app secret. Apps NOT in this list rely
  // on Origin allowlist enforcement (industry-standard for anonymous web
  // visitors — see CookieYes / OneTrust / Cookiebot threat models).
  APP_SIGNED_IDS?: string;
  // Hard cap on JWT lifetime — token's (exp - iat) must be ≤ this. Default
  // 300 (5 min). Capped at 900 (15 min) regardless of env value.
  JWT_MAX_AGE_SECONDS?: string;
  // Per-app JWT signing secrets are read from env vars named
  // `APP_SECRET_<UPPER_APPID>`. AppIds containing both `-` and `_` are
  // rejected at use to prevent env-var name collisions.
  // Example: APP_SECRET_MOBILE, APP_SECRET_DESKTOP.
  // Override the default UUIDv4 subject-id pattern. Any RegExp body string.
  // If parsing fails the worker fails closed (refuses all writes) — never
  // silently falls back to the default.
  SUBJECT_ID_PATTERN?: string;
  // Allow per-app secret env vars to live alongside known fields without
  // breaking strict typing.
  [key: `APP_SECRET_${string}`]: string | undefined;
}

export interface Consent {
  necessary: boolean;
  functional: boolean;
  analytics: boolean;
  marketing: boolean;
}

export interface ConsentRecord extends Consent {
  updatedAt: number;
  lastAppId: string;
}

export const DEFAULT_CONSENT: Consent = {
  necessary: true,
  functional: false,
  analytics: false,
  marketing: false,
};

export type AuditAction = 'grant' | 'withdraw';

export interface AuditRow {
  subjectHash: string;
  appId: string;
  action: AuditAction;
  consent: Consent;
  ipHash: string | null;
  userAgent: string | null;
  createdAt: number;
}

export const MAX_BODY_BYTES = 4096;
