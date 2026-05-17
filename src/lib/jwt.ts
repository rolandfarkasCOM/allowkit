// HS256 JWT verifier hardened against alg-confusion (`alg: none`, `RS256`,
// etc.) — we only ever accept the algorithm we asked for, regardless of what
// the token header claims.
//
// Signing intentionally lives in test/helpers.ts (test-only). Keeping the
// signing implementation out of the production bundle removes any future
// risk that an unrelated route handler imports it and exposes signing.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export interface JwtClaims {
  sub: string;
  iss: string;
  exp: number;
  iat: number;
}

export interface VerifyOptions {
  expectedIss: string;
  expectedSub: string;
  // Hard cap on (exp - iat). Tokens claiming longer lifetimes are rejected
  // even if signature is valid — defends against compromised customer
  // backends issuing infinite-lifetime tokens.
  maxAgeSeconds: number;
  // Clock-skew tolerance for iat in seconds. Default 5.
  clockSkewSeconds?: number;
}

export class JwtError extends Error {
  constructor(public reason: string) {
    super(reason);
    this.name = 'JwtError';
  }
}

export async function verifyJwt(
  token: string,
  secret: string,
  options: VerifyOptions,
): Promise<JwtClaims> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new JwtError('malformed_token');
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  const headerBytes = base64UrlDecode(headerB64);
  const payloadBytes = base64UrlDecode(payloadB64);
  const sigBytes = base64UrlDecode(sigB64);
  if (
    !headerBytes ||
    !payloadBytes ||
    !sigBytes ||
    headerBytes.length === 0 ||
    payloadBytes.length === 0 ||
    sigBytes.length === 0
  ) {
    throw new JwtError('malformed_token');
  }

  const header = safeJsonParse<{ alg: unknown; typ?: unknown }>(decoder.decode(headerBytes));
  const payload = safeJsonParse<Partial<JwtClaims>>(decoder.decode(payloadBytes));
  if (!header || !payload) throw new JwtError('malformed_token');

  // Strict alg check — defends against `alg: none` and RS/ES alg-confusion.
  if (header.alg !== 'HS256') throw new JwtError('unsupported_alg');
  // typ is optional per RFC 7519, but if present must be the string "JWT".
  if (header.typ !== undefined && header.typ !== 'JWT') {
    throw new JwtError('unsupported_typ');
  }

  // Signature verify — crypto.subtle.verify is constant-time per spec.
  const key = await importHmacKey(secret);
  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    sigBytes,
    encoder.encode(`${headerB64}.${payloadB64}`),
  );
  if (!valid) throw new JwtError('invalid_signature');

  // Claim shape — Number.isFinite catches NaN/±Infinity (which `typeof === 'number'`
  // accepts). JSON.parse can't actually produce NaN/Infinity from spec-compliant
  // JSON, but defense-in-depth: if a future parser swap or a pre-processed payload
  // ever introduces them, the temporal checks below would silently pass them
  // (NaN comparisons all return false), defeating the lifetime cap entirely.
  if (
    typeof payload.sub !== 'string' ||
    typeof payload.iss !== 'string' ||
    !isFiniteNumber(payload.exp) ||
    !isFiniteNumber(payload.iat)
  ) {
    throw new JwtError('invalid_claims');
  }

  const now = Math.floor(Date.now() / 1000);
  const skew = options.clockSkewSeconds ?? 5;
  if (payload.iat > now + skew) throw new JwtError('iat_in_future');
  if (payload.exp <= now - skew) throw new JwtError('expired');
  if (payload.exp - payload.iat > options.maxAgeSeconds) throw new JwtError('expiry_too_long');
  if (payload.iss !== options.expectedIss) throw new JwtError('issuer_mismatch');
  if (payload.sub !== options.expectedSub) throw new JwtError('subject_mismatch');

  return payload as JwtClaims;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function importHmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
}

function base64UrlDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  const padding = (4 - (s.length % 4)) % 4;
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padding);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

function safeJsonParse<T>(raw: string): T | null {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}
