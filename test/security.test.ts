import { beforeEach, describe, expect, it } from 'vitest';
import { appFetch, grantConsentBody, makeEnv, signTestJwt, SUBJECT_A, SUBJECT_B } from './helpers';
import { MAX_BODY_BYTES } from '../src/types';
import type { Env } from '../src/types';

let env: Env;
let kv: ReturnType<typeof makeEnv>['kv'];
let db: ReturnType<typeof makeEnv>['db'];

beforeEach(() => {
  ({ env, kv, db } = makeEnv());
});

describe('Content-Type enforcement', () => {
  it('415s POST without Content-Type', async () => {
    const res = await appFetch('/consent', {
      env,
      method: 'POST',
      rawBody: JSON.stringify(grantConsentBody()),
      contentType: null,
    });
    expect(res.status).toBe(415);
    expect(await res.json()).toMatchObject({ error: 'unsupported_media_type' });
  });

  it('415s POST with wrong Content-Type', async () => {
    const res = await appFetch('/consent', {
      env,
      method: 'POST',
      rawBody: 'appId=web&subjectId=' + SUBJECT_A,
      contentType: 'application/x-www-form-urlencoded',
    });
    expect(res.status).toBe(415);
  });

  it('accepts Content-Type with charset', async () => {
    const res = await appFetch('/consent', {
      env,
      method: 'POST',
      rawBody: JSON.stringify(grantConsentBody()),
      contentType: 'application/json; charset=utf-8',
    });
    expect(res.status).toBe(200);
  });
});

describe('Body size limit', () => {
  it('413s when body exceeds max size', async () => {
    const padding = 'x'.repeat(MAX_BODY_BYTES);
    const huge = JSON.stringify({ ...grantConsentBody(), pad: padding });
    const res = await appFetch('/consent', { env, method: 'POST', rawBody: huge });
    expect(res.status).toBe(413);
    expect(await res.json()).toMatchObject({ error: 'payload_too_large' });
  });
});

describe('Strict object validation', () => {
  it('rejects unknown keys in consent body', async () => {
    const res = await appFetch('/consent', {
      env,
      body: { ...grantConsentBody(), extraField: 'hax' },
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_body' });
  });

  it('rejects unknown keys inside the consent object', async () => {
    const res = await appFetch('/consent', {
      env,
      body: {
        appId: 'web',
        subjectId: SUBJECT_A,
        consent: {
          necessary: true,
          functional: false,
          analytics: false,
          marketing: false,
          extra: true,
        },
      },
    });
    expect(res.status).toBe(400);
  });
});

describe('AppId case + collision rules', () => {
  it('rejects uppercase appId at schema level', async () => {
    const res = await appFetch('/consent', {
      env,
      body: { ...grantConsentBody(), appId: 'Web' },
    });
    expect(res.status).toBe(400);
  });

  it('rejects appId containing both `-` and `_` (env-var collision)', async () => {
    const collisionEnv = makeEnv({
      APP_IDS: 'web,mobile,desktop,foo-bar_baz',
      APP_SIGNED_IDS: 'foo-bar_baz',
    }).env;
    const sig = await signTestJwt('whatever', { iss: 'foo-bar_baz', sub: SUBJECT_A });
    const res = await appFetch('/consent', {
      env: collisionEnv,
      body: grantConsentBody({ appId: 'foo-bar_baz' }),
      headers: { Authorization: `Bearer ${sig}` },
    });
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: 'server_misconfigured' });
  });
});

describe('SubjectId pattern (UUIDv4 default)', () => {
  it('accepts a valid UUIDv4 subjectId', async () => {
    const res = await appFetch('/consent', { env, body: grantConsentBody() });
    expect(res.status).toBe(200);
  });

  it('rejects a non-UUIDv4 subjectId on POST /consent', async () => {
    const res = await appFetch('/consent', {
      env,
      body: grantConsentBody({ subjectId: 'not-a-uuid' }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_subject_id' });
  });

  it('rejects an UPPERCASE UUIDv4 (canonical lowercase only)', async () => {
    const res = await appFetch('/consent', {
      env,
      // UUID with hex letters so .toUpperCase() actually changes characters.
      body: grantConsentBody({ subjectId: 'AABBCCDD-EEFF-4ABC-8DEF-AABBCCDDEEFF' }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_subject_id' });
  });

  it('honors SUBJECT_ID_PATTERN override', async () => {
    const customEnv = makeEnv({ SUBJECT_ID_PATTERN: '^user-[0-9]+$' }).env;
    const res = await appFetch('/consent', {
      env: customEnv,
      body: grantConsentBody({ subjectId: 'user-12345' }),
    });
    expect(res.status).toBe(200);
  });

  it('fails closed on broken SUBJECT_ID_PATTERN (no silent fallback)', async () => {
    const brokenEnv = makeEnv({ SUBJECT_ID_PATTERN: '[unclosed-bracket' }).env;
    const res = await appFetch('/consent', { env: brokenEnv, body: grantConsentBody() });
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: 'server_misconfigured' });
  });
});

describe('JWT auth for signed apps', () => {
  it('rejects unsigned POST from a signed-required app', async () => {
    const res = await appFetch('/consent', {
      env,
      body: grantConsentBody({ appId: 'mobile' }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'missing_token' });
  });

  it('accepts a correctly-signed POST from a signed-required app', async () => {
    const jwt = await signTestJwt(env.APP_SECRET_MOBILE!, { iss: 'mobile', sub: SUBJECT_A });
    const res = await appFetch('/consent', {
      env,
      body: grantConsentBody({ appId: 'mobile' }),
      headers: { Authorization: `Bearer ${jwt}` },
    });
    expect(res.status).toBe(200);
  });

  it('rejects a JWT signed with the wrong secret', async () => {
    const jwt = await signTestJwt('wrong-secret-32-chars-pad-aaaaaa', { iss: 'mobile', sub: SUBJECT_A });
    const res = await appFetch('/consent', {
      env,
      body: grantConsentBody({ appId: 'mobile' }),
      headers: { Authorization: `Bearer ${jwt}` },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'invalid_token' });
  });

  it('rejects a JWT whose sub does not match the body subjectId', async () => {
    const jwt = await signTestJwt(env.APP_SECRET_MOBILE!, { iss: 'mobile', sub: SUBJECT_B });
    const res = await appFetch('/consent', {
      env,
      body: grantConsentBody({ appId: 'mobile', subjectId: SUBJECT_A }),
      headers: { Authorization: `Bearer ${jwt}` },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'invalid_token' });
  });

  it('rejects an expired JWT', async () => {
    const jwt = await signTestJwt(env.APP_SECRET_MOBILE!, {
      iss: 'mobile',
      sub: SUBJECT_A,
      iatOverride: Math.floor(Date.now() / 1000) - 3600,
      expSecondsFromNow: -3540, // exp = iat + 60, both in the past
    });
    const res = await appFetch('/consent', {
      env,
      body: grantConsentBody({ appId: 'mobile' }),
      headers: { Authorization: `Bearer ${jwt}` },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'invalid_token' });
  });

  it('rejects a JWT whose lifetime exceeds JWT_MAX_AGE_SECONDS', async () => {
    const jwt = await signTestJwt(env.APP_SECRET_MOBILE!, {
      iss: 'mobile',
      sub: SUBJECT_A,
      expSecondsFromNow: 600, // 10 min, exceeds 300 default
    });
    const res = await appFetch('/consent', {
      env,
      body: grantConsentBody({ appId: 'mobile' }),
      headers: { Authorization: `Bearer ${jwt}` },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'invalid_token' });
  });

  it('500s when APP_SECRET is shorter than 32 bytes', async () => {
    // 16-byte secret — half the HMAC-SHA256 MAC width, trivially brute-forceable.
    const weak = 'tooshort16chars_';
    const weakEnv = makeEnv({ APP_SECRET_MOBILE: weak }).env;
    const jwt = await signTestJwt(weak, { iss: 'mobile', sub: SUBJECT_A });
    const res = await appFetch('/consent', {
      env: weakEnv,
      body: grantConsentBody({ appId: 'mobile' }),
      headers: { Authorization: `Bearer ${jwt}` },
    });
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: 'server_misconfigured' });
  });

  it('treats whitespace-only APP_SECRET as missing (also 500)', async () => {
    const whitespaceEnv = makeEnv({ APP_SECRET_MOBILE: '                    ' }).env;
    const jwt = await signTestJwt('does-not-matter-still-blocked-aaaa', {
      iss: 'mobile',
      sub: SUBJECT_A,
    });
    const res = await appFetch('/consent', {
      env: whitespaceEnv,
      body: grantConsentBody({ appId: 'mobile' }),
      headers: { Authorization: `Bearer ${jwt}` },
    });
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: 'server_misconfigured' });
  });
});

describe('Origin enforcement for unsigned apps', () => {
  it('403s POST from unsigned app with no Origin header', async () => {
    const res = await appFetch('/consent', {
      env,
      origin: null,
      body: grantConsentBody({ appId: 'web' }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'origin_required' });
  });

  it('403s POST from unsigned app with non-allowlisted Origin', async () => {
    const res = await appFetch('/consent', {
      env,
      origin: 'https://evil.example',
      body: grantConsentBody({ appId: 'web' }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'origin_not_allowed' });
  });

  it('200s POST from unsigned app with allowlisted Origin', async () => {
    const res = await appFetch('/consent', {
      env,
      origin: 'https://example.com',
      body: grantConsentBody({ appId: 'web' }),
    });
    expect(res.status).toBe(200);
  });

  it('treats Origin as case-insensitive (RFC 6454)', async () => {
    const res = await appFetch('/consent', {
      env,
      origin: 'HTTPS://Example.COM',
      body: grantConsentBody({ appId: 'web' }),
    });
    expect(res.status).toBe(200);
  });
});

describe('Idempotency body-binding', () => {
  it('replays same key + same body without writing a second audit row', async () => {
    const idem = 'idem-key-abc-123';
    const a = await appFetch('/consent', {
      env,
      body: grantConsentBody(),
      headers: { 'Idempotency-Key': idem },
    });
    expect(a.status).toBe(200);

    const b = await appFetch('/consent', {
      env,
      body: grantConsentBody(),
      headers: { 'Idempotency-Key': idem },
    });
    expect(b.status).toBe(200);
    expect((await b.json()) as { replayed?: boolean }).toMatchObject({ replayed: true });
    expect(db._rows).toHaveLength(1);
  });

  it('409s same key + different body', async () => {
    const idem = 'idem-key-abc-123';
    await appFetch('/consent', {
      env,
      body: grantConsentBody(),
      headers: { 'Idempotency-Key': idem },
    });

    const res = await appFetch('/consent', {
      env,
      body: grantConsentBody({
        consent: { necessary: true, functional: false, analytics: true, marketing: true },
      }),
      headers: { 'Idempotency-Key': idem },
    });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: 'idempotency_conflict' });
    expect(db._rows).toHaveLength(1);
  });

  it('treats different idempotency keys as separate requests', async () => {
    await appFetch('/consent', {
      env,
      body: grantConsentBody(),
      headers: { 'Idempotency-Key': 'first' },
    });
    await appFetch('/consent', {
      env,
      body: grantConsentBody(),
      headers: { 'Idempotency-Key': 'second' },
    });
    expect(db._rows).toHaveLength(2);
  });

  it('falls through to fresh write on replay if KV record was evicted', async () => {
    const idem = 'idem-evict-edge-case';
    // First write
    const a = await appFetch('/consent', {
      env,
      body: grantConsentBody(),
      headers: { 'Idempotency-Key': idem },
    });
    expect(a.status).toBe(200);
    expect(db._rows).toHaveLength(1);

    // Simulate eviction: delete the consent record but leave the idempotency key.
    const consentKeys = [...kv._store.keys()].filter((k) => k.startsWith('consent:'));
    for (const k of consentKeys) await kv.delete(k);

    // Replay should fall through to a fresh write rather than synthesise a stale response.
    const b = await appFetch('/consent', {
      env,
      body: grantConsentBody(),
      headers: { 'Idempotency-Key': idem },
    });
    expect(b.status).toBe(200);
    const body = (await b.json()) as { replayed?: boolean };
    expect(body.replayed).toBeUndefined();
    expect(db._rows).toHaveLength(2);
  });

  it('ignores malformed idempotency keys (still processes the request)', async () => {
    const res = await appFetch('/consent', {
      env,
      body: grantConsentBody(),
      headers: { 'Idempotency-Key': 'has spaces!' },
    });
    expect(res.status).toBe(200);
    expect(db._rows).toHaveLength(1);
  });
});

describe('Cache-Control', () => {
  it('sets no-store on every response', async () => {
    const res = await appFetch('/config/web', { env });
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('pragma')).toBe('no-cache');
  });
});

describe('User-Agent sanitization', () => {
  it('truncates UA longer than 256 chars', async () => {
    // 300 printable chars — Node's Headers.set rejects raw control bytes
    // (HTTP spec forbids them in header values), so Workers / fetch never
    // see them anyway. The control-char strip in sanitizeUserAgent is
    // defense-in-depth; truncation is the testable behaviour.
    const longUa = 'A'.repeat(300);
    await appFetch('/consent', {
      env,
      body: grantConsentBody(),
      ua: longUa,
    });
    const stored = db._rows[0]?.user_agent ?? '';
    expect(stored.length).toBe(256);
  });
});

describe('Information disclosure', () => {
  it('GET /consent never echoes subjectHash', async () => {
    await appFetch('/consent', { env, body: grantConsentBody() });
    const res = await appFetch('/consent', {
      env,
      headers: { 'X-Subject-Id': SUBJECT_A },
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).not.toHaveProperty('subjectHash');
    expect(body).not.toHaveProperty('lastAppId');
    expect(body).not.toHaveProperty('exists');
  });

  it('POST /consent response omits subjectHash and lastAppId', async () => {
    const res = await appFetch('/consent', { env, body: grantConsentBody() });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).not.toHaveProperty('subjectHash');
    expect(body).not.toHaveProperty('lastAppId');
    expect(body).not.toHaveProperty('record');
  });
});
