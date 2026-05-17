import { beforeEach, describe, expect, it } from 'vitest';
import { appFetch, grantConsentBody, makeEnv, signTestJwt, SUBJECT_A } from './helpers';
import type { Env } from '../src/types';

let env: Env;
let kv: ReturnType<typeof makeEnv>['kv'];
let db: ReturnType<typeof makeEnv>['db'];

beforeEach(() => {
  ({ env, kv, db } = makeEnv());
});

describe('POST /consent', () => {
  it('writes the consent to KV and appends an audit row', async () => {
    const res = await appFetch('/consent', { env, body: grantConsentBody() });
    expect(res.status).toBe(200);

    const data = (await res.json()) as { consent: { analytics: boolean }; updatedAt: number };
    expect(data.consent.analytics).toBe(true);
    expect(typeof data.updatedAt).toBe('number');

    // KV check via the (server-internal) hash — find the consent:* key.
    const consentKeys = [...kv._store.keys()].filter((k) => k.startsWith('consent:'));
    expect(consentKeys).toHaveLength(1);
    const stored = await kv.get(consentKeys[0]!, 'json');
    expect(stored).toMatchObject({ analytics: true, marketing: false, lastAppId: 'web' });

    expect(db._rows).toHaveLength(1);
    expect(db._rows[0]).toMatchObject({ app_id: 'web', action: 'grant', analytics: 1 });
  });

  it('rejects unknown appId', async () => {
    const res = await appFetch('/consent', {
      env,
      body: grantConsentBody({ appId: 'tv' }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'unknown_app' });
  });

  it('rejects malformed body', async () => {
    const res = await appFetch('/consent', { env, body: { appId: 'web' } });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; issues: unknown[] };
    expect(body.error).toBe('invalid_body');
    expect(body.issues.length).toBeGreaterThan(0);
  });

  it('rejects necessary=false', async () => {
    const res = await appFetch('/consent', {
      env,
      body: {
        appId: 'web',
        subjectId: SUBJECT_A,
        consent: { necessary: false, functional: false, analytics: false, marketing: false },
      },
    });
    expect(res.status).toBe(400);
  });

  it('merges across apps: signed mobile write overwrites unsigned web', async () => {
    // web (unsigned, Origin-protected)
    await appFetch('/consent', {
      env,
      body: grantConsentBody({
        appId: 'web',
        consent: { necessary: true, functional: true, analytics: true, marketing: true },
      }),
    });

    // mobile (signed — needs JWT)
    const jwt = await signTestJwt(env.APP_SECRET_MOBILE!, { iss: 'mobile', sub: SUBJECT_A });
    await appFetch('/consent', {
      env,
      body: grantConsentBody({
        appId: 'mobile',
        consent: { necessary: true, functional: false, analytics: false, marketing: false },
      }),
      headers: { Authorization: `Bearer ${jwt}` },
    });

    const get = await appFetch('/consent', { env, headers: { 'X-Subject-Id': SUBJECT_A } });
    const data = (await get.json()) as { consent: { analytics: boolean }; updatedAt: number | null };
    expect(data.consent.analytics).toBe(false);
    expect(typeof data.updatedAt).toBe('number');
  });

  it('responds with no-store cache header', async () => {
    const res = await appFetch('/consent', { env, body: grantConsentBody() });
    expect(res.headers.get('cache-control')).toBe('no-store');
  });
});

describe('GET /consent (header-based subjectId)', () => {
  it('returns default record when subject has no consent yet', async () => {
    const res = await appFetch('/consent', { env, headers: { 'X-Subject-Id': SUBJECT_A } });
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      consent: { necessary: boolean; analytics: boolean };
      updatedAt: number | null;
    };
    expect(data.consent.necessary).toBe(true);
    expect(data.consent.analytics).toBe(false);
    expect(data.updatedAt).toBeNull();
  });

  it('400s without X-Subject-Id header', async () => {
    const res = await appFetch('/consent', { env });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'subject_id_required' });
  });

  it('400s for non-UUID subjectId', async () => {
    const res = await appFetch('/consent', { env, headers: { 'X-Subject-Id': 'alice' } });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_subject_id' });
  });

  it('returns the same hashed identity for repeated reads', async () => {
    await appFetch('/consent', { env, body: grantConsentBody({ subjectId: SUBJECT_A }) });
    const a = await appFetch('/consent', { env, headers: { 'X-Subject-Id': SUBJECT_A } });
    const b = await appFetch('/consent', { env, headers: { 'X-Subject-Id': SUBJECT_A } });
    const updatedAtA = ((await a.json()) as { updatedAt: number }).updatedAt;
    const updatedAtB = ((await b.json()) as { updatedAt: number }).updatedAt;
    expect(updatedAtA).toBe(updatedAtB);
  });
});
