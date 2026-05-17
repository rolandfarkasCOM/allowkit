import { beforeEach, describe, expect, it } from 'vitest';
import { appFetch, grantConsentBody, makeEnv, SUBJECT_A } from './helpers';
import type { Env } from '../src/types';

let env: Env;
let kv: ReturnType<typeof makeEnv>['kv'];
let db: ReturnType<typeof makeEnv>['db'];

beforeEach(() => {
  ({ env, kv, db } = makeEnv());
});

describe('POST /withdraw', () => {
  it('resets non-necessary categories to false and appends an audit row', async () => {
    await appFetch('/consent', {
      env,
      body: grantConsentBody({
        consent: { necessary: true, functional: true, analytics: true, marketing: true },
      }),
    });

    const res = await appFetch('/withdraw', {
      env,
      body: { appId: 'web', subjectId: SUBJECT_A },
    });
    expect(res.status).toBe(200);

    const data = (await res.json()) as {
      consent: { necessary: boolean; functional: boolean; analytics: boolean; marketing: boolean };
    };
    expect(data.consent).toMatchObject({
      necessary: true,
      functional: false,
      analytics: false,
      marketing: false,
    });

    const consentKeys = [...kv._store.keys()].filter((k) => k.startsWith('consent:'));
    const stored = await kv.get(consentKeys[0]!, 'json');
    expect(stored).toMatchObject({ analytics: false, marketing: false });

    expect(db._rows.map((r) => r.action)).toEqual(['grant', 'withdraw']);
  });

  it('rejects unknown appId', async () => {
    const res = await appFetch('/withdraw', {
      env,
      body: { appId: 'tv', subjectId: SUBJECT_A },
    });
    expect(res.status).toBe(400);
  });

  it('rejects non-UUID subjectId', async () => {
    const res = await appFetch('/withdraw', {
      env,
      body: { appId: 'web', subjectId: 'never-consented' },
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_subject_id' });
  });

  it('works without prior consent (idempotent withdrawal)', async () => {
    const res = await appFetch('/withdraw', {
      env,
      body: { appId: 'web', subjectId: SUBJECT_A },
    });
    expect(res.status).toBe(200);
    expect(db._rows).toHaveLength(1);
    expect(db._rows[0]?.action).toBe('withdraw');
  });
});
