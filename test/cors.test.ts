import { beforeEach, describe, expect, it } from 'vitest';
import { ALLOWED_ORIGIN, appFetch, makeEnv, SUBJECT_A } from './helpers';
import type { Env } from '../src/types';

let env: Env;
beforeEach(() => {
  ({ env } = makeEnv());
});

describe('CORS', () => {
  it('allows requests from an allowlisted origin', async () => {
    const res = await appFetch('/config/web', {
      env,
      origin: ALLOWED_ORIGIN,
      headers: { 'X-Subject-Id': SUBJECT_A },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN);
  });

  it('omits the allow-origin header for an unlisted origin', async () => {
    const res = await appFetch('/config/web', { env, origin: 'https://evil.example' });
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('handles preflight (OPTIONS) for an allowlisted origin', async () => {
    const res = await appFetch('/consent', {
      env,
      method: 'OPTIONS',
      origin: ALLOWED_ORIGIN,
      headers: {
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type,authorization,x-subject-id,idempotency-key',
      },
    });
    expect(res.status).toBeLessThan(300);
    expect(res.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN);
    expect(res.headers.get('access-control-allow-methods')?.toUpperCase()).toContain('POST');
  });

  it('rejects preflight from an unlisted origin', async () => {
    const res = await appFetch('/consent', {
      env,
      method: 'OPTIONS',
      origin: 'https://evil.example',
      headers: {
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type',
      },
    });
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });
});
