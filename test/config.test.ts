import { beforeEach, describe, expect, it } from 'vitest';
import { appFetch, makeEnv } from './helpers';
import type { Env } from '../src/types';

let env: Env;
beforeEach(() => {
  ({ env } = makeEnv());
});

describe('GET /config/:appId', () => {
  it('returns the consent contract for a known app', async () => {
    const res = await appFetch('/config/web', { env });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      appId: string;
      categories: readonly string[];
      version: number;
    };
    expect(body).toEqual({
      appId: 'web',
      categories: ['necessary', 'functional', 'analytics', 'marketing'],
      version: 1,
    });
  });

  it('404s for an unknown app', async () => {
    const res = await appFetch('/config/tv', { env });
    expect(res.status).toBe(404);
  });
});
