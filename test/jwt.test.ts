import { describe, expect, it } from 'vitest';
import { JwtError, verifyJwt } from '../src/lib/jwt';
import { signJwt } from './helpers';

const SECRET = 'test-secret-32-chars-minimum-aaaa';

const baseClaims = (overrides: Partial<{ sub: string; iss: string; iat: number; exp: number }> = {}) => ({
  sub: 'subject-1',
  iss: 'mobile',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 60,
  ...overrides,
});

describe('JWT — happy path', () => {
  it('signs then verifies a token round-trip', async () => {
    const token = await signJwt(baseClaims(), SECRET);
    const claims = await verifyJwt(token, SECRET, {
      expectedIss: 'mobile',
      expectedSub: 'subject-1',
      maxAgeSeconds: 300,
    });
    expect(claims.iss).toBe('mobile');
    expect(claims.sub).toBe('subject-1');
  });
});

describe('JWT — alg-confusion defense', () => {
  it('rejects alg: none', async () => {
    const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payload = btoa(JSON.stringify(baseClaims()))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    // Non-empty placeholder signature so we exercise the alg check, not the
    // empty-bytes check.
    const token = `${header}.${payload}.AAAA`;

    await expect(
      verifyJwt(token, SECRET, { expectedIss: 'mobile', expectedSub: 'subject-1', maxAgeSeconds: 300 }),
    ).rejects.toThrow(JwtError);
    await expect(
      verifyJwt(token, SECRET, { expectedIss: 'mobile', expectedSub: 'subject-1', maxAgeSeconds: 300 }),
    ).rejects.toMatchObject({ reason: 'unsupported_alg' });
  });

  it('rejects token with empty signature segment (defense-in-depth)', async () => {
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payload = btoa(JSON.stringify(baseClaims()))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const token = `${header}.${payload}.`;
    await expect(
      verifyJwt(token, SECRET, { expectedIss: 'mobile', expectedSub: 'subject-1', maxAgeSeconds: 300 }),
    ).rejects.toMatchObject({ reason: 'malformed_token' });
  });

  it('rejects alg: RS256', async () => {
    const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payload = btoa(JSON.stringify(baseClaims()))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    // Forge a "signature" using HS256 with a known secret — the verifier
    // should still refuse because the alg field is wrong.
    const fakeSig = 'AAAA';
    const token = `${header}.${payload}.${fakeSig}`;

    await expect(
      verifyJwt(token, SECRET, { expectedIss: 'mobile', expectedSub: 'subject-1', maxAgeSeconds: 300 }),
    ).rejects.toMatchObject({ reason: 'unsupported_alg' });
  });
});

describe('JWT — claim validation', () => {
  it('rejects expired token', async () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    const token = await signJwt(baseClaims({ iat: past - 60, exp: past }), SECRET);
    await expect(
      verifyJwt(token, SECRET, { expectedIss: 'mobile', expectedSub: 'subject-1', maxAgeSeconds: 300 }),
    ).rejects.toMatchObject({ reason: 'expired' });
  });

  it('rejects iat in the future', async () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    const token = await signJwt(baseClaims({ iat: future, exp: future + 60 }), SECRET);
    await expect(
      verifyJwt(token, SECRET, { expectedIss: 'mobile', expectedSub: 'subject-1', maxAgeSeconds: 300 }),
    ).rejects.toMatchObject({ reason: 'iat_in_future' });
  });

  it('rejects token with lifetime exceeding maxAgeSeconds', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(baseClaims({ iat: now, exp: now + 7200 }), SECRET);
    await expect(
      verifyJwt(token, SECRET, { expectedIss: 'mobile', expectedSub: 'subject-1', maxAgeSeconds: 300 }),
    ).rejects.toMatchObject({ reason: 'expiry_too_long' });
  });

  it('rejects issuer mismatch', async () => {
    const token = await signJwt(baseClaims({ iss: 'mobile' }), SECRET);
    await expect(
      verifyJwt(token, SECRET, { expectedIss: 'desktop', expectedSub: 'subject-1', maxAgeSeconds: 300 }),
    ).rejects.toMatchObject({ reason: 'issuer_mismatch' });
  });

  it('rejects subject mismatch', async () => {
    const token = await signJwt(baseClaims({ sub: 'subject-1' }), SECRET);
    await expect(
      verifyJwt(token, SECRET, { expectedIss: 'mobile', expectedSub: 'subject-2', maxAgeSeconds: 300 }),
    ).rejects.toMatchObject({ reason: 'subject_mismatch' });
  });

  it('rejects token signed with the wrong secret', async () => {
    const token = await signJwt(baseClaims(), 'different-secret-32-chars-aaaaaa');
    await expect(
      verifyJwt(token, SECRET, { expectedIss: 'mobile', expectedSub: 'subject-1', maxAgeSeconds: 300 }),
    ).rejects.toMatchObject({ reason: 'invalid_signature' });
  });
});

describe('JWT — malformed tokens', () => {
  it('rejects 2-part token', async () => {
    await expect(
      verifyJwt('a.b', SECRET, { expectedIss: 'x', expectedSub: 'y', maxAgeSeconds: 300 }),
    ).rejects.toMatchObject({ reason: 'malformed_token' });
  });

  it('rejects token with non-base64 segment', async () => {
    await expect(
      verifyJwt('!@#.!@#.!@#', SECRET, { expectedIss: 'x', expectedSub: 'y', maxAgeSeconds: 300 }),
    ).rejects.toMatchObject({ reason: 'malformed_token' });
  });
});
