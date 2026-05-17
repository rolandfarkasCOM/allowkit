import { Hono } from 'hono';
import type { Env } from '../types';
import { DEFAULT_CONSENT } from '../types';
import { WithdrawBodySchema } from '../lib/schema';
import { hashWithSalt } from '../lib/hash';
import { putConsent } from '../lib/kv';
import { appendAudit } from '../lib/audit';
import { readSecureBody } from '../lib/readBody';
import { sanitizeUserAgent } from '../lib/security';

export const withdrawRoute = new Hono<{ Bindings: Env }>();

withdrawRoute.post('/withdraw', async (c) => {
  const result = await readSecureBody(c, WithdrawBodySchema);
  if (!result.ok) return result.response;

  const { appId, subjectId } = result.body;
  const now = Date.now();
  const subjectHash = await hashWithSalt(subjectId, c.env.HASH_SALT);
  const ipHeader = c.req.header('cf-connecting-ip') ?? null;
  const ipHash = ipHeader ? await hashWithSalt(ipHeader, c.env.HASH_SALT) : null;
  const userAgent = sanitizeUserAgent(c.req.header('user-agent') ?? undefined);

  // Audit row first; KV cache second. See routes/consent.ts for rationale.
  await appendAudit(c.env.AUDIT_DB, {
    subjectHash,
    appId,
    action: 'withdraw',
    consent: DEFAULT_CONSENT,
    ipHash,
    userAgent,
    createdAt: now,
  });
  const record = await putConsent(
    c.env.CONSENT_KV,
    subjectHash,
    DEFAULT_CONSENT,
    appId,
    now,
  );

  return c.json(
    {
      consent: {
        necessary: record.necessary,
        functional: record.functional,
        analytics: record.analytics,
        marketing: record.marketing,
      },
      updatedAt: record.updatedAt,
    },
    200,
  );
});
