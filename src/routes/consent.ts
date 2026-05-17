import { Hono } from 'hono';
import type { Env } from '../types';
import { DEFAULT_CONSENT } from '../types';
import { ConsentBodySchema } from '../lib/schema';
import { hashWithSalt, sha256Hex } from '../lib/hash';
import { getConsent, putConsent } from '../lib/kv';
import { appendAudit } from '../lib/audit';
import { readSecureBody } from '../lib/readBody';
import {
  getSubjectIdPattern,
  isValidIdempotencyKey,
  sanitizeUserAgent,
  SubjectIdPatternError,
} from '../lib/security';
import { checkIdempotency } from '../lib/idempotency';

export const consentRoute = new Hono<{ Bindings: Env }>();

// SubjectId is read from the `X-Subject-Id` header — never appears in the URL
// path (which would leak into CDN logs, browser history, and proxy logs).
// Response shape is uniform: never echoes the server-side subject hash, never
// leaks cross-app activity via lastAppId.
consentRoute.get('/consent', async (c) => {
  const subjectId = c.req.header('x-subject-id');
  if (!subjectId) return c.json({ error: 'subject_id_required' }, 400);

  let pattern: RegExp;
  try {
    pattern = getSubjectIdPattern(c.env);
  } catch (err) {
    if (err instanceof SubjectIdPatternError) {
      return c.json({ error: 'server_misconfigured' }, 500);
    }
    throw err;
  }
  if (!pattern.test(subjectId)) {
    return c.json({ error: 'invalid_subject_id' }, 400);
  }

  const subjectHash = await hashWithSalt(subjectId, c.env.HASH_SALT);
  const record = await getConsent(c.env.CONSENT_KV, subjectHash);

  return c.json({
    consent: record
      ? {
          necessary: record.necessary,
          functional: record.functional,
          analytics: record.analytics,
          marketing: record.marketing,
        }
      : DEFAULT_CONSENT,
    updatedAt: record ? record.updatedAt : null,
  });
});

consentRoute.post('/consent', async (c) => {
  const result = await readSecureBody(c, ConsentBodySchema);
  if (!result.ok) return result.response;

  const { appId, subjectId, consent } = result.body;
  const now = Date.now();
  const subjectHash = await hashWithSalt(subjectId, c.env.HASH_SALT);

  const idempotencyKey = c.req.header('idempotency-key');
  if (isValidIdempotencyKey(idempotencyKey)) {
    const bodyHash = await sha256Hex(result.raw);
    const outcome = await checkIdempotency(
      c.env.CONSENT_KV,
      subjectHash,
      idempotencyKey,
      bodyHash,
    );
    if (outcome === 'replay') {
      const current = await getConsent(c.env.CONSENT_KV, subjectHash);
      if (current) {
        return c.json({
          consent: {
            necessary: current.necessary,
            functional: current.functional,
            analytics: current.analytics,
            marketing: current.marketing,
          },
          updatedAt: current.updatedAt,
          replayed: true,
        });
      }
      // Idempotency entry survived but the consent record was evicted/deleted.
      // Fall through to a fresh write rather than synthesise a stale-looking
      // response — caller gets the same outcome shape they would have on the
      // first call.
    } else if (outcome === 'conflict') {
      return c.json(
        {
          error: 'idempotency_conflict',
          message: 'Same Idempotency-Key supplied with a different body',
        },
        409,
      );
    }
  }

  const ipHeader = c.req.header('cf-connecting-ip') ?? null;
  const ipHash = ipHeader ? await hashWithSalt(ipHeader, c.env.HASH_SALT) : null;
  const userAgent = sanitizeUserAgent(c.req.header('user-agent') ?? undefined);

  // Audit log is the source of truth; KV is a denormalised cache. Write the
  // audit row first so a downstream KV failure leaves intent recorded rather
  // than silently mutating the cache without a corresponding audit entry
  // (GDPR Art. 7(1) requires demonstrable consent records).
  await appendAudit(c.env.AUDIT_DB, {
    subjectHash,
    appId,
    action: 'grant',
    consent,
    ipHash,
    userAgent,
    createdAt: now,
  });
  const record = await putConsent(c.env.CONSENT_KV, subjectHash, consent, appId, now);

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
