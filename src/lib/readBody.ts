import type { Context } from 'hono';
import * as v from 'valibot';
import type { Env } from '../types';
import { MAX_BODY_BYTES } from '../types';
import { flattenIssues } from './schema';
import { JwtError, verifyJwt } from './jwt';
import { isAppIdAllowed } from '../middleware/validateAppId';
import {
  AppIdAmbiguityError,
  appRequiresSignature,
  AppSecretTooShortError,
  getAppSecret,
  getSubjectIdPattern,
  parseJwtMaxAge,
  parseOriginList,
  SubjectIdPatternError,
} from './security';

interface ReadOk<T> {
  ok: true;
  body: T;
  raw: string;
}

interface ReadFail {
  ok: false;
  response: Response;
}

// Reads a POST request body and runs the full security gauntlet:
//   1. Body size cap (4 KB → 413)
//   2. JSON parse (→ 400)
//   3. Valibot schema (strict, unknown keys rejected → 400)
//   4. appId allowlist (→ 400)
//   5. SubjectId pattern (UUIDv4 by default; configurable, fail-closed)
//   6. Auth: JWT bearer for apps in APP_SIGNED_IDS (→ 401), strict Origin
//      allowlist for unsigned apps (→ 403). The JWT path subsumes the prior
//      body-HMAC scheme — JWT binds writes to a specific subject; HMAC only
//      proved "from this app" without subject-binding.
// Returns either { ok: true, body, raw } or { ok: false, response }.
export async function readSecureBody<S extends v.GenericSchema>(
  c: Context<{ Bindings: Env }>,
  schema: S,
): Promise<ReadOk<v.InferOutput<S>> | ReadFail> {
  let raw: string;
  try {
    raw = await c.req.text();
  } catch {
    return { ok: false, response: c.json({ error: 'invalid_body' }, 400) };
  }

  if (raw.length > MAX_BODY_BYTES) {
    return {
      ok: false,
      response: c.json({ error: 'payload_too_large', maxBytes: MAX_BODY_BYTES }, 413),
    };
  }

  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return { ok: false, response: c.json({ error: 'invalid_json' }, 400) };
  }

  const parsed = v.safeParse(schema, json);
  if (!parsed.success) {
    return {
      ok: false,
      response: c.json({ error: 'invalid_body', issues: flattenIssues(parsed.issues) }, 400),
    };
  }

  const body = parsed.output as { appId: string; subjectId?: string };

  if (!isAppIdAllowed(body.appId, c.env)) {
    return { ok: false, response: c.json({ error: 'unknown_app' }, 400) };
  }

  if (typeof body.subjectId === 'string') {
    let pattern: RegExp;
    try {
      pattern = getSubjectIdPattern(c.env);
    } catch (err) {
      if (err instanceof SubjectIdPatternError) {
        return { ok: false, response: c.json({ error: 'server_misconfigured' }, 500) };
      }
      throw err;
    }
    if (!pattern.test(body.subjectId)) {
      return { ok: false, response: c.json({ error: 'invalid_subject_id' }, 400) };
    }
  }

  // Auth gate — signed apps require a JWT, unsigned apps require Origin.
  if (appRequiresSignature(body.appId, c.env)) {
    const authError = await verifyJwtForBody(c, body);
    if (authError) return { ok: false, response: authError };
  } else {
    const originError = enforceOrigin(c);
    if (originError) return { ok: false, response: originError };
  }

  return { ok: true, body: parsed.output, raw };
}

async function verifyJwtForBody(
  c: Context<{ Bindings: Env }>,
  body: { appId: string; subjectId?: string },
): Promise<Response | null> {
  // JWT subject-binding requires a subjectId in the body. Schemas that
  // include subjectId (consent, withdraw) trigger this path; any future
  // schema without subjectId on a signed app is a misuse.
  if (typeof body.subjectId !== 'string') {
    return c.json({ error: 'subject_required_for_signed_app' }, 400);
  }

  let secret: string | null;
  try {
    secret = getAppSecret(body.appId, c.env);
  } catch (err) {
    if (err instanceof AppIdAmbiguityError) {
      return c.json({ error: 'server_misconfigured' }, 500);
    }
    if (err instanceof AppSecretTooShortError) {
      console.error(`app_secret_too_short app=${body.appId} reason=${err.message}`);
      return c.json({ error: 'server_misconfigured' }, 500);
    }
    throw err;
  }
  if (!secret) {
    return c.json({ error: 'server_misconfigured' }, 500);
  }

  const auth = c.req.header('authorization') ?? '';
  const match = /^Bearer\s+(\S+)$/i.exec(auth);
  if (!match) {
    return c.json({ error: 'missing_token' }, 401);
  }

  try {
    await verifyJwt(match[1]!, secret, {
      expectedIss: body.appId,
      expectedSub: body.subjectId,
      maxAgeSeconds: parseJwtMaxAge(c.env.JWT_MAX_AGE_SECONDS),
    });
  } catch (err) {
    // Log the specific reason server-side (Cloudflare Workers Logs / observability)
    // so integrators can debug, but never echo it to the client — that's a
    // pre-signature side-channel for token-format probing by attackers without
    // the secret.
    if (err instanceof JwtError) {
      console.error(`jwt_verify_failed reason=${err.reason} app=${body.appId}`);
    } else {
      console.error('jwt_verify_failed unexpected_error', err);
    }
    return c.json({ error: 'invalid_token' }, 401);
  }
  return null;
}

function enforceOrigin(c: Context<{ Bindings: Env }>): Response | null {
  // Server-side Origin allowlist — the line of defense for anonymous web
  // visitors who don't have JWT auth. CORS only enforces in-browser; this
  // also rejects non-browser callers (curl, server-side scripts) that
  // forgot or omitted the Origin header.
  //
  // Note: the Origin header is trustworthy from real browsers (browser sets
  // it, page JS can't override). Non-browser callers can spoof any value
  // freely — this gate only constrains browsers. Mobile/desktop apps should
  // be on the JWT path (APP_SIGNED_IDS) instead.
  const rawOrigin = c.req.header('origin');
  if (!rawOrigin) return c.json({ error: 'origin_required' }, 403);
  const origin = rawOrigin.toLowerCase();
  if (!parseOriginList(c.env.ALLOWED_ORIGINS).has(origin)) {
    return c.json({ error: 'origin_not_allowed' }, 403);
  }
  return null;
}
