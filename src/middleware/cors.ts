import { cors } from 'hono/cors';
import type { MiddlewareHandler } from 'hono';
import type { Env } from '../types';
import { parseOriginList } from '../lib/security';

// Only headers the API actually reads are advertised. `x-app-id` was retired
// with the in-app rate-limit removal — keeping it here would be doc-code
// drift and might mislead integrators into thinking it's still consulted.
const ALLOWED_HEADERS = [
  'authorization',
  'content-type',
  'accept',
  'idempotency-key',
  'x-subject-id',
];
const ALLOWED_METHODS = ['GET', 'POST', 'OPTIONS'];

// CORS is browser-side defense in depth. The actual server-side Origin gate
// for unsigned apps lives in src/lib/readBody.ts (returns 403 if Origin is
// missing or not in the allowlist). Non-browser callers ignore CORS headers,
// which is why the readBody gate exists.
export function strictCors(): MiddlewareHandler<{ Bindings: Env }> {
  return async (c, next) => {
    const allowlist = parseOriginList(c.env.ALLOWED_ORIGINS);
    const handler = cors({
      // RFC 6454 §6.1: origin compare is ASCII case-insensitive. Allowlist is
      // already lowercased by parseOriginList; lowercase the inbound origin
      // for comparison but echo back the browser's exact form.
      origin: (origin) => (origin && allowlist.has(origin.toLowerCase()) ? origin : null),
      allowMethods: ALLOWED_METHODS,
      allowHeaders: ALLOWED_HEADERS,
      maxAge: 600,
      credentials: false,
    });
    return handler(c, next);
  };
}
