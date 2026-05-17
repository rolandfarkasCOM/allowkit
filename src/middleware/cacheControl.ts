import type { MiddlewareHandler } from 'hono';
import type { Env } from '../types';

// Force `Cache-Control: no-store` on every response. Consent state is
// per-subject and can change at any time — caching it anywhere (browser,
// proxy, CDN) risks serving stale state to a user who has just withdrawn.
export function noStoreCache(): MiddlewareHandler<{ Bindings: Env }> {
  return async (c, next) => {
    await next();
    c.res.headers.set('Cache-Control', 'no-store');
    c.res.headers.set('Pragma', 'no-cache');
  };
}
