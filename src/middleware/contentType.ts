import type { MiddlewareHandler } from 'hono';
import type { Env } from '../types';

// 415 if a POST arrives without `Content-Type: application/json`.
// Defends against form-encoded smuggling and CSRF tricks that rely on
// browsers sending non-JSON content types via simple form submissions.
export function requireJsonContentType(): MiddlewareHandler<{ Bindings: Env }> {
  return async (c, next) => {
    if (c.req.method === 'POST') {
      const ct = (c.req.header('content-type') ?? '').toLowerCase();
      if (!ct.startsWith('application/json')) {
        return c.json(
          { error: 'unsupported_media_type', message: 'Content-Type must be application/json' },
          415,
        );
      }
    }
    return next();
  };
}
