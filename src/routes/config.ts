import { Hono } from 'hono';
import type { Env } from '../types';
import { isAppIdAllowed } from '../middleware/validateAppId';

const CATEGORIES = ['necessary', 'functional', 'analytics', 'marketing'] as const;
const VERSION = 1;

export const configRoute = new Hono<{ Bindings: Env }>();

configRoute.get('/config/:appId', (c) => {
  const appId = c.req.param('appId');
  if (!isAppIdAllowed(appId, c.env)) {
    return c.json({ error: 'unknown_app' }, 404);
  }
  return c.json({
    appId,
    categories: CATEGORIES,
    version: VERSION,
  });
});
