import { Hono } from 'hono';
import type { Env } from './types';
import { strictCors } from './middleware/cors';
import { requireJsonContentType } from './middleware/contentType';
import { noStoreCache } from './middleware/cacheControl';
import { configRoute } from './routes/config';
import { consentRoute } from './routes/consent';
import { withdrawRoute } from './routes/withdraw';

// Rate limiting is configured at the Cloudflare edge (WAF rate-limit rules
// in the zone dashboard) rather than in-app. Edge enforcement runs before
// requests reach the Worker, costs nothing on free tier, and avoids the
// KV-write quota that an app-level limiter would burn through at scale.
const app = new Hono<{ Bindings: Env }>();

app.use('*', noStoreCache());
app.use('*', strictCors());
app.use('*', requireJsonContentType());

app.get('/', (c) =>
  c.json({
    name: 'allowkit',
    docs: 'https://github.com/rolandfarkasCOM/allowkit',
  }),
);

app.route('/', configRoute);
app.route('/', consentRoute);
app.route('/', withdrawRoute);

app.notFound((c) => c.json({ error: 'not_found' }, 404));

app.onError((err, c) => {
  console.error('allowkit_error', err);
  return c.json({ error: 'internal_error' }, 500);
});

export default app;
