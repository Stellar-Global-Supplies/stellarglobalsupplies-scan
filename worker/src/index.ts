import { Hono } from 'hono';
import { cors }  from 'hono/cors';
import { Env, JWTPayload, QueueMessage } from './types';
import { authenticate } from './lib/auth';
import { handleQueue }  from './queue/consumer';
import { handleCron }   from './cron/scheduler';
import repos   from './routes/repos';
import scans   from './routes/scans';
import vulns   from './routes/vulns';
import quality from './routes/quality';

// Secrets are direct env.* strings — no resolveSecrets() needed
type HonoVars = { user: JWTPayload };
const app = new Hono<{ Bindings: Env; Variables: HonoVars }>();

// ── CORS ───────────────────────────────────────────────────────────────────────
app.use('/api/*', cors({
  origin: (origin) => {
    const allowed = [
      'https://scan.stellarglobalsupplies.com',
      'http://localhost:5173',
    ];
    return allowed.includes(origin) ? origin : null;
  },
  allowHeaders: ['Authorization', 'Content-Type'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  maxAge: 600,
}));

// ── Auth middleware — SUPABASE_JWT_SECRET is env.* directly ───────────────────
app.use('/api/*', async (c, next) => {
  const user = await authenticate(c.req.raw, c.env.SUPABASE_JWT_SECRET);
  if (!user) return c.json({ error: 'Unauthorized' }, 401);
  c.set('user', user);
  return next();
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.route('/api/repos',   repos);
app.route('/api/scans',   scans);
app.route('/api/vulns',   vulns);
app.route('/api/quality', quality);

app.get('/health', (c) => c.json({
  ok:      true,
  service: 'Stellar Global Supplies Security Scanner',
  ts:      Date.now(),
}));

// ── Exports ───────────────────────────────────────────────────────────────────
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return app.fetch(request, env, ctx);
  },

  async queue(batch: MessageBatch<QueueMessage>, env: Env): Promise<void> {
    return handleQueue(batch, env);
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(handleCron(env, new Date(event.scheduledTime)));
  },
};