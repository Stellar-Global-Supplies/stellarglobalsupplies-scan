import { Hono } from 'hono';
import { cors }  from 'hono/cors';
import { Env, QueueMessage } from './types';
import { handleQueue }  from './queue/consumer';
import { handleCron }   from './cron/scheduler';
import repos   from './routes/repos';
import scans   from './routes/scans';
import vulns   from './routes/vulns';
import quality from './routes/quality';

const app = new Hono<{ Bindings: Env }>();

// ── CORS ───────────────────────────────────────────────────────────────────────
app.use('/api/*', cors({
  origin: (origin) => {
    const allowed = [
      'https://scan.stellarglobalsupplies.com',
      'https://scan-worker.workwithprasadbhavsar.workers.dev',
      'http://localhost:5173',
    ];
    return allowed.includes(origin) ? origin : null;
  },
  allowHeaders: ['Authorization', 'Content-Type'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  maxAge: 600,
}));

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