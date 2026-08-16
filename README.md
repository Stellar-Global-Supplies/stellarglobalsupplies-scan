# 🛡️ Stellar Global Supplies — Security Scanner

Vulnerability dashboard for all GitHub repositories, powered by Snyk API.
Deployed on Cloudflare Pages + Workers with D1 database and Supabase Auth.

**Live URL:** https://scan.stellarglobalsupplies.com

---

## Architecture

```
scan.stellarglobalsupplies.com      → Cloudflare Pages (React frontend)
api.scan.stellarglobalsupplies.com  → Cloudflare Worker (REST API + Cron + Queue)
                                      ├── D1 Database     (repos, scans, vulns)
                                      ├── CF Queue        (async scan jobs)
                                      ├── CF Secrets Store (all credentials)
                                      └── Cron 06:00 + 18:00 UTC (auto-scan)
```

---

## Prerequisites

- Node.js 20+
- Wrangler CLI: `npm install -g wrangler`
- Cloudflare account (Workers Paid or Free tier with D1/Queues)
- Supabase project (free tier is fine — Auth only)
- Snyk account (Team plan or above — needed for Fix PR API)
- GitHub account

---

## Step 1 — Cloudflare Infrastructure Setup

```bash
# Login to Cloudflare
wrangler login

# Create D1 database
wrangler d1 create scan-db
# → Copy the database_id into worker/wrangler.toml

# Create Queues
wrangler queues create scan-queue
wrangler queues create scan-queue-dlq

# Create Secrets Store
# Go to: Cloudflare Dashboard → Workers & Pages → Settings → Secrets Store
# Create a store, copy the Store ID into worker/wrangler.toml [[secrets_store_bindings]] store_id
```

---

## Step 2 — Add Secrets to CF Secrets Store

In the Cloudflare Dashboard:
**Workers & Pages → Settings → Secrets Store → your store → Add secret**

| Key                   | Where to find it                                         |
|-----------------------|----------------------------------------------------------|
| `SUPABASE_JWT_SECRET` | Supabase Dashboard → Settings → API → JWT Secret         |
| `SNYK_API_TOKEN`      | Snyk → Account Settings → General → Auth Token           |
| `SNYK_ORG_ID`         | Snyk → Account Settings → General → Organisation ID      |
| `GITHUB_TOKEN`        | GitHub → Settings → Developer Settings → PAT (classic)  |

GitHub PAT needs scopes: `repo`, `pull_requests`.

---

## Step 3 — Supabase Auth Setup

1. Go to your Supabase project → Authentication → Providers → GitHub
2. Enable GitHub OAuth and paste in your GitHub OAuth app credentials
3. Set redirect URL to: `https://scan.stellarglobalsupplies.com/auth/callback`
4. Copy your **Project URL** and **Anon Key** for the frontend .env

---

## Step 4 — Worker Setup & Deploy

```bash
cd worker
npm install

# Run D1 schema migration only — no manual repo seeding needed
npm run db:migrate:remote

# Deploy worker
npm run deploy

# Verify deployment
curl https://api.scan.stellarglobalsupplies.com/health
```

---

## Step 5 — Sync Repos from Snyk (automatic)

Since your repos are already in Snyk, **no manual seeding is required**.

On first login the dashboard automatically calls `POST /api/repos/sync`, which:
1. Calls `GET /orgs/{orgId}/projects` on Snyk API
2. Filters to GitHub-backed projects only
3. Upserts all repos + their Snyk project IDs into D1 in one batch

You can also trigger it manually any time from the **"🔄 Sync from Snyk"** button in the dashboard header — useful when you add a new repo to Snyk and want it to appear without redeploying.

To trigger it via curl:
```bash
curl -X POST https://api.scan.stellarglobalsupplies.com/api/repos/sync \
  -H "Authorization: Bearer YOUR_SUPABASE_JWT"
```

---

## Step 6 — Frontend Setup & Deploy

```bash
cd frontend
npm install

# Copy and fill in your env
cp .env.example .env
# Edit .env with your Supabase URL, Anon Key, and Worker API URL

# Build
npm run build

# Deploy to CF Pages
wrangler pages deploy dist --project-name scan-dashboard
```

---

## Step 7 — Custom Domain

**scan.stellarglobalsupplies.com** (Frontend):
1. Cloudflare Dashboard → Pages → scan-dashboard → Custom domains → Add
2. Enter: `scan.stellarglobalsupplies.com`
3. CF auto-adds the DNS CNAME

**api.scan.stellarglobalsupplies.com** (Worker API):
1. Cloudflare Dashboard → Workers & Pages → scan-worker → Settings → Domains & Routes
2. Add custom domain: `api.scan.stellarglobalsupplies.com`

---

## Cron Schedule

The worker auto-scans all repos twice daily:

| Time     | UTC  | IST (India)      |
|----------|------|------------------|
| Morning  | 06:00 | 11:30 AM        |
| Evening  | 18:00 | 11:30 PM        |

Cron config in `worker/wrangler.toml`:
```toml
[triggers]
crons = ["0 6,18 * * *"]
```

---

## Project Structure

```
scan-stellarglobalsupplies/
├── migrations/
│   └── 0001_init.sql          D1 schema (repos auto-populated from Snyk on first login)
├── worker/                    Cloudflare Worker
│   ├── wrangler.toml
│   └── src/
│       ├── index.ts           Entry — fetch / queue / scheduled handlers
│       ├── types.ts           TypeScript interfaces
│       ├── lib/
│       │   ├── secrets.ts     CF Secrets Store resolver
│       │   ├── auth.ts        Supabase JWT verification
│       │   ├── snyk.ts        Snyk REST API client
│       │   └── db.ts          D1 query helpers
│       ├── routes/
│       │   ├── repos.ts       GET /api/repos, POST /api/repos/:id/import
│       │   ├── scans.ts       POST /api/scans/repo/:id, POST /api/scans/all
│       │   └── vulns.ts       GET /api/vulns, POST /api/vulns/fix
│       ├── queue/
│       │   └── consumer.ts    Processes scan jobs from CF Queue
│       └── cron/
│           └── scheduler.ts   Queues all repos on cron trigger
└── frontend/                  React + Vite — CF Pages
    ├── vite.config.ts
    ├── .env.example
    └── src/
        ├── main.tsx           Entry + global styles (SGS brand tokens)
        ├── App.tsx            Router + auth guard
        ├── lib/
        │   ├── supabase.ts    Supabase client
        │   └── api.ts         Worker API client
        ├── pages/
        │   ├── Login.tsx      GitHub OAuth login
        │   ├── Dashboard.tsx  Main dashboard
        │   └── AuthCallback.tsx
        └── components/
            ├── RepoCard.tsx   Per-repo scan card with Scan Now button
            └── VulnTable.tsx  Vulnerability table with Fix PR button
```

---

## API Reference

| Method | Endpoint                        | Description                              |
|--------|---------------------------------|------------------------------------------|
| GET    | `/health`                       | Health check (no auth)                   |
| GET    | `/api/repos`                    | List all repos with latest scan status   |
| POST   | `/api/repos/sync`               | Pull all Snyk projects → upsert into D1  |
| POST   | `/api/scans/repo/:id`           | Scan a single repo now                   |
| POST   | `/api/scans/all`                | Scan all 30 repos now                    |
| GET    | `/api/scans/status/:scanRunId`  | Poll scan run status                     |
| GET    | `/api/vulns`                    | All vulnerabilities (filterable)         |
| GET    | `/api/vulns/summary`            | Count per severity (critical/high/etc.)  |
| POST   | `/api/vulns/fix`                | Create Snyk fix PR on GitHub             |

All `/api/*` endpoints require `Authorization: Bearer {supabase_jwt}`.

---

## D1 Schema

```
repos           — id, name, github_url, snyk_project_id, last_scanned_at
scan_runs       — id, repo_id, triggered_by, trigger_type, status, vuln_count
vulnerabilities — id, scan_run_id, repo_id, cve, severity, package, fixable, fix_pr_url
```

---

## Snyk Plan Requirements

| Feature        | Free | Team | Enterprise |
|----------------|------|------|------------|
| Issue scanning | ✓    | ✓    | ✓          |
| Fix PRs        | ✗    | ✓    | ✓          |
| API access     | Limited | Full | Full    |

Fix PR button (`POST /api/vulns/fix`) requires **Team plan or above**.

---

*Stellar Global Supplies — Internal Security Tool*
*Built on Cloudflare Workers + Pages + D1 + Supabase Auth + Snyk API*
