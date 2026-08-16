import { Hono } from 'hono';
import { Env, JWTPayload } from '../types';
import { getLatestQualityAll, getQualityHistory, syncSonarProjectKeys } from '../lib/db';
import { fetchSonarProjects } from '../lib/sonar';

const quality = new Hono<{ Bindings: Env; Variables: { user: JWTPayload } }>();

// GET /api/quality — latest quality snapshot for all repos
quality.get('/', async (c) => {
  const data = await getLatestQualityAll(c.env.DB);
  return c.json({ quality: data });
});

// GET /api/quality/:repoId/history
quality.get('/:repoId/history', async (c) => {
  const history = await getQualityHistory(c.env.DB, c.req.param('repoId'));
  return c.json({ history });
});

// POST /api/quality/sync — match SonarCloud projects → D1 repos
quality.post('/sync', async (c) => {
  try {
    // env.SONARCLOUD_ORG and env.SONARCLOUD_TOKEN are direct strings
    const sonarProjects = await fetchSonarProjects(
      c.env.SONARCLOUD_ORG,
      c.env.SONARCLOUD_TOKEN
    );

    if (sonarProjects.length === 0) {
      return c.json({
        message: 'No projects found in SonarCloud org. Import repos at sonarcloud.io first.',
        synced:  0,
      });
    }

    const synced = await syncSonarProjectKeys(c.env.DB, sonarProjects);
    return c.json({
      found:   sonarProjects.length,
      synced,
      message: `Found ${sonarProjects.length} SonarCloud projects, matched ${synced} repos in D1.`,
    });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Sync failed' }, 500);
  }
});

export default quality;