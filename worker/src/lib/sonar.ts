// SonarCloud API client — free for public repos, no usage limits

const SONAR_BASE = 'https://sonarcloud.io/api';

// Metrics to pull per project in a single API call
const METRIC_KEYS = [
  'reliability_rating',
  'maintainability_rating',
  'security_rating',
  'code_smells',
  'duplicated_lines_density',
  'complexity',
  'cognitive_complexity',
  'coverage',
  'ncloc',
  'security_hotspots',
  'sqale_index',         // technical debt in minutes
].join(',');

function sonarHeaders(token: string): HeadersInit {
  // SonarCloud uses HTTP Basic Auth: token as username, empty password
  const encoded = btoa(`${token}:`);
  return { 'Authorization': `Basic ${encoded}` };
}

// Converts SonarCloud numeric rating (1.0–5.0) to letter grade
function toRating(value: string | undefined): string | null {
  const map: Record<string, string> = {
    '1.0': 'A', '2.0': 'B', '3.0': 'C', '4.0': 'D', '5.0': 'E',
  };
  return value ? (map[value] ?? null) : null;
}

export interface SonarMetrics {
  reliabilityRating:     string | null;   // A–E
  maintainabilityRating: string | null;   // A–E
  securityRating:        string | null;   // A–E
  codeSmells:            number | null;
  duplicatedLinesPct:    number | null;
  complexity:            number | null;
  cognitiveComplexity:   number | null;
  coveragePct:           number | null;
  linesOfCode:           number | null;
  securityHotspots:      number | null;
  technicalDebtMins:     number | null;
}

export interface SonarProject {
  projectKey: string;
  name:       string;
  githubUrl:  string;
}

// Fetch all projects already linked in your SonarCloud org
// Matches repos by name so we can store sonar_project_key in D1
export async function fetchSonarProjects(
  org: string,
  token: string
): Promise<SonarProject[]> {
  const projects: SonarProject[] = [];
  let page = 1;

  while (true) {
    const url = `${SONAR_BASE}/projects/search?organization=${org}&ps=100&p=${page}`;
    const res = await fetch(url, { headers: sonarHeaders(token) });

    if (!res.ok) throw new Error(`SonarCloud projects fetch failed: ${res.status} ${await res.text()}`);

    const body = await res.json<{
      components: Array<{ key: string; name: string; qualifier: string }>;
      paging: { total: number; pageIndex: number; pageSize: number };
    }>();

    for (const c of body.components) {
      // SonarCloud project key is typically "org_repo-name"
      // GitHub URL reconstructed from org + repo name portion
      const repoPart = c.key.replace(`${org}_`, '');
      projects.push({
        projectKey: c.key,
        name:       c.name,
        githubUrl:  `https://github.com/${org}/${repoPart}`,
      });
    }

    const { total, pageIndex, pageSize } = body.paging;
    if (pageIndex * pageSize >= total) break;
    page++;
  }

  return projects;
}

// Fetch quality metrics for one SonarCloud project key
export async function fetchProjectMetrics(
  projectKey: string,
  token: string
): Promise<SonarMetrics> {
  const url = `${SONAR_BASE}/measures/component?component=${projectKey}&metricKeys=${METRIC_KEYS}`;
  const res  = await fetch(url, { headers: sonarHeaders(token) });

  if (!res.ok) throw new Error(`SonarCloud metrics failed for ${projectKey}: ${res.status} ${await res.text()}`);

  const body = await res.json<{
    component: {
      measures: Array<{ metric: string; value: string }>;
    };
  }>();

  // Build a quick lookup map
  const m: Record<string, string> = {};
  for (const measure of body.component.measures) {
    m[measure.metric] = measure.value;
  }

  return {
    reliabilityRating:     toRating(m['reliability_rating']),
    maintainabilityRating: toRating(m['maintainability_rating']),
    securityRating:        toRating(m['security_rating']),
    codeSmells:            m['code_smells']               ? parseInt(m['code_smells'])               : null,
    duplicatedLinesPct:    m['duplicated_lines_density']  ? parseFloat(m['duplicated_lines_density']) : null,
    complexity:            m['complexity']                ? parseInt(m['complexity'])                : null,
    cognitiveComplexity:   m['cognitive_complexity']      ? parseInt(m['cognitive_complexity'])      : null,
    coveragePct:           m['coverage']                  ? parseFloat(m['coverage'])                : null,
    linesOfCode:           m['ncloc']                     ? parseInt(m['ncloc'])                     : null,
    securityHotspots:      m['security_hotspots']         ? parseInt(m['security_hotspots'])         : null,
    technicalDebtMins:     m['sqale_index']               ? parseInt(m['sqale_index'])               : null,
  };
}
