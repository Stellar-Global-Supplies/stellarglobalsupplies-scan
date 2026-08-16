import { SecretsStore, AppSecrets } from '../types';

/**
 * Fetch all secrets from CF Secrets Store in parallel.
 *
 * Required keys in the store:
 *   SUPABASE_JWT_SECRET  — Supabase dashboard > Settings > API > JWT Secret
 *   SNYK_API_TOKEN       — Snyk > Account Settings > Auth Token
 *   SNYK_ORG_ID          — Snyk > Account Settings > Organisation ID
 *   GITHUB_TOKEN         — GitHub PAT (repo + pull_requests scopes)
 *   SONARCLOUD_TOKEN     — SonarCloud > My Account > Security > Generate Token
 *   SONARCLOUD_ORG       — SonarCloud organisation key (usually your GitHub org slug)
 */
export async function resolveSecrets(store: SecretsStore): Promise<AppSecrets> {
  const [
    supabaseJwtSecret,
    snykApiToken,
    snykOrgId,
    githubToken,
    sonarcloudToken,
    sonarcloudOrg,
  ] = await Promise.all([
    store.get('SUPABASE_JWT_SECRET'),
    store.get('SNYK_API_TOKEN'),
    store.get('SNYK_ORG_ID'),
    store.get('GITHUB_TOKEN'),
    store.get('SONARCLOUD_TOKEN'),
    store.get('SONARCLOUD_ORG'),
  ]);

  const missing: string[] = [];
  if (!supabaseJwtSecret) missing.push('SUPABASE_JWT_SECRET');
  if (!snykApiToken)       missing.push('SNYK_API_TOKEN');
  if (!snykOrgId)          missing.push('SNYK_ORG_ID');
  if (!githubToken)        missing.push('GITHUB_TOKEN');
  if (!sonarcloudToken)    missing.push('SONARCLOUD_TOKEN');
  if (!sonarcloudOrg)      missing.push('SONARCLOUD_ORG');

  if (missing.length > 0) {
    throw new Error(
      `Missing secrets in CF Secrets Store: ${missing.join(', ')}. ` +
      'Add them at: Workers & Pages → Settings → Secrets Store.'
    );
  }

  return {
    supabaseJwtSecret: supabaseJwtSecret!,
    snykApiToken:      snykApiToken!,
    snykOrgId:         snykOrgId!,
    githubToken:       githubToken!,
    sonarcloudToken:   sonarcloudToken!,
    sonarcloudOrg:     sonarcloudOrg!,
  };
}
