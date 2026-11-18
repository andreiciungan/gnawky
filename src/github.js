// GitHub REST API: 60 requests an hour without a token, more with GITHUB_TOKEN / GH_TOKEN.

export const API = 'https://api.github.com';

export class ApiError extends Error {}

/** GET a GitHub API URL. Null for 404; throws ApiError for anything else that isn't a success. */
export async function github(url) {
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'gnawky', 'X-GitHub-Api-Version': '2022-11-28' };
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(url, { headers, signal: AbortSignal.timeout(20000) });
  } catch (e) {
    throw new ApiError(`could not reach the GitHub API (${e.cause?.code ?? e.name})`);
  }
  if (res.status === 404) return null;
  if ((res.status === 403 || res.status === 429) && res.headers.get('x-ratelimit-remaining') === '0') {
    throw new ApiError(token
      ? 'GitHub API rate limit reached, try again later'
      : 'GitHub API rate limit reached (60 requests/hour without a token); try later, or set GITHUB_TOKEN');
  }
  if (!res.ok) throw new ApiError(`GitHub API returned ${res.status} for ${url.replace(API, '')}`);
  return res.json();
}
