// Next.js ships its own copy of React's server code (next/dist/compiled/react-server-dom-*),
// so npm audit never sees it: the lockfile only lists `next`. Next.js also patches that copy
// in place without changing its version string, so the bundled version can't tell a patched
// Next.js from a vulnerable one.
//
// What can be known for sure: a Next.js release published before a React Server Components
// advisory was disclosed can't contain the fix. That is the only thing this check reports.
// Releases newer than the advisory may or may not include the fix; they are left to the
// Next.js advisory that npm audit picks up once it's published.

import fs from 'node:fs';
import path from 'node:path';
import { makeFinding } from './finding.js';
import { NEXT_REACT_TOOL } from './pm.js';
import { satisfies, parse } from './semver.js';
import { OUT_DIR, ensureOutDir } from './config.js';

const RSC_PACKAGES = ['react-server-dom-webpack', 'react-server-dom-turbopack'];
const API = 'https://api.github.com';
const SEVERITY = { critical: 'critical', high: 'high', medium: 'medium', moderate: 'medium', low: 'low' };
const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'];

const nextDir = (dir) => path.join(dir, 'node_modules', 'next');

/** True if the project depends on next (or has it installed), so the check applies. */
export function usesNext(dir) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
    if (DEP_FIELDS.some((k) => pkg[k]?.next)) return true;
  } catch {
    /* no package.json */
  }
  return fs.existsSync(path.join(nextDir(dir), 'package.json'));
}

/** The React version Next.js bundles, read from its compiled copy of react (same build as the server code). */
export function bundledReactVersion(dir) {
  const base = path.join(nextDir(dir), 'dist', 'compiled', 'react', 'cjs');
  for (const f of ['react.production.js', 'react.production.min.js', 'react.development.js']) {
    try {
      const m = /version\s*=\s*"([^"]+)"/.exec(fs.readFileSync(path.join(base, f), 'utf8'));
      if (m && parse(m[1])) return m[1];
    } catch {
      /* try the next file */
    }
  }
  return null;
}

// ---- GitHub API, with an on-disk cache for values that never change ----

const cacheFile = (dir) => path.join(dir, OUT_DIR, 'cache', 'next-bundled-react.json');

function loadCache(dir) {
  try {
    const c = JSON.parse(fs.readFileSync(cacheFile(dir), 'utf8'));
    return { releases: c.releases ?? {}, disclosed: c.disclosed ?? {} };
  } catch {
    return { releases: {}, disclosed: {} };
  }
}

function saveCache(dir, cache) {
  try {
    ensureOutDir(dir);
    fs.mkdirSync(path.dirname(cacheFile(dir)), { recursive: true });
    fs.writeFileSync(cacheFile(dir), JSON.stringify(cache, null, 2) + '\n');
  } catch {
    /* the cache is only an optimization */
  }
}

class ApiError extends Error {}

async function github(url) {
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

/** When the Next.js release was published, from its GitHub release (cached: it never changes). */
async function releaseDate(version, cache) {
  if (cache.releases[version]) return cache.releases[version];
  const rel = await github(`${API}/repos/vercel/next.js/releases/tags/v${encodeURIComponent(version)}`);
  const date = rel?.published_at ?? rel?.created_at ?? null;
  if (date) cache.releases[version] = date;
  return date;
}

/**
 * When an advisory became public: the earlier of its date in the GitHub Advisory Database and
 * the date the project published it (React's repository advisory can be weeks earlier).
 * Null if the earlier date couldn't be checked.
 */
async function disclosedDate(adv, cache) {
  if (cache.disclosed[adv.ghsa_id]) return cache.disclosed[adv.ghsa_id];
  let date = adv.published_at;
  if (adv.repository_advisory_url) {
    const repo = await github(adv.repository_advisory_url);
    if (repo === null) return null;
    if (repo.published_at && repo.published_at < date) date = repo.published_at;
  }
  cache.disclosed[adv.ghsa_id] = date;
  return date;
}

// ---- the check ------------------------------------------------------------

const day = (iso) => iso.slice(0, 10);

/** "19.2.0-canary-0bdb9206-20250818" -> "19.2.0": a canary is a build on the way to that release. */
const releaseLine = (v) => {
  const p = parse(v);
  return `${p.major}.${p.minor}.${p.patch}`;
};

/** Advisory ranges look like ">= 19.2.0, < 19.2.9"; semver wants spaces, not commas. */
const affects = (adv, version) => (adv.vulnerabilities ?? []).some((v) => RSC_PACKAGES.includes(v.package?.name)
  && v.vulnerable_version_range && satisfies(version, v.vulnerable_version_range.replace(/,/g, ' ')));

export async function scanNextBundledReact(dir) {
  let next;
  try {
    next = JSON.parse(fs.readFileSync(path.join(nextDir(dir), 'package.json'), 'utf8')).version;
  } catch {
    return { skipped: 'next is not installed (run your install first; the check reads node_modules/next)' };
  }
  if (!fs.existsSync(path.join(nextDir(dir), 'dist', 'compiled', 'react-server-dom-webpack'))) {
    return { skipped: `next@${next} doesn't bundle React Server Components` };
  }
  const bundled = bundledReactVersion(dir);
  if (!bundled) return { skipped: `could not read the React version bundled in next@${next}` };
  const line = releaseLine(bundled);

  const cache = loadCache(dir);
  try {
    const released = await releaseDate(next, cache);
    if (!released) return { skipped: `no GitHub release found for next@${next}, so its release date is unknown` };

    const list = await github(`${API}/advisories?ecosystem=npm&type=reviewed&per_page=100&affects=${RSC_PACKAGES.join(',')}`);
    const relevant = (list ?? []).filter((a) => !a.withdrawn_at && affects(a, line));

    const findings = [];
    let unknown = 0;
    for (const adv of relevant) {
      // Database date before the release: the earlier repository date can only be earlier still.
      if (adv.published_at <= released) continue;
      const disclosed = await disclosedDate(adv, cache);
      if (!disclosed) { unknown++; continue; }
      if (disclosed <= released) continue;
      findings.push(makeFinding({
        tool: NEXT_REACT_TOOL,
        ruleId: adv.ghsa_id,
        severity: SEVERITY[adv.severity] ?? 'medium',
        title: `next (bundled React): ${adv.summary}`,
        package: 'next',
        file: 'package.json',
        description: `next@${next} was released on ${day(released)} and bundles its own React (${bundled}), `
          + `which npm audit can't see. This React Server Components advisory${adv.cve_id ? ` (${adv.cve_id})` : ''} `
          + `was disclosed on ${day(disclosed)}, after that release, so this Next.js version can't contain the fix. `
          + 'It matters if the app uses the App Router (React Server Components).',
        cwe: (adv.cwes ?? []).map((x) => x.cwe_id),
        url: adv.html_url ?? null,
        fix: {
          type: 'manual',
          detail: `Upgrade next to a release from after ${day(disclosed)} that includes the fix (see the Next.js releases `
            + 'or a Next.js advisory for this issue). Upgrading react or react-dom alone does not help: '
            + 'the App Router uses the copy bundled in next.',
        },
      }));
    }
    const note = [
      `next@${next} bundles React ${bundled}`,
      unknown ? `${unknown} advisory date(s) could not be checked` : null,
    ].filter(Boolean).join('; ');
    return { findings, note };
  } catch (e) {
    if (e instanceof ApiError) return { error: e.message };
    throw e;
  } finally {
    saveCache(dir, cache);
  }
}
