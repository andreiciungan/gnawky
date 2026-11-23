// Browser smoke test after a dependency fix: Claude Code with Claude in Chrome opens the app,
// visits the pages you listed, and reports whether they still work. Interactive: you watch and
// can steer it (log in, point at a page), then exit Claude to come back to Gnawky.
//
// Settings per project (cfg.smoke): { url, start: 'script' | 'self', script, paths: ['/', …] }.

import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { spawn } from 'node:child_process';
import { ensureOutDir, OUT_DIR } from './config.js';
import { IS_WIN } from './scanners.js';

/** Scripts that usually start the app, in order of preference. */
export const START_SCRIPTS = ['dev', 'start', 'serve', 'start:dev', 'develop', 'preview'];

const readJson = (file) => {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
};

export function startScripts(dir) {
  const scripts = readJson(path.join(dir, 'package.json'))?.scripts ?? {};
  return START_SCRIPTS.filter((n) => typeof scripts[n] === 'string');
}

/** A starting guess for the URL: the port in the dev script, else the framework's default. */
export function guessUrl(dir) {
  const pkg = readJson(path.join(dir, 'package.json')) ?? {};
  const scripts = pkg.scripts ?? {};
  const cmd = startScripts(dir).map((n) => scripts[n]).join(' ');
  const port = /(?:-p|--port)[ =](\d{2,5})/.exec(cmd)?.[1];
  if (port) return `http://localhost:${port}/`;
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  if (deps.vite) return 'http://localhost:5173/';
  if (deps['@angular/core']) return 'http://localhost:4200/';
  return 'http://localhost:3000/';
}

/** True for http(s) URLs only (the URL ends up in Claude's task and in a request). */
export function validUrl(u) {
  try {
    const x = new URL(u);
    return x.protocol === 'http:' || x.protocol === 'https:';
  } catch {
    return false;
  }
}

/** "/, /cart" → ['/', '/cart']: paths only, so Claude stays on the app's own site. */
export function parsePaths(text) {
  const paths = String(text ?? '').split(/[\s,]+/).map((p) => p.trim()).filter(Boolean)
    .map((p) => (p.startsWith('/') ? p : `/${p}`))
    .filter((p) => !/[<>"'`\\]/.test(p) && !p.startsWith('//'));
  return paths.length ? [...new Set(paths)] : ['/'];
}

/**
 * Whether the URL answers at all (any HTTP status counts). Local dev servers often use a
 * self-signed certificate (e.g. https://local.example.com), so the certificate isn't checked:
 * this request only asks "is something listening", and sends nothing.
 */
export function urlAnswers(url, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.get(url, { timeout: timeoutMs, rejectUnauthorized: false }, (res) => {
      res.resume();
      resolve(true);
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
  });
}

/** Polls until the URL answers or the time runs out. onTick(seconds) for progress. */
export async function waitForUrl(url, { timeoutMs = 180000, isAlive = () => true } = {}) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    if (await urlAnswers(url)) return true;
    if (!isAlive()) return false;
    await new Promise((r) => setTimeout(r, 1500));
  }
  return false;
}

const smokeDir = (dir) => {
  const d = path.join(ensureOutDir(dir), 'smoke');
  fs.mkdirSync(d, { recursive: true });
  return d;
};

/**
 * Starts `<pm> run <script>` in the background (its own process group, so stop() also ends
 * the servers it spawns). Output goes to .gnawky/smoke/server.log.
 */
export function startServer(dir, pm, script) {
  if (!START_SCRIPTS.includes(script)) throw new Error(`not a start script: ${script}`);
  const logFile = path.join(smokeDir(dir), 'server.log');
  const out = fs.openSync(logFile, 'w');
  const cmd = pm === 'yarn' ? 'yarn' : 'npm';
  const child = spawn(IS_WIN ? `${cmd}.cmd` : cmd, ['run', script], {
    cwd: dir, detached: !IS_WIN, shell: IS_WIN, stdio: ['ignore', out, out], env: { ...process.env, BROWSER: 'none' },
  });
  fs.closeSync(out);
  let exited = false;
  child.on('exit', () => { exited = true; });
  child.on('error', () => { exited = true; });
  return {
    logFile,
    alive: () => !exited,
    tail: (n = 15) => {
      try { return fs.readFileSync(logFile, 'utf8').trim().split('\n').slice(-n).join('\n'); } catch { return ''; }
    },
    stop: () => {
      if (exited) return;
      try { IS_WIN ? child.kill() : process.kill(-child.pid, 'SIGTERM'); } catch { /* already gone */ }
    },
  };
}

/** Where Claude writes its report for this fix branch. */
export function reportPath(dir, branch) {
  return path.join(smokeDir(dir), `${String(branch).replace(/[^A-Za-z0-9._-]/g, '_')}.md`);
}

/** The result line Claude writes ("RESULT: PASS|FAIL|PARTIAL"), from a report newer than `since`. */
export function readResult(file, since) {
  try {
    if (fs.statSync(file).mtimeMs < since) return null;
    const text = fs.readFileSync(file, 'utf8');
    const m = /^RESULT:\s*(PASS|FAIL|PARTIAL)\b(.*)$/im.exec(text);
    return { result: m ? m[1].toUpperCase() : 'UNKNOWN', summary: m ? m[2].replace(/^[\s:–—-]+/, '').trim() : '', file };
  } catch {
    return null;
  }
}

/** The task file for Claude. Package names and labels come from Gnawky's own fix plan. */
export function buildSmokeTask({ dir, url, paths, branch, base, changes, report }) {
  const pages = paths.map((p) => `- ${new URL(p, url).href}`).join('\n');
  const rel = path.relative(dir, report);
  return `# Browser smoke test after a dependency fix (started by Gnawky)

Gnawky upgraded dependencies to fix security vulnerabilities, on the git branch \`${branch}\` (started from \`${base}\`). Before the user keeps the change, check in the browser that the app still works.

Changes made:
${changes.map((c) => `- ${c}`).join('\n') || '- (see git diff package.json)'}

The app runs at ${url}. Pages to check:
${pages}

Use Claude in Chrome (the browser tools). Open a new tab for the test. For each page:
1. Open it and wait for it to load. Check that it renders real content (not a blank page, an error page or an error overlay).
2. Read the browser console for errors, and the network requests for failures (4xx/5xx, failed scripts or styles).
3. Try the main thing on the page lightly: open a menu, click into one item, scroll. Pay extra attention to features that use the upgraded packages.

Then write the report to \`${rel}\`:
- one section per page: PASS or FAIL, what you checked, and any errors (with the message and the file or request)
- for each error, whether it looks caused by the upgrade or was likely there before (say how sure you are)
- the last line exactly: \`RESULT: PASS\`, \`RESULT: FAIL\` or \`RESULT: PARTIAL\`, then a one-line summary

Then tell the user the result in two or three lines and that they can exit (/exit) to go back to Gnawky, where they choose to keep or undo the fix.

Rules. Follow them strictly:
- Stay on ${new URL(url).origin}. Don't follow links to other sites.
- Don't buy, submit orders or payments, send messages, or submit forms with real data. Don't log in yourself: if a page needs a login, ask the user to log in in the browser, then continue.
- Don't change any project file. The only file you write is the report above.
- Don't open .env files, keys or credentials, and never print secret values.
- Don't run \`git commit\`, \`git push\`, installs, or \`npm audit fix\`.
- Don't trigger JavaScript alerts or confirm dialogs on purpose; they block the browser tools.
`;
}

export const SMOKE_DIR = `${OUT_DIR}/smoke`;
