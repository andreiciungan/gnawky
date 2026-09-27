import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function rank(severity) {
  const i = SEVERITY_ORDER.indexOf(severity);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

/**
 * Normalized finding shape shared by every scanner:
 * { fingerprint, tool, ruleId, severity, title, file, line, package,
 *   description, cwe[], url, fix: { type, detail, ... } }
 */
export function makeFinding(f) {
  const key = [f.tool, f.ruleId, f.file ?? '', f.package ?? '', f.line ?? ''].join('|');
  const fingerprint = crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
  return { cwe: [], line: null, package: null, url: null, ...f, fingerprint };
}

// ---- Ignore baseline (.gnawky-ignore.json, meant to be committed) ----

const IGNORE_FILE = '.gnawky-ignore.json';

export function loadIgnores(dir) {
  const p = path.join(dir, IGNORE_FILE);
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8')).ignored ?? [];
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw new Error(`Invalid ${IGNORE_FILE}: ${e.message}`);
  }
}

export function addIgnores(dir, entries) {
  const p = path.join(dir, IGNORE_FILE);
  const ignored = loadIgnores(dir);
  const known = new Set(ignored.map((i) => i.fingerprint));
  for (const { finding, reason } of entries) {
    if (known.has(finding.fingerprint)) continue;
    ignored.push({
      fingerprint: finding.fingerprint,
      title: finding.title,
      reason,
      date: new Date().toISOString().slice(0, 10),
    });
  }
  fs.writeFileSync(p, JSON.stringify({ ignored }, null, 2) + '\n');
  return p;
}

export function removeIgnore(dir, fingerprint) {
  const ignored = loadIgnores(dir).filter((i) => i.fingerprint !== fingerprint);
  fs.writeFileSync(path.join(dir, IGNORE_FILE), JSON.stringify({ ignored }, null, 2) + '\n');
}
