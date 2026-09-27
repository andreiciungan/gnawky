import fs from 'node:fs';
import path from 'node:path';
import { SEVERITY_ORDER } from './finding.js';

export const OUT_DIR = '.gnawky';

export const DEFAULT_CONFIG = {
  minSeverity: 'low',
  offline: false,
  scanners: { 'npm-audit': true, gitleaks: true, semgrep: true },
  semgrepConfigs: ['p/javascript', 'p/nodejsscan'],
};

const file = (dir) => path.join(dir, OUT_DIR, 'config.json');

export function ensureOutDir(dir) {
  const out = path.join(dir, OUT_DIR);
  fs.mkdirSync(out, { recursive: true });
  // The folder ignores itself so reports and settings are never committed by accident.
  fs.writeFileSync(path.join(out, '.gitignore'), '*\n');
  return out;
}

/** False until setup has run (or was skipped) in this project. */
export const configExists = (dir) => fs.existsSync(file(dir));

export function loadConfig(dir) {
  let user = {};
  try {
    user = JSON.parse(fs.readFileSync(file(dir), 'utf8'));
  } catch {
    /* no config yet, or unreadable: use defaults */
  }
  const cfg = {
    ...structuredClone(DEFAULT_CONFIG),
    ...user,
    scanners: { ...DEFAULT_CONFIG.scanners, ...(user.scanners ?? {}) },
  };
  if (!SEVERITY_ORDER.includes(cfg.minSeverity)) cfg.minSeverity = DEFAULT_CONFIG.minSeverity;
  if (!Array.isArray(cfg.semgrepConfigs) || !cfg.semgrepConfigs.length) cfg.semgrepConfigs = [...DEFAULT_CONFIG.semgrepConfigs];
  return cfg;
}

export function saveConfig(dir, cfg) {
  ensureOutDir(dir);
  fs.writeFileSync(file(dir), JSON.stringify(cfg, null, 2) + '\n');
}
