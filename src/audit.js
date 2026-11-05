import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { OUT_DIR, ensureOutDir } from './config.js';
import { makeFinding } from './finding.js';

// Full security audit with the bundled security-audit skill (Cloudflare, MIT; see
// skills/security-audit/VENDORED.md). Gnawky only starts the session and imports
// the results: the skill itself decides how to audit and writes its own reports,
// outside the project, to ~/security-audit-skill/<project>/run-<N>.

export const AUDIT_TOOL = 'claude-audit';
export const PLUGIN_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const SKILL_NAME = 'gnawky:security-audit';

const SEVERITY = { informational: 'info', low: 'low', medium: 'medium', high: 'high', critical: 'critical' };
const recordFile = (dir) => path.join(dir, OUT_DIR, 'audit.json');

function loadRecord(dir) {
  try {
    const r = JSON.parse(fs.readFileSync(recordFile(dir), 'utf8'));
    return Array.isArray(r.runs) ? r : { runs: [] };
  } catch {
    return { runs: [] };
  }
}

/** Projects with the same folder name get separate audit folders. */
function auditBase(dir) {
  const real = fs.realpathSync(dir);
  const name = path.basename(real).replace(/[^\w.-]/g, '_') || 'project';
  const hash = crypto.createHash('sha256').update(real).digest('hex').slice(0, 6);
  return path.join(os.homedir(), 'security-audit-skill', `${name}-${hash}`);
}

/** The next unused run-<N> folder (not created or recorded yet). */
export function nextAuditRun(dir) {
  const base = auditBase(dir);
  let n = 1;
  try {
    for (const e of fs.readdirSync(base)) {
      const m = /^run-(\d+)$/.exec(e);
      if (m) n = Math.max(n, Number(m[1]) + 1);
    }
  } catch { /* first run */ }
  return path.join(base, `run-${n}`);
}

/** Records a run folder, so the import knows where to look. */
export function recordAuditRun(dir, runDir) {
  const rec = loadRecord(dir);
  rec.runs.push({ dir: runDir, started: new Date().toISOString() });
  ensureOutDir(dir);
  fs.writeFileSync(recordFile(dir), JSON.stringify(rec, null, 2) + '\n');
}

const readJson = (p) => {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
};

/**
 * The newest recorded run that produced a findings.json, or null.
 * { runDir, started, status, sourceRef, records, report }
 */
export function latestAudit(dir) {
  const runs = [...loadRecord(dir).runs].reverse();
  for (const r of runs) {
    const records = readJson(path.join(r.dir, 'findings.json'));
    if (!Array.isArray(records)) continue;
    const meta = readJson(path.join(r.dir, 'run-metadata.json')) ?? {};
    const report = path.join(r.dir, 'REPORT.md');
    return {
      runDir: r.dir,
      started: r.started,
      status: meta.run_status ?? 'unknown',
      incompleteReason: meta.incomplete_reason ?? null,
      sourceRef: typeof meta.source_ref === 'string' ? meta.source_ref : meta.source_ref?.commit ?? null,
      records,
      report: fs.existsSync(report) ? report : null,
    };
  }
  return null;
}

export function auditCounts(audit) {
  const n = (v) => audit.records.filter((r) => r?.verdict === v).length;
  return { confirmed: n('confirmed'), needsValidation: n('needs_validation'), rejected: n('rejected') };
}

const str = (v, max = 1500) => (typeof v === 'string' ? v.replace(/\s+/g, ' ').trim().slice(0, max) : '');

// Paths in the skill's records may be absolute or relative to the target.
function relPath(dir, file) {
  if (typeof file !== 'string' || !file) return null;
  const rel = path.isAbsolute(file) ? path.relative(dir, file) : file;
  return rel.startsWith('..') ? file : rel;
}

/** Confirmed audit records as Gnawky findings. Reproduction payloads are left out on purpose. */
export function auditFindings(dir, audit) {
  return audit.records
    .filter((r) => r && r.verdict === 'confirmed' && typeof r.fingerprint === 'string')
    .map((r) => {
      const trace = Array.isArray(r.trace) ? r.trace : [];
      const at = trace.find((t) => t.kind === 'sink') ?? trace[0] ?? (Array.isArray(r.evidence) ? r.evidence[0] : null);
      const severity = SEVERITY[r.severity?.overall_severity] ?? 'medium';
      return makeFinding({
        tool: AUDIT_TOOL,
        ruleId: r.fingerprint,
        severity,
        title: str(r.title, 200) || r.fingerprint,
        file: relPath(dir, at?.file),
        line: Number.isInteger(at?.line) ? at.line : null,
        description: [str(r.description), r.root_cause && `Root cause: ${str(r.root_cause)}`].filter(Boolean).join(' '),
        fix: { type: 'manual', detail: str(r.remediation?.strategy) || 'See the audit report.' },
        audit: {
          confidence: r.confidence?.score ?? null,
          confidenceReason: str(r.confidence?.reason, 400),
          likelihood: r.severity?.likelihood?.score ?? null,
          impact: r.severity?.impact?.score ?? null,
          conditions: (Array.isArray(r.conditions) ? r.conditions : []).map((c) => str(c.description, 300)).filter(Boolean),
          trace: trace.map((t) => ({ kind: t.kind, file: relPath(dir, t.file), line: t.line, description: str(t.description, 300) })),
          attacker: str(r.execution?.attacker_perspective, 400),
          runDir: audit.runDir,
        },
      });
    });
}

/** Scanner entry: imports the latest audit's confirmed findings (local files only, works offline). */
export function scanAudit(dir) {
  const audit = latestAudit(dir);
  if (!audit) return { name: AUDIT_TOOL, skipped: 'no audit yet, start one from the menu' };
  return { name: AUDIT_TOOL, findings: auditFindings(dir, audit) };
}

export function buildAuditTask(s, runDir) {
  const secretFiles = [...new Set((s.result?.findings ?? []).filter((x) => x.tool === 'gitleaks').map((x) => x.file).filter(Boolean))];
  return `# Full security audit (started by Gnawky)

Use the \`${SKILL_NAME}\` skill in **full audit mode** on this repository (the current directory). I am explicitly asking for a complete codebase audit with report artifacts.

- Output directory: \`${runDir}\`. Gnawky chose it: it is new and outside the repository. Create it and use it; do not pick another one.
- Gnawky already scanned the dependencies, secrets and common code patterns; the results are in \`${OUT_DIR}/findings.json\`. Use them as leads, but the audit is about finding what scanners miss.
- Ask me before you start if you need a decision on scope or budget.
- When the run is finished (complete, or incomplete with the reason recorded), tell me in one line, and remind me to type /exit to return to Gnawky, which imports the results.

Rules. Follow them strictly:
- Do not change any file in this repository. Only write inside the output directory.
- Do not open .env files, private keys (*.pem, *.key), or any credentials file.${secretFiles.length ? `\n- Do not open these files, a scanner flagged them as containing secrets: ${secretFiles.join(', ')}. Work from the file name and line number only.` : ''}
- Never print secret values.
- Follow the skill's execution-safety rules: if you can't run something inside the sandbox it requires, don't run it.
- Never run install scripts, \`git commit\`, or \`git push\`.
`;
}
