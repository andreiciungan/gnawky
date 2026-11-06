import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { c, clear, ask, confirm, pause, select, checklist, sevTag, printLogo, wordmark, ticker, fmtDuration } from './ui.js';
import {
  loadConfig, saveConfig, configExists, ensureOutDir, OUT_DIR, DEFAULT_CONFIG,
} from './config.js';
import { detectProject, semgrepRulesFor } from './detect.js';
import { TOOLS, tool, toolVersion, installCommand, installTool } from './tools.js';
import {
  performScan, loadLastScan, writeReports, reportFile, htmlReportFile, filterFindings, visibleFindings,
} from './scan.js';
import { SEVERITY_ORDER, loadIgnores, addIgnores, removeIgnore } from './finding.js';
import {
  loadTriage, runTriage, triageItems, batchCount, triageOrder, secretDenyRules, VERDICTS, URGENCIES,
  findingSource, TRIAGE_SOURCES, MAX_PARALLEL,
} from './triage.js';
import {
  AUDIT_TOOL, PLUGIN_DIR, latestAudit, auditCounts, nextAuditRun, recordAuditRun, buildAuditTask, scanAudit,
} from './audit.js';
import {
  isAutoFixable, emptyPlan, planSize, addFixToPlan, describePlan, preflight, applyPlan, hasDependencyChanges,
  planSteps, regressions, undoFix,
} from './fix.js';
import { isAvailable, IS_WIN, scanDependencies } from './scanners.js';
import {
  PROFILES, SCOPE_MODES, projectFiles, buildTree, itemsOf, stateOf, toggle, selectedCount, validKeys, shortKey, scopeSummary,
} from './scope.js';
import {
  packageManager, lockfileName, runLabel, auditName, isDepAudit, DEP_AUDIT_TOOLS,
} from './pm.js';
import {
  detectScripts, runScript, describeResult, packagesWithInstallScripts, diffFindings, rebuild,
} from './verify.js';

// ------------------------------------------------------------------ helpers

const loc = (f) => (f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '');
const fmtDate = (iso) => new Date(iso).toLocaleString();

function safeIgnores(dir) {
  try { return loadIgnores(dir); } catch { return []; }
}

function readPkg(dir) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch { return null; }
}

function summary(findings) {
  if (!findings.length) return c.green('no findings');
  const colors = { critical: c.red, high: c.red, medium: c.yellow, low: c.blue, info: c.gray };
  return SEVERITY_ORDER
    .map((s) => [s, findings.filter((f) => f.severity === s).length])
    .filter(([, n]) => n)
    .map(([s, n]) => colors[s](`${n} ${s}`))
    .join(', ');
}

// HEADER_LINES: what header() prints under the logo (name, status, rule, blank line).
const HEADER_LINES = 4;

/** `below`: lines the screen prints after the header, so the big logo is only shown when it all fits. */
function header(s, { logo = false, below } = {}) {
  clear();
  const name = s.pkg?.name ?? path.basename(s.dir);
  if (logo) {
    printLogo(below === undefined ? undefined : { below: HEADER_LINES + below });
    console.log(`${c.bold(name)}  ${c.gray(s.dir)}`);
  } else {
    console.log(`${wordmark()}  ${c.bold(name)}  ${c.gray(s.dir)}`);
  }
  const bits = [s.result ? `Last scan ${fmtDate(s.result.date)}: ${summary(s.result.findings)}` : c.gray('Not scanned yet')];
  if (s.cfg.offline) bits.push(c.yellow('offline mode'));
  if (s.stale && s.result) bits.push(c.yellow('results may be out of date, rescan'));
  if (!s.pkg) bits.push(c.yellow('no package.json here'));
  console.log(bits.join(c.gray('  ·  ')));
  console.log(c.gray('─'.repeat(Math.min(process.stdout.columns || 60, 72))));
  console.log();
}

function triageTag(t) {
  if (!t) return '';
  if (t.verdict === 'false-positive') return c.green('[likely false positive]');
  const u = { now: (x) => c.bold(c.red(x)), soon: c.yellow, low: c.gray }[t.urgency] ?? c.gray;
  return u(`[${URGENCIES[t.urgency]}${t.verdict === 'needs-review' ? ', unsure' : ''}]`);
}

function printFinding(f, t) {
  console.log(`${sevTag(f.severity)} ${c.bold(f.title)}\n`);
  const row = (k, v) => v && console.log(`  ${c.gray(k.padEnd(14))}${v}`);
  row('Location', loc(f));
  row('Found by', `${f.tool} (${f.ruleId})`);
  row('CWE', f.cwe?.join(', '));
  row('Details', f.description);
  row('Suggested fix', f.fix.detail);
  row('More info', f.url);
  row('ID', c.gray(f.fingerprint));
  if (f.audit) {
    row('Audit', `verified by the full audit${f.audit.confidence ? `, ${f.audit.confidence} confidence` : ''}${f.audit.likelihood ? ` (likelihood ${f.audit.likelihood}, impact ${f.audit.impact})` : ''}`);
    row('Attacker', f.audit.attacker);
    if (f.audit.conditions.length) row('Conditions', f.audit.conditions.join('; '));
    if (f.audit.trace.length) row('Trace', f.audit.trace.map((x) => `${x.kind} ${x.file}:${x.line}`).join(' → '));
    row('Full report', c.gray(f.audit.runDir));
  }
  if (t) row("Claude's take", `${triageTag(t)} ${VERDICTS[t.verdict]}. ${t.reason} ${c.gray('(a suggestion; check it)')}`);
  console.log();
}

function dropFromResult(s, fingerprints) {
  const set = new Set(fingerprints);
  const before = s.result.findings.length;
  s.result.findings = s.result.findings.filter((f) => !set.has(f.fingerprint));
  s.result.ignoredCount += before - s.result.findings.length;
  writeReports(s.dir, s.result);
}

// ------------------------------------------------------------------ screens

async function scanScreen(s) {
  header(s);
  console.log(`${c.bold('Scanning')} ${c.gray('(read-only: nothing in your project is changed)')}\n`);
  s.result = await performScan(s.dir, s.cfg, (m) => console.log(c.gray(m)), { onStep: (label) => ticker(label) });
  s.browse = null;
  s.stale = false;

  console.log();
  for (const t of s.result.tools) {
    const icon = t.status === 'ran' ? c.green('✔') : t.status === 'skipped' ? c.yellow('–') : c.red('✖');
    const msg = t.status === 'ran' ? `${t.count} finding(s)${t.note ? c.gray(`  ·  ${t.note}`) : ''}` : c.gray(t.message);
    const time = t.seconds >= 1 ? c.gray(`  ·  ${fmtDuration(t.seconds)}`) : '';
    console.log(`  ${icon} ${t.name.padEnd(12)} ${msg}${time}`);
  }
  if (s.result.tools.every((t) => t.status !== 'ran')) {
    console.log(c.yellow('\n  ⚠ No scanner ran, so "no findings" does NOT mean the project is safe.'));
    console.log(c.yellow('    Open "Tools & scanners" from the menu to see what is missing.'));
  }
  console.log(`\n  ${c.bold('Result:')} ${summary(s.result.findings)}\n`);

  const n = s.result.findings.length;
  const next = await select('Next step', [
    { label: 'Review & fix findings one by one', value: 'review', disabled: !n },
    { label: 'Browse findings', value: 'view', disabled: !n },
    { label: 'Back to menu', value: null },
  ]);
  if (next) await SCREENS[next](s);
}

async function viewScreen(s) {
  // Where the user was (page and finding), kept on `s` so it survives opening a
  // finding and leaving the screen; a new scan starts again at the top.
  s.browse ??= { page: 0, fingerprint: null };
  for (;;) {
    header(s);
    const list = s.result.findings;
    if (!list.length) {
      console.log(c.green('No findings to show.'));
      await pause();
      return;
    }
    const size = 9;
    const pages = Math.ceil(list.length / size);
    const at = list.findIndex((f) => f.fingerprint === s.browse.fingerprint);
    // Back from a finding that is still listed: its page. Otherwise (e.g. it was ignored) the same page number.
    const page = Math.min(at >= 0 && s.browse.fromDetail ? Math.floor(at / size) : s.browse.page, pages - 1);
    const items = list.slice(page * size, (page + 1) * size);

    const options = items.map((f, i) => ({
      label: `${sevTag(f.severity)} ${f.title}  ${triageTag(s.triage.entries[f.fingerprint])} ${c.gray(loc(f))}`.replace(/  +/g, '  '), value: f, number: page * size + i + 1,
    }));
    options.push({ static: '' });
    if (pages > 1) {
      const prev = page > 0 ? c.accent('← Previous page') : c.gray('← Previous page');
      const next = page < pages - 1 ? c.accent('Next page →') : c.gray('Next page →');
      options.push({ static: `${prev}    ${c.gray('·')}    ${next}` });
    }
    options.push({ label: 'Back', value: null });

    const first = page * size + 1;
    const title = pages > 1
      ? `Findings ${first}-${first + items.length - 1} of ${list.length}  ${c.gray(`(page ${page + 1} of ${pages})`)}. Choose one for details`
      : `Findings (${list.length}). Choose one for details`;
    const cursor = items.findIndex((f) => f.fingerprint === s.browse.fingerprint);
    const pick = await select(title, options, {
      initial: cursor >= 0 ? cursor : null,
      keys: pages > 1 ? { right: 'next', left: 'prev' } : {},
      hint: pages > 1 ? '←/→ page' : '',
    });

    s.browse.fromDetail = false;
    if (pick === 'next' || pick === 'prev') {
      s.browse = { page: Math.min(Math.max(0, page + (pick === 'next' ? 1 : -1)), pages - 1), fingerprint: null };
      continue;
    }
    s.browse.page = page;
    if (!pick) return;
    s.browse = { page, fingerprint: pick.fingerprint, fromDetail: true };
    await detailScreen(s, pick);
  }
}

async function detailScreen(s, f) {
  header(s);
  printFinding(f, s.triage.entries[f.fingerprint]);
  const auto = isAutoFixable(f);
  const action = await select('What do you want to do?', [
    { label: auto ? 'Fix it automatically' : 'Fix automatically (not available, see suggested fix)', value: 'fix', disabled: !auto },
    { label: 'Ask Claude to explain it and propose a fix', value: 'claude' },
    { label: 'Ignore it (needs a reason)', value: 'ignore' },
    { label: 'Back', value: null },
  ]);
  if (action === 'fix') {
    const plan = emptyPlan();
    addFixToPlan(plan, f);
    await confirmAndApply(s, plan);
  } else if (action === 'ignore') {
    const reason = await ask('Why is this safe to ignore? (leave empty to cancel) ');
    if (!reason) return;
    addIgnores(s.dir, [{ finding: f, reason }]);
    dropFromResult(s, [f.fingerprint]);
    console.log(c.green('✔ Ignored. You can restore it from "Ignored findings".'));
    await pause();
  } else if (action === 'claude') {
    await claudeScreen(s, f);
  }
}

async function reviewScreen(s, { claudeOrder = false } = {}) {
  const plan = emptyPlan();
  const list = claudeOrder ? triageOrder(s.result.findings, s.triage) : [...s.result.findings];
  for (const [i, f] of list.entries()) {
    header(s);
    console.log(c.gray(`Finding ${i + 1} of ${list.length}   ·   planned so far: ${planSize(plan)} change(s)\n`));
    printFinding(f, s.triage.entries[f.fingerprint]);
    const choice = await select('Your decision', [
      { label: 'Fix automatically', value: 'fix', disabled: !isAutoFixable(f) },
      { label: 'Skip for now', value: 'skip' },
      { label: 'Ignore (needs a reason)', value: 'ignore' },
      { label: 'Stop reviewing', value: 'stop' },
    ]);
    if (choice === null || choice === 'stop') break;
    if (choice === 'fix') addFixToPlan(plan, f);
    if (choice === 'ignore') {
      const reason = await ask('Why is this safe to ignore? (leave empty to skip) ');
      if (reason) plan.ignores.push({ finding: f, reason });
    }
  }
  if (!planSize(plan)) {
    header(s);
    console.log('No changes selected. Nothing was changed.');
    await pause();
    return;
  }
  await confirmAndApply(s, plan);
}

async function confirmAndApply(s, plan) {
  header(s);
  console.log(c.bold('Here is what will happen:\n'));
  for (const line of describePlan(plan)) console.log(`  • ${line}`);
  const deps = hasDependencyChanges(plan);
  const problem = deps ? preflight(s.dir) : null;
  if (deps) {
    console.log(problem
      ? c.yellow(`\n  ⚠ Dependency fixes will be skipped: ${problem}`)
      : c.gray('\n  Dependency changes are made on a new git branch, with install scripts disabled.'));
  }
  console.log();
  let opts = { scripts: [], oneAtATime: false };
  if (deps && !problem) {
    opts = await chooseVerification(s, plan);
    if (!opts) return;
  }
  if (!(await confirm('Apply this plan?'))) {
    console.log('Cancelled. Nothing was changed.');
    await pause();
    return;
  }
  console.log();
  const report = applyPlan(s.dir, plan, (m) => console.log(m), opts);
  if (plan.ignores.length) dropFromResult(s, plan.ignores.map((i) => i.finding.fingerprint));
  if (report.branch) return verifyScreen(s, report);
  await pause();
}

/** Asks which package.json scripts should verify the fix. Returns null if the user backs out. */
async function chooseVerification(s, plan) {
  const available = detectScripts(s.dir);
  if (!available.length) {
    console.log(c.yellow('  ⚠ No test, build, lint or typecheck script in package.json.'));
    console.log(c.gray('    Gnawky will check dependency compatibility, but can\'t check that your project still runs.\n'));
    return { scripts: [], oneAtATime: false };
  }
  const cmds = (names) => names.map((n) => runLabel(s.pm, n)).join(', ');
  console.log(c.bold('Check that your project still works?'));
  console.log(c.gray('  Gnawky can run your package.json scripts before and after the fix, so it can tell'));
  console.log(c.gray('  whether the fix broke something or it was already failing.'));
  console.log(`  ${c.yellow('This runs your project\'s own code')} ${c.gray('(tests may start servers or use the network).')}`);
  console.log(c.gray('  Each script gets 15 minutes. Install scripts stay disabled.\n'));
  const choices = [{ label: `Yes, run: ${cmds(available)}`, value: available }];
  if (available.includes('test') && available.length > 1) choices.push({ label: `Only: ${runLabel(s.pm, 'test')}`, value: ['test'] });
  choices.push({ label: 'No, only check dependency compatibility', value: [] });
  const scripts = await select('Verify the fix?', choices);
  if (scripts === null) return null;

  let oneAtATime = false;
  if (scripts.length && planSteps(plan).length > 1) {
    console.log();
    const mode = await select('How should the fixes be applied?', [
      { label: 'All at once, then run the scripts (faster)', value: 'all' },
      { label: 'One package at a time: run the scripts after each, undo any change that breaks them (slower)', value: 'one' },
    ]);
    if (mode === null) return null;
    oneAtATime = mode === 'one';
  }
  console.log();
  return { scripts, oneAtATime };
}

function printVerifyReport(pm, report, audit) {
  const runs = (n) => runLabel(pm, n);
  const tree = pm === 'yarn' ? 'yarn check' : 'npm ls';
  const ok = (m) => console.log(`  ${c.green('✔')} ${m}`);
  const warn = (m) => console.log(`  ${c.yellow('⚠')} ${m}`);
  const bad = (m) => console.log(`  ${c.red('✖')} ${m}`);
  const sub = (m) => console.log(`      ${c.gray(m)}`);

  console.log(`${c.bold('Fix results')}  ${c.gray(`on branch ${report.branch}`)}\n`);
  console.log(c.bold('Changes'));
  for (const st of report.steps) {
    const label = `${st.label}${st.major ? c.yellow('  (major)') : ''}`;
    if (st.status === 'applied') ok(`${label}  ${c.gray(`${st.findings} finding(s)`)}`);
    else if (st.status === 'skipped') ok(`${label}  ${c.gray(st.note)}`);
    else if (st.status === 'reverted') warn(`${label}  ${c.yellow(`undone: it broke ${st.broke.map(runs).join(', ')}`)}`);
    else bad(`${label}  ${c.red(`${pm === 'yarn' ? 'yarn' : 'npm'} failed, not applied`)}`);
  }

  console.log(`\n${c.bold('Compatibility')}`);
  if (report.lsNew.length) {
    bad(`${report.lsNew.length} new dependency problem(s) found by ${tree}:`);
    for (const p of report.lsNew.slice(0, 8)) sub(p);
  } else {
    ok(`No new dependency problems (${tree})${report.lsPreexisting ? c.gray(`  ·  ${report.lsPreexisting} that already existed`) : ''}`);
  }
  if (report.engines.length) {
    warn(`Packages that say they don't support your Node ${process.version}:`);
    for (const e of report.engines.slice(0, 8)) sub(e);
  } else {
    ok(`Installed packages support your Node ${process.version}`);
  }

  if (audit) {
    console.log(`\n${c.bold(auditName(pm))}`);
    const line = `fixed ${audit.fixed.length}  ·  still open ${audit.remaining.length}`;
    if (audit.added.length) {
      warn(`${line}  ·  ${c.yellow(`new ${audit.added.length}`)}`);
      for (const f of audit.added.slice(0, 5)) console.log(`      ${sevTag(f.severity)} ${f.title}`);
      sub('New ones usually come from the upgraded packages\' own dependencies. Rescan and review them.');
    } else {
      ok(line);
    }
  }

  console.log(`\n${c.bold('Your scripts')}`);
  if (report.scriptsSkipped) {
    warn(`Not run: ${report.scriptsSkipped}`);
  } else if (!report.scripts.length) {
    warn('Not run, so this fix is not verified. Run your app and tests before you commit.');
  } else {
    for (const n of report.scripts) {
      const before = report.baseline[n];
      const after = report.after[n];
      if (report.oneAtATime) {
        if (before.ok) ok(`${runs(n)}  ${c.gray('passed before, and after every change that was kept')}`);
        else warn(`${runs(n)}  ${c.gray('was already failing before the fix, so it could not judge the changes')}`);
      } else if (before.ok && after.ok) ok(`${runs(n)}  ${c.gray('passed before and after')}`);
      else if (before.ok) bad(`${runs(n)}  ${c.red(`passed before, ${after.timedOut ? 'TIMES OUT' : 'FAILS'} after the fix`)}`);
      else if (after.ok) ok(`${runs(n)}  ${c.gray('failed before, passes now')}`);
      else warn(`${runs(n)}  ${c.gray('failed before and after (not caused by the fix)')}`);
    }
  }

  const broken = regressions(report);
  console.log();
  if (broken.length) console.log(c.bold(c.red(`✖ The fix broke: ${broken.map(runs).join(', ')}`)));
  else if (report.scripts.length && !report.lsNew.length) console.log(c.bold(c.green('✔ Everything that worked before still works.')));
  console.log();
}

/** After a dependency fix: show the checks, then keep, undo, or dig into failures. */
async function verifyScreen(s, report) {
  let audit = null;
  let auditAll = null;
  if (!s.cfg.offline && s.cfg.scanners['npm-audit'] !== false) {
    console.log();
    const done = ticker(`running ${auditName(s.pm)} again`);
    const res = await scanDependencies(s.dir);
    done(res.findings ? `${auditName(s.pm)}: ${res.findings.length} finding(s)` : `${auditName(s.pm)} failed`, res.findings ? 'ok' : 'fail');
    if (res.findings) {
      auditAll = filterFindings(s.dir, s.cfg, res.findings);
      audit = diffFindings(s.result.findings.filter(isDepAudit), auditAll);
    }
  }

  for (;;) {
    header(s);
    printVerifyReport(s.pm, report, audit);
    const broken = regressions(report);
    const failed = report.scripts.filter((n) => report.after[n] && !report.after[n].ok);
    const native = broken.length ? packagesWithInstallScripts(s.dir) : [];
    const choice = await select('What now?', [
      { label: 'Keep the changes on this branch', value: 'keep' },
      { label: `Undo everything (back to ${report.base}, delete the branch)`, value: 'undo' },
      ...(failed.length ? [{ label: 'Show the output of the failed scripts', value: 'output' }] : []),
      ...(broken.length && native.length
        ? [{ label: `Run npm rebuild, then retry (runs install scripts of ${native.length} package(s))`, value: 'rebuild' }] : []),
      ...(broken.length ? [{ label: 'Ask Claude to investigate the failure', value: 'claude', disabled: s.cfg.offline }] : []),
    ]);

    if (choice === 'undo') {
      if (!(await confirm(`Throw away all changes on ${report.branch}?`))) continue;
      console.log();
      undoFix(s.dir, report, (m) => console.log(m));
      s.stale = false;
      await pause();
      return;
    }
    if (choice === 'output') {
      header(s);
      for (const n of failed) {
        console.log(c.bold(runLabel(s.pm, n)) + c.gray(`  (last lines; full log: ${path.relative(s.dir, report.after[n].logFile)})`));
        console.log(report.after[n].tail + '\n');
      }
      await pause();
      continue;
    }
    if (choice === 'rebuild') {
      console.log(c.yellow('\nnpm rebuild runs the install scripts of every installed package (for example native builds).'));
      console.log(c.gray(`Packages with install scripts: ${native.slice(0, 10).join(', ')}${native.length > 10 ? ', …' : ''}`));
      if (!(await confirm('Only continue if you trust your dependencies. Run npm rebuild?'))) continue;
      console.log(c.gray('\n  running npm rebuild…'));
      const r = rebuild(s.dir);
      if (r.status !== 0) console.log(c.red(`  ✖ npm rebuild failed:\n${r.stderr.trim().split('\n').slice(-8).join('\n')}`));
      for (const n of broken) {
        console.log(c.gray(`  running ${runLabel(s.pm, n)}…`));
        report.after[n] = runScript(s.dir, n, 'after-rebuild');
        console.log(`    ${describeResult(report.after[n])}`);
      }
      await pause();
      continue;
    }
    if (choice === 'claude') {
      await launchClaude(s, buildVerifyPrompt(s, report, broken));
      continue;
    }

    // Keep (also when the user just backs out).
    if (auditAll) {
      const others = s.result.findings.filter((f) => !isDepAudit(f));
      s.result.findings = visibleFindings([...others, ...auditAll], s.cfg);
      const tool = s.result.tools.find((t) => DEP_AUDIT_TOOLS.includes(t.name));
      if (tool) tool.count = auditAll.length;
      writeReports(s.dir, s.result);
    } else {
      s.stale = true;
    }
    header(s);
    console.log(`${c.bold('Kept on branch')} ${report.branch}\n`);
    if (report.diffStat) console.log(`${report.diffStat}\n`);
    console.log('Next steps:');
    console.log('  1. Review the changes:  git diff');
    console.log('  2. If a package needs a build step:  npm rebuild');
    const files = `package.json ${lockfileName(s.pm)}`;
    console.log(`  3. Commit on this branch:  git add ${files} && git commit -m "Fix vulnerable dependencies"`);
    console.log(c.gray(`  To throw it all away:  git checkout -- ${files} && git checkout ${report.base} && git branch -D ${report.branch}`));
    await pause();
    return;
  }
}

function buildClaudePrompt(s, f) {
  const secretFiles = [...new Set(s.result.findings.filter((x) => x.tool === 'gitleaks').map((x) => x.file))];
  const focus = f
    ? `Focus only on the finding with fingerprint ${f.fingerprint} ("${f.title}").`
    : 'Go through the findings, most severe first.';
  return `# Security fix session (started by Gnawky)

Read \`${OUT_DIR}/findings.json\`: it contains the results of a security scan of this project.
${focus}

For each finding: explain in plain language what an attacker could do, check in the code whether it is a real issue or a false positive, then give 1 to 3 fix options with trade-offs (effort, risk of breaking things) and say which one you recommend. Then ask me what I want to do.

Rules. Follow them strictly:
- Do not open .env files, private keys (*.pem, *.key), or any credentials file.${secretFiles.length ? `\n- Do not open these files, a scanner flagged them as containing secrets: ${secretFiles.join(', ')}. Work from the file name and line number only.` : ''}
- Never print secret values.
- For leaked secrets, tell me to rotate the credential first; removing it from the code is not enough.
- Do not change any file until I approve that specific change. Show me the diff first.
- Never run \`npm audit fix --force\`, install scripts, this project's code or tests, \`git commit\`, or \`git push\` unless I ask.
`;
}

function buildVerifyPrompt(s, report, broken) {
  const logs = broken.map((n) => `- \`${runLabel(s.pm, n)}\`: \`${path.relative(s.dir, report.after[n].logFile)}\``).join('\n');
  const changes = report.steps.filter((st) => st.status === 'applied').map((st) => `- ${st.label}`).join('\n');
  return `# Investigate a failing dependency upgrade (started by Gnawky)

Gnawky upgraded dependencies to fix security vulnerabilities, on the git branch \`${report.branch}\` (started from \`${report.base}\`). These scripts passed before the upgrade and fail after it.

Full output of each failing script:
${logs}

Changes made (see \`git diff package.json\`; in yarn projects \`resolutions\` entries count as changes too):
${changes}

Find out why it fails: read the logs, identify which upgraded package causes it and what changed in it, and find the code in this project that is affected. Then give 1 to 3 ways to fix it with trade-offs (for example: adapt the code, pick a different version, or undo just that upgrade) and say which one you recommend. Then ask me what I want to do.

Rules. Follow them strictly:
- Do not open .env files, private keys (*.pem, *.key), or any credentials file. Never print secret values.
- Do not change any file until I approve that specific change. Show me the diff first.
- You may re-run the failing scripts to check a fix, but only after I approve.
- Never run \`npm audit fix --force\`, install scripts (including \`npm rebuild\`), \`git commit\`, or \`git push\` unless I ask.
`;
}

async function claudeScreen(s, f) {
  await launchClaude(s, buildClaudePrompt(s, f));
}

/** Starts Claude Code in the project with a task file, after a privacy notice. */
async function launchClaude(s, task, { args = [], notice = null, onStart = null } = {}) {
  header(s);
  if (s.cfg.offline) {
    console.log(c.yellow('Offline mode is on. Asking Claude sends data to Anthropic, so it is turned off.'));
    console.log(c.gray('You can change this in Settings.'));
    await pause();
    return false;
  }
  if (!isAvailable('claude')) {
    console.log('Claude Code is not installed.\n');
    console.log(`  Install it with:  ${c.accent('npm install -g @anthropic-ai/claude-code')}`);
    console.log('  then choose this option again.');
    await pause();
    return false;
  }
  console.log(c.bold('Before you continue: privacy\n'));
  if (notice) {
    for (const line of notice) console.log(line);
    console.log();
  } else {
    console.log('  • This starts Claude Code in this folder.');
    console.log(`  • Claude will read the files Gnawky prepared in ${OUT_DIR}/ (scan results have secret values`);
    console.log('    removed; test logs are not filtered) and may read the source files it needs.');
    console.log('    Anything Claude reads is sent to Anthropic.');
    console.log('  • Claude is told not to open .env files, keys, or files flagged as containing secrets.');
    console.log(c.gray('    That is an instruction, not a hard block. For a hard block, add deny rules'));
    console.log(c.gray('    in Claude Code\'s permission settings.'));
    console.log('  • Claude asks before changing any file.\n');
  }
  if (!(await confirm('Continue?'))) return false;

  ensureOutDir(s.dir);
  fs.writeFileSync(path.join(s.dir, OUT_DIR, 'claude-task.md'), task);
  // A constant prompt is passed, never scanner data, so it is safe even when Windows needs a shell.
  const prompt = `Read ${OUT_DIR}/claude-task.md and follow the instructions in it.`;
  clear();
  const quote = (a) => (IS_WIN ? `"${a}"` : a);
  onStart?.();
  // The prompt goes first: options like --disallowedTools take several values and would swallow it.
  spawnSync(IS_WIN ? 'claude.cmd' : 'claude', [prompt, ...args].map(quote), {
    cwd: s.dir, stdio: 'inherit', shell: IS_WIN,
  });
  s.stale = true; // Claude may have changed files
  return true;
}

// Full-audit findings were already verified by the skill, so they are not triaged again.
const triageable = (s) => s.result.findings.filter((f) => f.tool !== AUDIT_TOOL);

function triaged(s) {
  const all = s.result ? triageable(s) : [];
  const done = all.filter((f) => s.triage.entries[f.fingerprint]).length;
  return done ? c.gray(`  (${done} of ${all.length} done)`) : '';
}

const SEVERITIES_DESC = ['critical', 'high', 'medium', 'low', 'info'];

/** Rough wall-clock estimate: 1-4 minutes per Claude run, `parallel` runs at once. */
function triageEstimate(batches, parallel) {
  const rounds = Math.ceil(batches / Math.max(1, parallel));
  const [lo, hi] = [rounds, rounds * 4];
  return hi < 2 ? 'about a minute' : `about ${lo}–${hi} min`;
}

/** Severity and source checkboxes. Resolves with { severities, sources }, or null. */
async function chooseTriageFilter(s, pool) {
  const last = s.cfg.triageFilter ?? {};
  const severities = SEVERITIES_DESC.filter((v) => pool.some((f) => f.severity === v));
  const sources = Object.keys(TRIAGE_SOURCES).filter((v) => pool.some((f) => findingSource(f) === v));
  const keep = (saved, avail, def) => {
    const picked = Array.isArray(saved) ? saved.filter((v) => avail.includes(v)) : def.filter((v) => avail.includes(v));
    return new Set(picked.length ? picked : avail);
  };
  const sev = keep(last.severities, severities, ['critical', 'high']);
  const src = keep(last.sources, sources, sources);
  const rows = [
    { heading: 'Severity' },
    ...severities.map((v) => ({ set: sev, value: v })),
    { heading: '' },
    { heading: 'Source' },
    ...sources.map((v) => ({ set: src, value: v })),
  ];
  const picked = () => pool.filter((f) => sev.has(f.severity) && src.has(findingSource(f)));
  const view = {
    title: () => {
      const todo = picked();
      const items = triageItems(todo);
      const b = batchCount(items);
      return `${c.bold('What should Claude triage?')}\n`
        + (todo.length
          ? c.green(`${todo.length} finding(s) → ${items.length} item(s) → ${b} Claude run(s)`) + c.gray(`  ·  ${triageEstimate(b, 1)} one at a time`)
          : c.yellow('Nothing selected')) + '\n';
    },
    items: () => rows.map((r) => {
      if ('heading' in r) return r;
      const inPool = pool.filter((f) => (r.set === sev ? f.severity : findingSource(f)) === r.value);
      let extra = '';
      if (r.value === 'dependencies') extra = c.gray(` → ${triageItems(inPool).length} package(s)`);
      if (r.value === 'secrets') extra = c.gray(` → ${triageItems(inPool).length} file(s)`);
      return { label: `${r.value.padEnd(14)} ${String(inPool.length).padStart(5)}${extra}`, state: r.set.has(r.value) ? 'on' : 'off' };
    }),
    toggle: (i) => {
      const r = rows[i];
      if (r.set.has(r.value)) r.set.delete(r.value); else r.set.add(r.value);
    },
  };
  for (;;) {
    header(s);
    if ((await checklist(view)) === null) return null;
    if (picked().length) return { severities: [...sev], sources: [...src] };
    console.log(c.yellow('\nNothing to triage with this selection. Tick at least one severity and one source.'));
    await pause();
  }
}

/** Read-only Claude run that gives every finding a verdict and an urgency. */
async function triageScreen(s) {
  header(s);
  const blocked = s.cfg.offline
    ? 'Offline mode is on. Triage sends data to Anthropic, so it is turned off (change it in Settings).'
    : !isAvailable('claude') ? 'Claude Code is not installed. Install it with: npm install -g @anthropic-ai/claude-code'
    : IS_WIN ? 'Claude triage is not supported on Windows yet. Use "Ask Claude for help" instead.'
    : null;
  if (blocked) {
    console.log(c.yellow(blocked));
    await pause();
    return;
  }

  const all = triageable(s);
  const fresh = all.filter((f) => !s.triage.entries[f.fingerprint]);
  console.log(c.bold('Claude triage\n'));
  console.log('  Claude reads your code and decides, for each finding, whether it is a real issue');
  console.log('  for this project and how urgent it is. Its answers are suggestions: nothing is');
  console.log('  fixed or ignored automatically.\n');
  console.log(`  ${all.length - fresh.length} of ${all.length} findings already have a verdict.\n`);
  const scope = await select('What should Claude check?', [
    { label: `Only findings without a verdict (${fresh.length})`, value: 'new', disabled: !fresh.length },
    { label: `All findings again (${all.length})`, value: 'all' },
    { label: 'Show the current results', value: 'show', disabled: fresh.length === all.length },
    { label: 'Back', value: null },
  ]);
  if (!scope) return;
  if (scope === 'show') return triageResults(s, null);

  const pool = scope === 'new' ? fresh : all;
  const filter = await chooseTriageFilter(s, pool);
  if (!filter) return;
  const todo = pool.filter((f) => filter.severities.includes(f.severity) && filter.sources.includes(findingSource(f)));
  const items = triageItems(todo);
  const batches = batchCount(items);

  header(s);
  console.log(`${todo.length} finding(s) in ${items.length} item(s), ${batches} Claude run(s) of up to 25 items.\n`);
  const lastParallel = s.cfg.triageFilter?.parallel ?? 1;
  const choices = [1, 2, 3].filter((n) => n <= MAX_PARALLEL);
  const parallel = batches < 2 ? 1 : await select('How many Claude runs at the same time?', [
    ...choices.map((n) => ({
      label: `${n} at a time  ${c.gray(`${triageEstimate(batches, n)}${n === 1 ? '' : ', same tokens, heavier on rate limits'}`)}`,
      value: n,
      disabled: n > batches,
    })),
    { label: 'Back', value: null },
  ], { initial: Math.max(0, choices.indexOf(Math.min(lastParallel, batches))) });
  if (!parallel) return;
  s.cfg.triageFilter = { ...filter, parallel };
  saveConfig(s.dir, s.cfg);

  header(s);
  console.log(c.bold('Before you continue: privacy and cost\n'));
  console.log(`  • ${todo.length} finding(s) in ${items.length} item(s) (advisories grouped per package, secrets per file), in ${batches} Claude run(s)${parallel > 1 ? `, ${parallel} at a time` : ''}.`);
  console.log('  • Claude gets the scan results (secret values removed) and reads the source files,');
  console.log('    package.json, the lockfile and node_modules it needs. All of it is sent to Anthropic.');
  console.log('  • Claude can only read and search files: it cannot edit files or run commands.');
  console.log('  • Reading .env files, keys and .npmrc is blocked. Files flagged as containing secrets');
  console.log('    are blocked too; Claude reads a copy with the flagged lines hidden instead.');
  console.log(c.gray(`  • Rough estimate: ${triageEstimate(batches, parallel)}. It uses your Claude plan or API credits.`));
  console.log(c.gray('    Verdicts are saved after every run, so stopping halfway keeps what is done.\n'));
  if (!(await confirm('Start triage?'))) return;

  console.log();
  const started = Date.now();
  let state = { done: 0, running: 0, total: batches };
  const line = () => `  Claude is reviewing: ${state.done} of ${state.total} run(s) done${state.running ? `, ${state.running} running` : ''}… ${fmtDuration((Date.now() - started) / 1000)}`;
  const draw = () => process.stdout.write(`\r\x1b[2K${line()}`);
  const tick = setInterval(draw, 1000);
  const { triage, summary } = await runTriage(s.dir, todo, all, {
    parallel,
    onProgress: (p) => { state = p; draw(); },
  }).finally(() => clearInterval(tick));
  process.stdout.write('\n');
  s.triage = triage;
  writeReports(s.dir, s.result);
  await triageResults(s, { ...summary, seconds: Math.round((Date.now() - started) / 1000) });
}

async function triageResults(s, summary) {
  for (;;) {
    header(s);
    const all = triageable(s);
    const done = all.filter((f) => s.triage.entries[f.fingerprint]);
    const count = (fn) => done.filter((f) => fn(s.triage.entries[f.fingerprint])).length;
    const now = triageOrder(all, s.triage).filter((f) => {
      const t = s.triage.entries[f.fingerprint];
      return t && t.verdict !== 'false-positive' && t.urgency === 'now';
    });
    console.log(c.bold("Claude's triage") + c.gray('  (suggestions: check the reasons before acting)\n'));
    if (summary) {
      console.log(`  Checked ${summary.triaged} finding(s) in ${summary.seconds}s${summary.cost ? c.gray(`  ·  ≈ $${summary.cost.toFixed(2)} at API prices`) : ''}`);
      if (summary.missing) console.log(c.yellow(`  ${summary.missing} finding(s) got no verdict. Run triage again for "findings without a verdict".`));
      for (const e of summary.errors) console.log(c.red(`  ✖ ${e}`));
      if (summary.redacted) console.log(c.gray(`  Claude read ${summary.redacted} file(s) flagged for secrets as redacted copies (flagged lines hidden, copies deleted).`));
      if (summary.blocked) console.log(c.yellow(`  ${summary.blocked} file(s) flagged for secrets stayed blocked (no safe copy), so findings in them may say "needs a human".`));
      if (summary.denials) console.log(c.gray(`  Claude tried to open ${summary.denials} blocked file(s); the reads were refused.`));
      console.log();
    }
    console.log(`  ${c.bold(c.red(`${now.length} fix now`))}  ·  ${count((t) => t.verdict !== 'false-positive' && t.urgency === 'soon')} fix soon  ·  `
      + `${count((t) => t.verdict !== 'false-positive' && t.urgency === 'low')} low priority  ·  ${c.green(`${count((t) => t.verdict === 'false-positive')} likely false positive`)}`
      + `  ·  ${count((t) => t.verdict === 'needs-review')} unsure  ·  ${all.length - done.length} not triaged\n`);
    for (const f of now.slice(0, 8)) {
      console.log(`  ${sevTag(f.severity)} ${f.title}`);
      console.log(c.gray(`      ${s.triage.entries[f.fingerprint].reason}`));
    }
    if (now.length > 8) console.log(c.gray(`  …and ${now.length - 8} more`));
    if (now.length) console.log();

    const pick = await select('Next step', [
      { label: "Review & fix in Claude's order (fix now first)", value: 'review' },
      { label: 'Browse findings', value: 'view' },
      { label: 'Open HTML report in browser', value: 'html' },
      { label: 'Back to menu', value: null },
    ]);
    if (!pick) return;
    if (pick === 'review') return reviewScreen(s, { claudeOrder: true });
    if (pick === 'view') await viewScreen(s);
    if (pick === 'html' && !openHtmlReport(s)) await pause();
  }
}

/** Re-imports the latest audit into the current results without a full rescan. */
function refreshAudit(s) {
  if (!s.result) return;
  const res = scanAudit(s.dir);
  const imported = filterFindings(s.dir, s.cfg, res.findings ?? []);
  s.result.findings = visibleFindings([...s.result.findings.filter((f) => f.tool !== AUDIT_TOOL), ...imported], s.cfg);
  s.result.tools = [
    ...s.result.tools.filter((t) => t.name !== AUDIT_TOOL),
    res.findings ? { name: AUDIT_TOOL, status: 'ran', count: res.findings.length } : { name: AUDIT_TOOL, status: 'skipped', message: res.skipped },
  ];
  writeReports(s.dir, s.result);
  s.browse = null;
}

async function auditScreen(s) {
  for (;;) {
    header(s);
    const audit = latestAudit(s.dir);
    console.log(c.bold('Full security audit') + c.gray('  (security-audit skill by Cloudflare, MIT, bundled with Gnawky)\n'));
    console.log('  Claude audits the whole codebase for what scanners miss: broken access control,');
    console.log('  injection, data leaking between users, unsafe auth flows. Every candidate is checked');
    console.log('  by a separate verifier; only confirmed findings are imported into Gnawky.\n');
    if (audit) {
      const n = auditCounts(audit);
      const status = audit.status === 'complete' ? c.green('complete')
        : audit.status === 'incomplete' ? c.yellow(`incomplete${audit.incompleteReason ? ` (${audit.incompleteReason})` : ''}`)
        : c.yellow(audit.status);
      console.log(`  Last audit: ${fmtDate(audit.started)}  ·  ${status}${audit.sourceRef ? c.gray(`  ·  commit ${String(audit.sourceRef).slice(0, 8)}`) : ''}`);
      if (audit.scope) console.log(`  Scope: ${scopeSummary(audit.scope)}`);
      console.log(`  ${c.bold(`${n.confirmed} confirmed`)} (imported)  ·  ${n.needsValidation} need validation  ·  ${n.rejected} rejected`);
      console.log(c.gray(`  Reports: ${audit.runDir}\n`));
    } else {
      console.log(c.gray('  No audit yet.\n'));
    }
    const pick = await select('What do you want to do?', [
      { label: audit ? 'Start a new audit' : 'Start the audit', value: 'start' },
      { label: 'Open the audit report (REPORT.md)', value: 'report', disabled: !audit?.report },
      { label: 'Import the latest results again', value: 'import', disabled: !audit },
      { label: 'Back', value: null },
    ]);
    if (!pick) return;
    if (pick === 'report' && !openInBrowser(audit.report)) await pause();
    if (pick === 'import') {
      refreshAudit(s);
      console.log(c.green(`\n✔ Imported. ${s.result.findings.filter((f) => f.tool === AUDIT_TOOL).length} audit finding(s) in the list.`));
      await pause();
    }
    if (pick === 'start') await startAudit(s);
  }
}

const fmtNum = (n) => n.toLocaleString('en-US');

/** Folder picker for a custom audit. Resolves with the selected keys, or null when cancelled. */
async function pickFolders(s, tree, initial) {
  const sel = new Set(initial);
  const trail = []; // folder paths opened, from the root down
  const here = () => tree.byPath.get(trail.at(-1) ?? '');
  const view = {
    title: () => {
      const n = selectedCount(tree, sel);
      const where = trail.length ? `${trail.at(-1)}/` : 'project root';
      return `${c.bold('Folders to audit')}  ${c.gray(`in ${where}`)}\n`
        + `${n ? c.green(`${fmtNum(n)} of ${fmtNum(tree.root.total)} files selected`) : c.gray(`nothing selected yet (${fmtNum(tree.root.total)} files)`)}\n`;
    },
    items: () => itemsOf(here()).map((it) => {
      const name = (it.node ? `${it.node.name}/` : trail.length ? '(files directly in this folder)' : '(files in the project root)').padEnd(32);
      return {
        label: `${it.node ? name : c.gray(name)} ${c.gray(`${fmtNum(it.count).padStart(6)} file${it.count === 1 ? '' : 's'}`)}`,
        state: stateOf(sel, it.key),
        openable: Boolean(it.node?.children.size),
      };
    }),
    toggle: (i) => toggle(sel, tree, itemsOf(here())[i].key),
    open: (i) => {
      const it = itemsOf(here())[i];
      if (!it.node?.children.size) return false;
      trail.push(it.key);
      return true;
    },
    up: () => {
      if (!trail.length) return null;
      const left = trail.pop();
      return Math.max(0, itemsOf(here()).findIndex((it) => it.key === left));
    },
  };
  for (;;) {
    header(s);
    if ((await checklist(view)) === null) return null;
    if (sel.size) return [...sel].sort();
    console.log(c.yellow('\nSelect at least one folder (Space), or press q to go back.'));
    await pause();
  }
}

/** Asks how big the audit should be. Resolves with { mode, profile, paths, budget }, or null. */
async function chooseAuditScope(s) {
  const last = s.cfg.auditScope ?? {};
  header(s);
  const modes = ['quick', 'full', 'custom'];
  const mode = await select('How big an audit?', [
    { label: `Quick   ${c.gray('whole project, one pass (quick profile). Cheapest first look.')}`, value: 'quick' },
    { label: `Full    ${c.gray('whole project, standard profile. Long, many sub-agents.')}`, value: 'full' },
    { label: `Custom  ${c.gray('choose folders, then quick / standard / deep and a budget')}`, value: 'custom' },
    { label: 'Back', value: null },
  ], { initial: Math.max(0, modes.indexOf(last.mode)) });
  if (!mode) return null;
  if (mode !== 'custom') return { mode, profile: SCOPE_MODES[mode].profile, paths: [], budget: null };

  header(s);
  const done = ticker('listing project files');
  const tree = buildTree(projectFiles(s.dir));
  done(`${fmtNum(tree.root.total)} project files`);
  if (!tree.root.total) {
    console.log(c.yellow('No project files found.'));
    await pause();
    return null;
  }
  const paths = await pickFolders(s, tree, validKeys(tree, last.paths));
  if (!paths) return null;

  header(s);
  console.log(`Folders: ${paths.map(shortKey).join(', ')}  ${c.gray(`(${fmtNum(selectedCount(tree, new Set(paths)))} files)`)}\n`);
  const profiles = Object.keys(PROFILES);
  const profile = await select('Which profile?', [
    ...profiles.map((p) => ({ label: `${p.padEnd(9)} ${c.gray(PROFILES[p])}`, value: p })),
    { label: 'Back', value: null },
  ], { initial: Math.max(0, profiles.indexOf(last.profile ?? 'quick')) });
  if (!profile) return null;

  console.log(c.gray('\nA budget caps the number of sub-agents the audit may start. The skill needs about'));
  console.log(c.gray('6-8 for the minimum (reconnaissance, coverage checks, one verifier); it stops cleanly'));
  console.log(c.gray('and marks the run incomplete when the budget runs out.'));
  let budget = null;
  for (;;) {
    const def = last.budget ? ` ${c.gray(`[${last.budget}]`)}` : '';
    const a = await ask(`Max sub-agents (Enter = ${last.budget ? 'same as last time' : 'no limit'}, 0 = no limit)${def}: `);
    if (a === '') { budget = last.budget ?? null; break; }
    if (/^\d+$/.test(a)) { budget = Number(a) || null; break; }
    console.log(c.yellow('Type a whole number.'));
  }
  return { mode, profile, paths, budget };
}

async function startAudit(s) {
  if (!s.result) {
    header(s);
    console.log(c.yellow('Run a scan first: the audit uses the scan results as leads.'));
    await pause();
    return;
  }
  const scope = await chooseAuditScope(s);
  if (!scope) return;
  s.cfg.auditScope = scope;
  saveConfig(s.dir, s.cfg);

  const dir = nextAuditRun(s.dir);
  const shown = dir.startsWith(os.homedir()) ? path.join('~', path.relative(os.homedir(), dir)) : dir;
  const secretFiles = [...new Set(s.result.findings.filter((f) => f.tool === 'gitleaks').map((f) => f.file).filter(Boolean))];
  const cost = scope.profile === 'quick'
    ? [`  • ${c.bold('It takes a while and uses tokens')}, with several sub-agents, on your Claude plan or API credits.`]
    : [`  • ${c.bold('It takes a while and uses a lot of tokens')}: on a real project often 30 minutes or more,`,
      '    with many sub-agents, on your Claude plan or API credits.'];
  const notice = [
    `  • Scope: ${c.bold(scopeSummary(scope))}`,
    '  • This starts Claude Code in this folder with the security-audit skill.',
    `  • Claude reads the ${scope.paths.length ? 'selected folders (and code they call)' : 'whole codebase'}. Anything Claude reads is sent to Anthropic.`,
    ...cost,
    `  • Reports are written outside the project, to ${shown}.`,
    '    Claude is told not to change project files, and asks before tool use as usual.',
    '  • Reading .env files, keys, .npmrc and files flagged as containing secrets is blocked.',
    '  • When it is done, type /exit in Claude to come back; Gnawky imports the confirmed findings.',
  ];
  const launched = await launchClaude(s, buildAuditTask(s, dir, scope), {
    args: ['--plugin-dir', PLUGIN_DIR, '--disallowedTools', secretDenyRules(s.dir, secretFiles).join(',')],
    notice,
    onStart: () => recordAuditRun(s.dir, dir, scope),
  });
  if (!launched) return;
  refreshAudit(s);
  s.stale = false; // the audit doesn't change project files
}

async function ignoredScreen(s) {
  for (;;) {
    header(s);
    const list = safeIgnores(s.dir);
    if (!list.length) {
      console.log('No ignored findings.');
      await pause();
      return;
    }
    const pick = await select(`Ignored findings (${list.length}). Choose one to restore it`, [
      ...list.map((i) => ({ label: `${i.title ?? i.fingerprint}  ${c.gray(`${i.date ?? ''}: ${i.reason}`)}`, value: i })),
      { label: 'Back', value: null },
    ]);
    if (!pick) return;
    if (await confirm(`Restore "${pick.title ?? pick.fingerprint}"? It will show up again on the next scan.`)) {
      removeIgnore(s.dir, pick.fingerprint);
      s.stale = true;
    }
  }
}

async function reportScreen(s) {
  header(s);
  const file = reportFile(s.dir);
  try {
    console.log(fs.readFileSync(file, 'utf8'));
  } catch {
    console.log('No report yet. Run a scan first.');
  }
  const html = htmlReportFile(s.dir);
  console.log(c.gray(`Saved at ${file} (also security-report.html and findings.json next to it).`));
  console.log(c.gray('It lists your weak spots: keep it private, don\'t upload it anywhere public.\n'));
  if (!fs.existsSync(html) && !s.result) return pause();
  const pick = await select('Report', [
    { label: 'Open HTML report in browser', value: 'open' },
    { label: 'Back', value: 'back' },
  ]);
  if (pick === 'open' && !openHtmlReport(s)) await pause();
}

/** Rebuilds the HTML report from the current results (so it has the latest page code), then opens it. */
function openHtmlReport(s) {
  if (s.result) writeReports(s.dir, s.result);
  return openInBrowser(htmlReportFile(s.dir));
}

function openInBrowser(file) {
  const [cmd, args] =
    process.platform === 'darwin' ? ['open', [file]]
    : IS_WIN ? ['explorer', [file]]
    : ['xdg-open', [file]];
  const r = spawnSync(cmd, args, { stdio: 'ignore' });
  // explorer.exe exits with 1 even on success, so only a launch error counts there.
  if (!r.error && (IS_WIN || !r.status)) return true;
  console.log(c.yellow(`Could not open a browser. Open this file yourself: ${file}`));
  return false;
}

async function settingsScreen(s) {
  const onoff = (v) => (v ? c.green('on') : c.gray('off'));
  for (;;) {
    header(s);
    const pick = await select(`Settings ${c.gray(`(saved in ${OUT_DIR}/config.json)`)}`, [
      { label: `Minimum severity to show: ${c.bold(s.cfg.minSeverity)}`, value: 'sev' },
      { label: `Offline mode: ${onoff(s.cfg.offline)}  ${c.gray('(nothing leaves this computer)')}`, value: 'offline' },
      { label: `Scanner ${auditName(s.pm)}: ${onoff(s.cfg.scanners['npm-audit'])}`, value: 'npm-audit' },
      { label: `Scanner gitleaks: ${onoff(s.cfg.scanners.gitleaks)}`, value: 'gitleaks' },
      { label: `Scanner semgrep: ${onoff(s.cfg.scanners.semgrep)}`, value: 'semgrep' },
      { label: `Semgrep rules: ${s.cfg.semgrepConfigs.join(', ')}`, value: 'rules' },
      { label: `Semgrep skips test and mock files: ${onoff(s.cfg.semgrepSkipTests !== false)}  ${c.gray('(much faster; gitleaks still checks them)')}`, value: 'tests' },
      { label: 'Run setup again (detect stack, install tools)', value: 'setup' },
      { label: 'Reset to defaults', value: 'reset' },
      { label: 'Back', value: null },
    ]);
    if (!pick) return;
    if (pick === 'sev') {
      const v = await select('Show findings of at least this severity', SEVERITY_ORDER.map((x) => ({ label: x, value: x })));
      if (v) s.cfg.minSeverity = v;
    } else if (pick === 'offline') {
      s.cfg.offline = !s.cfg.offline;
    } else if (pick === 'tests') {
      s.cfg.semgrepSkipTests = s.cfg.semgrepSkipTests === false;
    } else if (pick === 'rules') {
      console.log(c.gray('\nRegistry rulesets (like p/javascript) or local rule files (like ./rules.yml).'));
      console.log(c.gray('In offline mode only local files are used.'));
      const v = await ask('Comma-separated list (empty = keep current): ');
      if (v) s.cfg.semgrepConfigs = v.split(',').map((x) => x.trim()).filter(Boolean);
    } else if (pick === 'setup') {
      await setupScreen(s);
      continue;
    } else if (pick === 'reset') {
      if (!(await confirm('Reset all settings?'))) continue;
      s.cfg = structuredClone(DEFAULT_CONFIG);
    } else {
      s.cfg.scanners[pick] = !s.cfg.scanners[pick];
    }
    saveConfig(s.dir, s.cfg);
    s.stale = true;
  }
}

// ------------------------------------------------------------------ setup

const STEPS = 3;
const stepTitle = (n, title) => console.log(`${c.gray(`Step ${n} of ${STEPS}`)}  ${c.bold(title)}\n`);
const listOr = (xs, none = c.gray('none detected')) => (xs.length ? xs.join(', ') : none);

function printProject(p) {
  const row = (k, v) => console.log(`  ${c.gray(k.padEnd(12))}${v}`);
  row('Project', p.hasPackageJson ? `${c.bold(p.name)} ${c.gray(`(${p.depCount} dependencies)`)}` : c.yellow('no package.json'));
  row('Language', p.typescript ? 'TypeScript' : 'JavaScript');
  row('Frameworks', listOr(p.frameworks));
  if (p.databases.length) row('Databases', p.databases.join(', '));
  if (p.auth.length) row('Auth', p.auth.join(', '));
  const extras = [p.docker && 'Docker', p.workflows && `GitHub Actions (${p.workflows} workflow${p.workflows > 1 ? 's' : ''})`].filter(Boolean);
  if (extras.length) row('Also', extras.join(', '));
  const LOCK_ROWS = {
    npm: `${c.green('✔')} package-lock.json`,
    yarn: `${c.green('✔')} yarn.lock ${c.gray('(Yarn 1, checked with yarn audit)')}`,
    'yarn-berry': c.yellow('⚠ yarn.lock from Yarn 2+: not supported yet, so dependencies are not checked'),
    pnpm: c.yellow('⚠ pnpm-lock.yaml: not supported yet, so dependencies are not checked'),
  };
  row('Lockfile', LOCK_ROWS[p.lockfile]
    ?? c.yellow('⚠ none: the dependency audit needs one (npm install --package-lock-only --ignore-scripts, or yarn install)'));
  row('Git', p.git ? `${c.green('✔')} repository` : c.yellow('⚠ not a git repository: automatic fixes need one (git init)'));
  for (const e of p.envFiles) {
    row('Secrets', e.ignored === false
      ? c.red(`✖ ${e.file} is NOT ignored by git: it could be committed with your secrets`)
      : `${c.green('✔')} ${e.file} ${c.gray(e.ignored ? 'is ignored by git' : 'found')}`);
  }
  console.log();
}

function recommendTools(p) {
  const envNote = p.envFiles.length ? ` You have ${p.envFiles.map((e) => e.file).join(', ')}.` : '';
  const stack = [p.typescript ? 'TypeScript' : 'JavaScript', ...p.frameworks].join(' / ');
  return [
    { t: tool(p.lockfile === 'yarn' ? 'yarn' : 'npm'), level: 'required', reason: `Checks your ${p.depCount} dependencies for known vulnerabilities.` },
    { t: tool('git'), level: 'recommended', reason: 'Lets Gnawky make fixes on a separate branch you can throw away.' },
    { t: tool('gitleaks'), level: 'recommended', reason: `Finds API keys, passwords and tokens in your files and git history.${envNote}` },
    { t: tool('semgrep'), level: 'recommended', reason: `Finds risky code (injection, XSS, unsafe eval) with rules for ${stack}.` },
    { t: tool('claude'), level: 'optional', reason: 'Explains findings in plain language and proposes fixes ("Ask Claude").' },
  ];
}

/** Offers to install one missing tool. Returns true if it is installed afterwards. */
async function offerInstall(t) {
  const cmd = installCommand(t);
  if (!cmd) {
    console.log(`    ${c.gray('install it yourself:')} ${t.hint}`);
    return false;
  }
  const choice = await select(`Install ${t.cmd}?`, [
    { label: `Install now  ${c.gray(`(${cmd[0]} ${cmd[1].join(' ')})`)}`, value: 'install' },
    { label: 'Skip', value: 'skip' },
  ]);
  if (choice !== 'install') return false;
  console.log(c.gray(`\n$ ${cmd[0]} ${cmd[1].join(' ')}`));
  const ok = installTool(t);
  console.log(ok
    ? c.green(`\n✔ ${t.cmd} installed: ${toolVersion(t.cmd)}\n`)
    : c.red(`\n✖ ${t.cmd} is still not available. If the install succeeded, open a new terminal and start Gnawky again.\n`));
  return ok;
}

/** First-run setup: detect the stack, recommend and install tools, pick semgrep rules, first scan. */
async function setupScreen(s, { firstRun = false } = {}) {
  header(s, { logo: true });
  console.log(c.bold(firstRun ? 'Welcome to Gnawky!' : 'Setup') + '\n');
  console.log(`Let's set Gnawky up for ${c.bold(s.pkg?.name ?? path.basename(s.dir))}. It takes about a minute:\n`);
  console.log(`  1. Look at your project to see which technologies it uses`);
  console.log(c.gray('     (reads package.json and file names only; nothing leaves this computer)'));
  console.log('  2. Recommend the scanners that fit it, and install the ones you want');
  console.log('  3. Run your first security scan');
  console.log(c.gray('\n  Scanning is read-only: nothing in your project changes unless you approve a fix.\n'));
  const start = await select('Ready?', [
    { label: 'Start setup', value: 'start' },
    { label: 'Skip setup (you can run it later from Settings)', value: 'skip' },
  ]);
  if (start === null) return; // back: ask again next time
  if (start === 'skip') {
    saveConfig(s.dir, s.cfg);
    return;
  }

  // Step 1: the project
  header(s, { logo: true });
  stepTitle(1, 'Your project');
  const p = detectProject(s.dir);
  printProject(p);
  await pause();

  // Step 2: tools
  header(s, { logo: true });
  stepTitle(2, 'Recommended tools');
  const recs = recommendTools(p).map((r) => ({ ...r, version: toolVersion(r.t.cmd) }));
  for (const { t, level, reason, version } of recs) {
    const icon = version ? c.green('✔') : level === 'optional' ? c.gray('–') : c.red('✖');
    const tag = level === 'optional' ? c.gray('optional') : level === 'required' ? c.gray('required') : c.accent('recommended');
    console.log(`  ${icon} ${c.bold(t.cmd.padEnd(9))} ${version ? c.gray(version) : c.yellow('not installed')}  ${tag}`);
    console.log(`      ${c.gray(reason)}`);
  }
  console.log();
  const missing = recs.filter((r) => !r.version && r.level !== 'required');
  if (!missing.length) {
    console.log(c.green('All set: every tool is installed.\n'));
    await pause();
  } else {
    if (process.platform === 'darwin' && !isAvailable('brew')) {
      console.log(c.gray('Tip: with Homebrew (https://brew.sh) Gnawky can install these for you.\n'));
    }
    for (const { t } of missing) {
      console.log(`${c.bold(t.cmd)}: ${c.gray(t.why)}`);
      await offerInstall(t);
      console.log();
    }
    await pause();
  }

  // Step 3: rules and first scan
  s.cfg.semgrepConfigs = semgrepRulesFor(p);
  saveConfig(s.dir, s.cfg);
  header(s, { logo: true });
  stepTitle(3, 'First scan');
  console.log(`Settings saved in ${c.bold(`${OUT_DIR}/config.json`)} ${c.gray('(the folder is ignored by git)')}:`);
  console.log(`  ${c.gray('Semgrep rules'.padEnd(15))}${s.cfg.semgrepConfigs.join(', ')}`);
  console.log(`  ${c.gray('Min. severity'.padEnd(15))}${s.cfg.minSeverity}`);
  console.log(c.gray('  You can change these any time in Settings.\n'));
  const scan = await select('Run your first scan now?', [
    { label: 'Scan now', value: true },
    { label: 'Later, go to the menu', value: false },
  ]);
  if (scan) await scanScreen(s);
}

async function doctorScreen(s) {
  for (;;) {
    header(s);
    console.log(c.bold('Installed tools\n'));
    console.log(`  ${c.green('✔')} ${'node'.padEnd(9)} ${process.version}`);
    const missing = [];
    for (const t of TOOLS.filter((x) => !x.onlyFor || x.onlyFor === s.pm)) {
      const version = toolVersion(t.cmd);
      if (version) {
        console.log(`  ${c.green('✔')} ${t.cmd.padEnd(9)} ${version}  ${c.gray(t.why)}`);
      } else {
        missing.push(t);
        console.log(`  ${c.red('✖')} ${t.cmd.padEnd(9)} ${c.gray(t.why)}`);
        console.log(`    ${c.gray('install:')} ${installCommand(t) ? installCommand(t).flat().join(' ') : t.hint}`);
      }
    }
    if (!s.pm) console.log(c.yellow('\n  ⚠ No lockfile: the dependency audit needs one (npm install --package-lock-only --ignore-scripts, or yarn install).'));
    else if (!['npm', 'yarn'].includes(s.pm)) console.log(c.yellow(`\n  ⚠ ${s.pm === 'pnpm' ? 'pnpm' : 'Yarn 2+'} lockfiles are not supported yet, so dependencies are not checked.`));
    console.log();
    const installable = missing.filter((t) => installCommand(t));
    const pick = await select('Install a missing tool?', [
      ...installable.map((t) => ({ label: `Install ${t.cmd}  ${c.gray(`(${installCommand(t).flat().join(' ')})`)}`, value: t })),
      { label: 'Back', value: null },
    ]);
    if (!pick) return;
    console.log(c.gray(`\n$ ${installCommand(pick).flat().join(' ')}`));
    const ok = installTool(pick);
    console.log(ok ? c.green(`\n✔ ${pick.cmd} installed.`) : c.red(`\n✖ ${pick.cmd} is still not available.`));
    await pause();
  }
}

const SCREENS = {
  scan: scanScreen, view: viewScreen, review: (s) => reviewScreen(s), reviewClaude: (s) => reviewScreen(s, { claudeOrder: true }),
  claude: (s) => claudeScreen(s, null), triage: triageScreen, audit: auditScreen,
  ignored: ignoredScreen, report: reportScreen, settings: settingsScreen, doctor: doctorScreen,
  findings: findingsMenu, ai: aiMenu,
};

/**
 * A submenu that runs the chosen screen and comes back to itself (cursor on the
 * same item) until q/Esc or "Back". `build` is called on every pass so counts and
 * disabled states follow what the screens changed.
 */
async function submenu(s, build) {
  let last = null;
  for (;;) {
    const { title, note, options } = build();
    header(s);
    if (note) console.log(c.yellow(`${note}\n`));
    const initial = Math.max(0, options.findIndex((o) => o.value === last));
    const choice = await select(title, options, { initial, footer: [{ label: '← Back', value: 'back' }] });
    if (choice === null || choice === 'back') return;
    last = choice;
    await SCREENS[choice](s);
  }
}

function findingsMenu(s) {
  return submenu(s, () => {
    const n = s.result?.findings.length ?? 0;
    const ignored = safeIgnores(s.dir).length;
    const hasTriage = n > 0 && s.result.findings.some((f) => s.triage.entries[f.fingerprint]);
    return {
      title: `Findings (${n} open${ignored ? `, ${ignored} ignored` : ''})`,
      note: s.result ? null : 'No scan yet. Run a scan from the main menu to see findings.',
      options: [
        { label: `Review & fix${n ? ` (${n})` : ''}`, value: 'review', disabled: !n },
        ...(hasTriage ? [{ label: "Review & fix in Claude's order", value: 'reviewClaude' }] : []),
        { label: 'Browse findings', value: 'view', disabled: !s.result },
        { label: `Ignored findings${ignored ? ` (${ignored})` : ''}`, value: 'ignored' },
      ],
    };
  });
}

function aiMenu(s) {
  return submenu(s, () => {
    const n = s.result?.findings.length ?? 0;
    const blocked = s.cfg.offline ? 'Offline mode is on, so the AI tools are turned off (change it in Settings).'
      : !isAvailable('claude') ? 'Claude Code is not installed. Install it with: npm install -g @anthropic-ai/claude-code'
      : null;
    const note = blocked ?? (!s.result ? 'No scan yet. Run a scan from the main menu first.'
      : IS_WIN ? 'Triage is not supported on Windows yet.' : null);
    return {
      title: 'AI tools (Claude Code)',
      note,
      options: [
        { label: `Triage findings${triaged(s)}`, value: 'triage', disabled: !!blocked || !n || IS_WIN },
        { label: 'Run a full security audit', value: 'audit', disabled: !!blocked || !s.result },
        { label: 'Ask Claude for help', value: 'claude', disabled: !!blocked || !s.result },
      ],
    };
  });
}

// ------------------------------------------------------------------ main loop

export async function startApp(dir) {
  const s = {
    dir, cfg: loadConfig(dir), result: loadLastScan(dir), triage: loadTriage(dir), pkg: readPkg(dir), pm: packageManager(dir), stale: false,
  };
  try {
    if (!s.pkg) {
      header(s);
      console.log(c.yellow('There is no package.json in this folder.'));
      console.log('Gnawky is meant to be started inside the Node.js project you want to scan.\n');
      if (!(await confirm('Continue anyway?'))) return;
    }
    if (!configExists(dir)) await setupScreen(s, { firstRun: true });
    for (;;) {
      const n = s.result?.findings.length ?? 0;
      const ignored = safeIgnores(dir).length;
      const options = [
        { label: s.result ? 'Scan again' : 'Run security scan', value: 'scan' },
        { label: `Findings${s.result ? ` (${n})` : ''}`, value: 'findings', disabled: !s.result && !ignored },
        { label: 'AI tools', value: 'ai' },
        { label: 'View report', value: 'report', disabled: !s.result },
        { label: 'Settings', value: 'settings' },
        { label: 'Tools & scanners', value: 'doctor' },
      ];
      const footer = [{ label: 'Quit', value: 'quit' }];
      // The menu takes its options plus a title, a blank line, the footer, a help line and the cursor line.
      header(s, { logo: true, below: options.length + 5 });
      const choice = await select('What would you like to do?', options, { footer });
      if (choice === null || choice === 'quit') break;
      await SCREENS[choice](s);
    }
  } catch (e) {
    if (e.code !== 'ABORT_ERR') throw e;
  }
  clear();
  console.log('Gnawky closed. Reports are in .gnawky/');
}

