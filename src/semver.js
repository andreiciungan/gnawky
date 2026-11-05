// A small subset of node-semver, enough to reason about advisory ranges and the
// ranges in yarn.lock: versions, comparators, ^ ~ x-ranges, hyphen ranges and ||.
// Prerelease versions only match comparators on the same major.minor.patch, like npm.

const VERSION = /^\s*v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$/;

export function parse(v) {
  const m = VERSION.exec(String(v));
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ? m[4].split('.') : [] };
}

export const valid = (v) => parse(v) !== null;

function comparePre(a, b) {
  if (!a.length || !b.length) return (b.length ? 1 : 0) - (a.length ? 1 : 0);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] === undefined) return -1;
    if (b[i] === undefined) return 1;
    const na = /^\d+$/.test(a[i]);
    const nb = /^\d+$/.test(b[i]);
    if (na && nb && +a[i] !== +b[i]) return +a[i] < +b[i] ? -1 : 1;
    if (na !== nb) return na ? -1 : 1;
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

export function compare(a, b) {
  const x = typeof a === 'string' ? parse(a) : a;
  const y = typeof b === 'string' ? parse(b) : b;
  for (const k of ['major', 'minor', 'patch']) if (x[k] !== y[k]) return x[k] < y[k] ? -1 : 1;
  return comparePre(x.pre, y.pre);
}

export const major = (v) => parse(v)?.major ?? null;

/** True if going from `from` to `to` is a breaking change by semver rules (0.x minors count as breaking). */
export function isBreaking(from, to) {
  const a = parse(from);
  const b = parse(to);
  if (!a || !b) return true;
  if (a.major !== b.major) return true;
  return a.major === 0 && a.minor !== b.minor;
}

// ---- ranges -------------------------------------------------------------

const PARTIAL = /^v?(\d+|[xX*])?(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;
const isX = (p) => p === undefined || /^[xX*]$/.test(p);

function partial(s) {
  const m = PARTIAL.exec(s);
  if (!m) return null;
  const [, M, m2, p, pre] = m;
  return { M: isX(M) ? null : +M, m: isX(m2) ? null : +m2, p: isX(p) ? null : +p, pre: pre ?? '' };
}

const ver = (M, m, p, pre = '') => `${M}.${m}.${p}${pre ? `-${pre}` : ''}`;

/** Turns one range token (with its operator) into plain comparators [op, version]. */
function desugar(op, s) {
  const v = partial(s);
  if (!v) return null;
  const { M, m, p, pre } = v;
  if (M === null) return op === '<' || op === '>' ? [['<', '0.0.0-0']] : [];
  if (op === '^') {
    const lo = ['>=', ver(M, m ?? 0, p ?? 0, pre)];
    if (M > 0 || m === null) return [lo, ['<', `${M + 1}.0.0-0`]];
    if (m > 0 || p === null) return [lo, ['<', `0.${m + 1}.0-0`]];
    return [lo, ['<', `0.0.${p + 1}-0`]];
  }
  if (op === '~') {
    const lo = ['>=', ver(M, m ?? 0, p ?? 0, pre)];
    return m === null ? [lo, ['<', `${M + 1}.0.0-0`]] : [lo, ['<', `${M}.${m + 1}.0-0`]];
  }
  if (m === null || p === null) {
    // x-range: 1.x, 1.2, >=1.2, <1, ...
    const lo = ver(M, m ?? 0, 0);
    const hi = m === null ? `${M + 1}.0.0-0` : `${M}.${m + 1}.0-0`;
    if (op === '' || op === '=') return [['>=', lo], ['<', hi]];
    if (op === '>=') return [['>=', lo]];
    if (op === '<') return [['<', `${lo}-0`]];
    if (op === '>') return [['>=', hi]];
    if (op === '<=') return [['<', hi]];
  }
  return [[op || '=', ver(M, m, p, pre)]];
}

function parseSet(set) {
  set = set.trim();
  const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(set);
  if (hyphen) {
    const lo = desugar('>=', hyphen[1]);
    const hiP = partial(hyphen[2]);
    if (!lo || !hiP) return null;
    const hi = hiP.M === null ? [] : hiP.m === null ? [['<', `${hiP.M + 1}.0.0-0`]]
      : hiP.p === null ? [['<', `${hiP.M}.${hiP.m + 1}.0-0`]] : [['<=', ver(hiP.M, hiP.m, hiP.p, hiP.pre)]];
    return [...lo, ...hi];
  }
  const tokens = set.replace(/(>=|<=|>|<|=|\^|~)\s+/g, '$1').split(/\s+/).filter(Boolean);
  const out = [];
  for (const t of tokens) {
    const m = /^(>=|<=|>|<|=|\^|~>?)?(.*)$/.exec(t);
    const c = desugar((m[1] ?? '').replace('~>', '~'), m[2]);
    if (!c) return null;
    out.push(...c);
  }
  return out;
}

/** Parses a range into a list of comparator sets, or null if it is not a semver range (git URL, tag, ...). */
export function parseRange(range) {
  const sets = String(range).split('||').map(parseSet);
  return sets.some((s) => s === null) ? null : sets;
}

function test(v, [op, target]) {
  const c = compare(v, target);
  return op === '<' ? c < 0 : op === '<=' ? c <= 0 : op === '>' ? c > 0 : op === '>=' ? c >= 0 : c === 0;
}

function testSet(v, set) {
  if (!set.every((c) => test(v, c))) return false;
  if (!v.pre.length) return true;
  // A prerelease only matches when a comparator names the same version with a prerelease.
  return set.some(([, t]) => {
    const p = parse(t);
    return p.pre.length && p.pre[0] !== '0' && p.major === v.major && p.minor === v.minor && p.patch === v.patch;
  });
}

export function satisfies(version, range) {
  const v = parse(version);
  const sets = parseRange(range);
  if (!v || !sets) return false;
  return sets.some((set) => testSet(v, set));
}

/**
 * Release versions an advisory's "patched_versions" range starts at, lowest first.
 * Advisories write it as ">=1.2.3", ">=1.2.3 <2.0.0 || >=2.1.0", or "<0.0.0" for "no fix".
 */
export function patchedCandidates(range) {
  const sets = parseRange(range);
  if (!sets) return [];
  const found = [];
  for (const set of sets) {
    const lows = set.filter(([op]) => op === '>=' || op === '=').map(([, v]) => v);
    for (const v of lows.length ? lows : ['0.0.0']) {
      const p = parse(v);
      if (p.pre.length) continue;
      if (satisfies(v, range)) found.push(v);
    }
  }
  return [...new Set(found)].sort(compare);
}
