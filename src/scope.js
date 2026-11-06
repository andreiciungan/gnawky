import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { OUT_DIR } from './config.js';

// Audit scope: which profile the security-audit skill runs, and on which folders.
//
// A selection is a Set of keys:
//   'src/api'  a folder and everything under it
//   'src/*'    only the files directly in src/ (not its subfolders)
//   '*'        only the files directly in the project root

export const PROFILES = {
  quick: 'one hunting pass, then a coverage check. Cheapest.',
  standard: 'the full workflow: hunting waves until coverage is clean.',
  deep: 'per-subsystem passes, a second independent check. Most thorough and costly.',
};

export const SCOPE_MODES = {
  quick: { label: 'Quick', profile: 'quick' },
  full: { label: 'Full', profile: 'standard' },
};

const SKIP_DIRS = new Set(['node_modules', '.git', OUT_DIR]);

/** Project files, relative to dir: tracked plus untracked-but-not-ignored when it is a git repo. */
export function projectFiles(dir) {
  const r = spawnSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
    cwd: dir, encoding: 'utf8', maxBuffer: 512 * 1024 * 1024,
  });
  if (r.status === 0) {
    return r.stdout.split('\0').filter((f) => f && !f.split('/').some((p) => SKIP_DIRS.has(p)) && fs.existsSync(path.join(dir, f)));
  }
  const out = [];
  const walk = (rel) => {
    let entries = [];
    try { entries = fs.readdirSync(path.join(dir, rel), { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(p); } else if (e.isFile()) out.push(p);
    }
  };
  walk('');
  return out;
}

/** Folder tree with file counts. Node: { path, name, files (direct), total, children: Map }. */
export function buildTree(files) {
  const node = (p) => ({ path: p, name: p.split('/').pop(), files: 0, total: 0, children: new Map() });
  const root = node('');
  const byPath = new Map([['', root]]);
  for (const f of files) {
    const parts = f.split('/');
    let cur = root;
    cur.total++;
    for (let i = 0; i < parts.length - 1; i++) {
      const p = parts.slice(0, i + 1).join('/');
      let next = cur.children.get(parts[i]);
      if (!next) {
        next = node(p);
        cur.children.set(parts[i], next);
        byPath.set(p, next);
      }
      next.total++;
      cur = next;
    }
    cur.files++;
  }
  return { root, byPath };
}

export const filesKey = (folder) => (folder ? `${folder}/*` : '*');
const isFilesKey = (k) => k === '*' || k.endsWith('/*');
const folderOf = (k) => (k === '*' ? '' : isFilesKey(k) ? k.slice(0, -2) : k);
const parentOf = (k) => (isFilesKey(k) ? folderOf(k) : k.includes('/') ? k.slice(0, k.lastIndexOf('/')) : '');
const under = (k, folder) => folder === '' || k.startsWith(`${folder}/`);

/** The selectable items inside a folder node: its direct files (if it also has subfolders), then subfolders A-Z. */
export function itemsOf(node) {
  const kids = [...node.children.values()].sort((a, b) => a.name.localeCompare(b.name));
  const items = kids.map((n) => ({ key: n.path, node: n, count: n.total }));
  if (node.files && (kids.length || node.path === '')) items.unshift({ key: filesKey(node.path), node: null, count: node.files });
  return items;
}

const ancestors = (k) => {
  const out = [];
  for (let p = parentOf(k); p; p = parentOf(p)) out.push(p);
  return out;
};

/** 'on' (selected itself or through a parent folder), 'partial' (something inside is) or 'off'. */
export function stateOf(sel, key) {
  if (sel.has(key) || ancestors(key).some((a) => sel.has(a))) return 'on';
  if (!isFilesKey(key) && [...sel].some((k) => under(k, key))) return 'partial';
  return 'off';
}

/** Toggles one item, keeping the selection minimal (no key inside a selected folder). */
export function toggle(sel, tree, key) {
  if (sel.has(key)) {
    sel.delete(key);
  } else {
    const covering = ancestors(key).find((a) => sel.has(a));
    if (covering) {
      // Deselecting something inside a selected folder: select its siblings instead, level by level.
      sel.delete(covering);
      let cur = covering;
      while (cur !== key) {
        let next = null;
        for (const it of itemsOf(tree.byPath.get(cur))) {
          if (it.key === key || (!isFilesKey(it.key) && under(key, it.key))) next = it.key;
          else sel.add(it.key);
        }
        cur = next;
      }
    } else {
      if (!isFilesKey(key)) for (const k of [...sel]) if (under(k, key)) sel.delete(k);
      sel.add(key);
      // Every item of a folder selected: select the folder instead (not at the root).
      for (let p = parentOf(key); p; p = parentOf(p)) {
        const items = itemsOf(tree.byPath.get(p));
        if (!items.every((it) => sel.has(it.key))) break;
        for (const it of items) sel.delete(it.key);
        sel.add(p);
      }
    }
  }
}

const countOf = (tree, k) => (isFilesKey(k) ? tree.byPath.get(folderOf(k))?.files ?? 0 : tree.byPath.get(k)?.total ?? 0);

export const selectedCount = (tree, sel) => [...sel].reduce((n, k) => n + countOf(tree, k), 0);

/** Drops saved keys that no longer exist in the project. */
export function validKeys(tree, keys) {
  return (Array.isArray(keys) ? keys : []).filter((k) => typeof k === 'string' && countOf(tree, k) > 0);
}

/** How a key reads in the task for Claude and on screen. */
export function describeKey(k) {
  if (k === '*') return 'the files directly in the project root (not its subfolders)';
  if (isFilesKey(k)) return `the files directly in ${folderOf(k)}/ (not its subfolders)`;
  return `${k}/`;
}

export const shortKey = (k) => (k === '*' ? '(root files)' : isFilesKey(k) ? `${folderOf(k)}/ (files only)` : `${k}/`);

/** One-line summary of a scope, e.g. "custom · quick · server/, utils/ · max 20 agents". */
export function scopeSummary(scope) {
  if (!scope) return null;
  const where = scope.paths?.length ? scope.paths.map(shortKey).join(', ') : 'whole project';
  return [scope.mode, scope.mode === 'custom' && scope.profile, where, scope.budget && `max ${scope.budget} agents`].filter(Boolean).join(' · ');
}
