import readline from 'node:readline';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const wrap = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));

export const c = {
  bold: wrap('1'), dim: wrap('2'), red: wrap('31'), green: wrap('32'), yellow: wrap('33'),
  blue: wrap('34'), cyan: wrap('36'), gray: wrap('90'), inverse: wrap('7'),
  // Brand purple (256-color 141, #af87ff), matching the logo.
  accent: wrap('38;5;141'),
};

const SEV_COLOR = { critical: (s) => c.bold(c.red(s)), high: c.red, medium: c.yellow, low: c.blue, info: c.gray };
export const sevTag = (sev) => (SEV_COLOR[sev] ?? String)(sev.toUpperCase().padEnd(8));

const ANSI = /\x1b\[[0-9;]*m/g;
const visibleLen = (s) => s.replace(ANSI, '').length;
/** Terminal rows the lines take up, counting lines that wrap. */
const screenRows = (lines) => {
  const width = process.stdout.columns || 80;
  return lines.reduce((n, l) => n + Math.max(1, Math.ceil(visibleLen(l) / width)), 0);
};

export function truncate(s, max) {
  if (visibleLen(s) <= max) return s;
  return s.replace(ANSI, '').slice(0, Math.max(1, max - 1)) + '…';
}

/** 75 → "1m 15s", 9 → "9s". */
export function fmtDuration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}

/**
 * A progress line with a running clock, so a slow scanner visibly keeps working:
 *   ⠼ running semgrep on 2,620 JS/TS file(s) (2 ruleset(s))… 4m 12s
 * Returns done(text, kind) that replaces it with a final ✔ / – / ✖ line.
 * Without a terminal (CI, piped output) it prints one line at the start and one at the end.
 */
export function ticker(label, stream = process.stdout) {
  const started = Date.now();
  const elapsed = () => fmtDuration((Date.now() - started) / 1000);
  const icon = { ok: c.green('✔'), skip: c.yellow('–'), fail: c.red('✖') };
  if (!stream.isTTY) {
    stream.write(`  ${label}…\n`);
    return (text, kind = 'ok') => stream.write(`  ${kind === 'ok' ? '✔' : kind === 'skip' ? '–' : '✖'} ${text} (${elapsed()})\n`);
  }
  const frames = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏';
  let i = 0;
  const width = () => (stream.columns || 80) - 1;
  const draw = () => {
    const clock = elapsed();
    const line = truncate(`  ${frames[i++ % frames.length]} ${label}…`, width() - clock.length - 1);
    stream.write(`\r\x1b[2K${c.accent(line)} ${c.gray(clock)}`);
  };
  draw();
  const timer = setInterval(draw, 250);
  return (text, kind = 'ok') => {
    clearInterval(timer);
    stream.write(`\r\x1b[2K  ${icon[kind] ?? icon.ok} ${text} ${c.gray(`(${elapsed()})`)}\n`);
  };
}

export function clear() {
  if (process.stdout.isTTY) process.stdout.write('\x1b[2J\x1b[3J\x1b[H');
}

const abortError = () => Object.assign(new Error('aborted'), { code: 'ABORT_ERR' });

/** Free-text question. Ctrl+C / Ctrl+D rejects with ABORT_ERR. */
export function ask(question) {
  return new Promise((resolve, reject) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    let answered = false;
    rl.on('SIGINT', () => rl.close());
    rl.on('close', () => { if (!answered) reject(abortError()); });
    rl.question(question, (a) => { answered = true; rl.close(); resolve(a.trim()); });
  });
}

export async function confirm(question) {
  return (await ask(`${question} ${c.gray('[y/N]')} `)).toLowerCase() === 'y';
}

export async function pause() {
  await ask(c.gray('\nPress Enter to continue…'));
}

/**
 * Arrow-key menu. options: [{ label, value, disabled }], or { static: label } for a
 * row that is only shown (a blank line with ''), never selected.
 * Resolves with the chosen value, or null for q / Esc (= back).
 * Options may carry their own `number` (e.g. 10-18 on page 2 of a list); typing it
 * moves the cursor there and Enter selects, instead of the default 1-9 instant pick.
 * opts.initial: index to start on. opts.keys: { keyName: value } extra shortcuts
 * (e.g. { left: 'prev' }), shown with opts.hint in the help line.
 * opts.footer: [{ label, value }] shown unnumbered on one line after a blank line
 * (e.g. Settings · Quit); ↓ from the last option moves into it, ←/→ moves along it.
 */
export function select(title, options, { initial = null, keys = {}, hint = '', footer = [] } = {}) {
  return new Promise((resolve, reject) => {
    const input = process.stdin;
    const cols = () => (process.stdout.columns || 80) - 4;
    const maxVisible = () => Math.max(5, (process.stdout.rows || 24) - 10);
    options = options.map((o) => ('static' in o ? { ...o, disabled: true } : o));
    let idx = initial !== null && options[initial] && !options[initial].disabled
      ? initial
      : Math.max(0, options.findIndex((o) => !o.disabled));
    let drawn = 0;
    // Removes the menu from the screen: before a redraw, and once a choice is made, so the
    // next screen or submenu doesn't appear below a stale copy of this one.
    const erase = () => {
      if (drawn) process.stdout.write(`\x1b[${drawn}A\x1b[0J`);
      drawn = 0;
    };
    // idx >= options.length points into the footer.
    const inFooter = () => idx >= options.length;
    const numbered = options.some((o) => Number.isInteger(o.number));
    // Without explicit numbers every option is numbered 1..n and typing its number picks it.
    const autoNum = (i) => ('static' in options[i] ? null : i + 1);
    const numWidth = numbered
      ? String(Math.max(...options.map((o) => o.number ?? 0))).length + 1
      : String(options.length).length + 1;
    let typed = '';
    let typedAt = 0;
    let pickTimer = null;

    const render = () => {
      erase();
      const lines = [c.bold(truncate(title, cols()))];
      const n = options.length;
      const size = Math.min(n, maxVisible());
      const start = Math.min(Math.max(0, idx - Math.floor(size / 2)), n - size);
      if (start > 0) lines.push(c.gray('    ↑ more'));
      for (let i = start; i < start + size; i++) {
        const o = options[i];
        if ('static' in o) {
          lines.push(o.static ? `${' '.repeat(numWidth + 3)}${truncate(o.static, cols())}` : '');
          continue;
        }
        const n = numbered ? o.number : autoNum(i);
        const num = (Number.isInteger(n) ? `${n}.` : '').padStart(numWidth);
        let label = truncate(`${num} ${o.label}`, cols());
        if (o.disabled) label = c.gray(label.replace(ANSI, ''));
        else if (i === idx) label = c.accent(label);
        lines.push(`${i === idx ? c.accent('❯') : ' '} ${label}`);
      }
      if (start + size < n) lines.push(c.gray('    ↓ more'));
      if (footer.length) {
        const pad = ' '.repeat(numWidth + 1);
        const parts = footer.map((f, j) => (idx === options.length + j ? `${c.accent('❯')} ${c.accent(f.label)}` : `  ${f.label}`));
        lines.push('', truncate(`${pad}${parts.join('    ')}`, cols() + 2));
      }
      lines.push(c.gray(truncate(`↑/↓${footer.length ? '/←/→' : ''} move · Enter select · ${numbered ? 'type a number to jump' : 'number to pick'}${hint ? ` · ${hint}` : ''} · q/Esc back`, cols() + 2)));
      process.stdout.write(lines.join('\n') + '\n');
      drawn = screenRows(lines);
    };

    const lastEnabled = () => {
      for (let i = options.length - 1; i >= 0; i--) if (!options[i].disabled) return i;
      return idx;
    };
    const move = (d) => {
      if (footer.length && inFooter()) {
        // ↑ leaves the footer for the last option, ↓ wraps to the top.
        if (d < 0) idx = lastEnabled();
        else { idx = -1; move(1); }
        return;
      }
      if (footer.length && d > 0 && idx === lastEnabled()) { idx = options.length; return; }
      if (footer.length && d < 0 && idx === options.findIndex((o) => !o.disabled)) { idx = options.length; return; }
      let i = idx;
      for (let k = 0; k < options.length; k++) {
        i = (i + d + options.length) % options.length;
        if (!options[i].disabled) { idx = i; return; }
      }
    };

    const finish = (value, err) => {
      clearTimeout(pickTimer);
      erase();
      input.removeListener('keypress', onKey);
      if (input.isTTY) input.setRawMode(false);
      input.pause();
      err ? reject(err) : resolve(value);
    };

    const onKey = (str, key = {}) => {
      if (key.ctrl && (key.name === 'c' || key.name === 'd')) return finish(null, abortError());
      if (key.name === 'up' || key.name === 'k') move(-1);
      else if (key.name === 'down' || key.name === 'j') move(1);
      else if (key.name === 'return' || key.name === 'enter') return finish(inFooter() ? footer[idx - options.length].value : options[idx]?.value ?? null);
      else if (key.name === 'escape' || str === 'q') return finish(null);
      else if (inFooter() && (key.name === 'left' || key.name === 'right')) {
        const j = idx - options.length + (key.name === 'left' ? -1 : 1);
        idx = options.length + ((j + footer.length) % footer.length);
      }
      else if (key.name && Object.hasOwn(keys, key.name)) return finish(keys[key.name]);
      else if (numbered && /^[0-9]$/.test(str ?? '')) {
        // Digits typed within a second build one number (1, then 2 → 12).
        typed = Date.now() - typedAt < 1000 ? typed + str : str;
        typedAt = Date.now();
        let i = options.findIndex((o) => o.number === Number(typed));
        if (i === -1) {
          typed = str;
          i = options.findIndex((o) => o.number === Number(typed));
        }
        if (i === -1 || options[i].disabled) return;
        idx = i;
      } else if (!numbered && /^[0-9]$/.test(str ?? '')) {
        // Picks as soon as the number is unambiguous: with 11 options, 2-9 pick at once,
        // while 1 waits briefly for a second digit (10, 11) and then picks option 1.
        clearTimeout(pickTimer);
        typed = Date.now() - typedAt < 1000 ? typed + str : str;
        typedAt = Date.now();
        let i = Number(typed) - 1;
        if (!options[i]) {
          typed = str;
          i = Number(typed) - 1;
        }
        const o = options[i];
        if (!o || o.disabled) return;
        const longer = options.some((_, j) => autoNum(j) && String(autoNum(j)).startsWith(typed) && autoNum(j) !== Number(typed));
        if (!longer) return finish(o.value);
        idx = i;
        pickTimer = setTimeout(() => finish(o.value), 700);
      } else return;
      render();
    };

    readline.emitKeypressEvents(input);
    if (input.isTTY) input.setRawMode(true);
    input.resume();
    input.on('keypress', onKey);
    render();
  });
}

/**
 * Checkbox list that can open folders. The caller owns the state through `view`:
 *   view.title()        heading (re-read on every render, so it can show counts)
 *   view.items()        [{ label, state: 'on' | 'off' | 'partial', openable }], or { heading } for a
 *                       row that is only shown (the cursor skips it)
 *   view.toggle(i)      Space
 *   view.open(i)        optional, → / l: returns true when it moved into item i
 *   view.up()           optional, ← / h / Backspace: the index to put the cursor on, or null at the top
 *   view.cursor         optional; where the cursor starts, and kept up to date
 * Resolves 'done' on Enter, or null for q / Esc (= back).
 */
export function checklist(view) {
  return new Promise((resolve, reject) => {
    const input = process.stdin;
    const cols = () => (process.stdout.columns || 80) - 4;
    const maxVisible = () => Math.max(5, (process.stdout.rows || 24) - 10);
    const box = { on: c.green('[x]'), partial: c.yellow('[~]'), off: '[ ]' };
    let idx = view.cursor ?? 0;
    let drawn = 0;
    // Removes the menu from the screen: before a redraw, and once a choice is made, so the
    // next screen or submenu doesn't appear below a stale copy of this one.
    const erase = () => {
      if (drawn) process.stdout.write(`\x1b[${drawn}A\x1b[0J`);
      drawn = 0;
    };
    const selectable = (i) => !('heading' in (view.items()[i] ?? { heading: '' }));
    const move = (d) => {
      const n = view.items().length;
      for (let k = 0, i = idx; k < n; k++) {
        i = (i + d + n) % n;
        if (selectable(i)) { idx = i; return; }
      }
    };
    if (!selectable(idx)) move(1);

    const render = () => {
      erase();
      const items = view.items();
      idx = Math.min(idx, Math.max(0, items.length - 1));
      view.cursor = idx;
      const lines = view.title().split('\n').map((l) => truncate(l, cols()));
      const n = items.length;
      const size = Math.min(n, maxVisible());
      const start = Math.min(Math.max(0, idx - Math.floor(size / 2)), n - size);
      if (start > 0) lines.push(c.gray('    ↑ more'));
      for (let i = start; i < start + size; i++) {
        const it = items[i];
        if ('heading' in it) {
          lines.push(it.heading ? `      ${c.gray(truncate(it.heading, cols() - 6))}` : '');
          continue;
        }
        const label = truncate(`${it.label}${it.openable ? ' ›' : ''}`, cols() - 4);
        lines.push(`${i === idx ? c.accent('❯') : ' '} ${box[it.state] ?? box.off} ${i === idx ? c.accent(label) : label}`);
      }
      if (start + size < n) lines.push(c.gray('    ↓ more'));
      lines.push(c.gray(truncate(`↑/↓ move · Space toggle${view.open ? ' · → open · ← up' : ''} · Enter done · q/Esc cancel`, cols() + 2)));
      process.stdout.write(lines.join('\n') + '\n');
      drawn = screenRows(lines);
    };

    const finish = (value, err) => {
      erase();
      input.removeListener('keypress', onKey);
      if (input.isTTY) input.setRawMode(false);
      input.pause();
      err ? reject(err) : resolve(value);
    };

    const onKey = (str, key = {}) => {
      if (key.ctrl && (key.name === 'c' || key.name === 'd')) return finish(null, abortError());
      if (key.name === 'up' || key.name === 'k') move(-1);
      else if (key.name === 'down' || key.name === 'j') move(1);
      else if (key.name === 'space') view.toggle(idx);
      else if (view.open && (key.name === 'right' || key.name === 'l')) { if (view.open(idx)) idx = 0; }
      else if (view.up && (key.name === 'left' || key.name === 'h' || key.name === 'backspace')) {
        const back = view.up();
        if (back !== null) idx = back;
      } else if (key.name === 'return' || key.name === 'enter') return finish('done');
      else if (key.name === 'escape' || str === 'q') return finish(null);
      else return;
      render();
    };

    readline.emitKeypressEvents(input);
    if (input.isTTY) input.setRawMode(true);
    input.resume();
    input.on('keypress', onKey);
    render();
  });
}

// ------------------------------------------------------------------ logo

// Wordmark colors sampled from assets/logo-dark.png. Exact in truecolor terminals,
// the nearest 256-color elsewhere.
const truecolor = /^(truecolor|24bit)$/i.test(process.env.COLORTERM ?? '');
const rgb = (hex, fallback) => {
  const [r, g, b] = hex.match(/\w\w/g).map((h) => parseInt(h, 16));
  return wrap(truecolor ? `38;2;${r};${g};${b}` : `38;5;${fallback}`);
};
const logoWhite = rgb('f4f6fc', 255); // "Gnaw"
const brand = rgb('5414c0', 56); // "ky" and the tagline's bullet
const logoGray = rgb('c6c6d6', 251); // tagline
export const TAGLINE = 'gnaws through your code • watches like a hawk';
const tagline = () => TAGLINE.split(' • ').map((part) => logoGray(part)).join(` ${brand('•')} `);

/** "Gnawky" as in logo-dark.png: "Gnaw" in off-white, "ky" in purple. */
export const wordmark = () => `${c.bold(logoWhite('Gnaw'))}${c.bold(brand('ky'))}`;

const LETTERS = {
  G: [' ██████ ', '██      ', '██   ███', '██    ██', ' ██████ '],
  N: ['███    ██', '████   ██', '██ ██  ██', '██  ██ ██', '██   ████'],
  A: [' █████ ', '██   ██', '███████', '██   ██', '██   ██'],
  W: ['██     ██', '██     ██', '██  █  ██', '██ ███ ██', ' ███ ███ '],
  K: ['██   ██', '██  ██ ', '█████  ', '██  ██ ', '██   ██'],
  Y: ['██    ██', ' ██  ██ ', '  ████  ', '   ██   ', '   ██   '],
};
const ROWS = 5;
const lettersRow = (word, i) => [...word].map((ch) => LETTERS[ch][i]).join(' ');
// Each row sits one column left of the row above it, for the logo's italic lean.
const LOGO_ROWS = Array.from({ length: ROWS }, (_, i) => ({
  indent: ' '.repeat(ROWS - 1 - i),
  gnaw: lettersRow('GNAW', i),
  ky: lettersRow('KY', i),
}));
const LOGO_WIDTH = ROWS - 1 + LOGO_ROWS[0].gnaw.length + 1 + LOGO_ROWS[0].ky.length;

const center = (s, width) => ' '.repeat(Math.max(0, Math.floor((width - visibleLen(s)) / 2))) + s;

const LOGO_LINES = ROWS + 4; // blank, letters, blank, tagline, blank

/**
 * Big block-letter logo in logo-dark.png's colors ("GNAW" in off-white, "KY" in purple),
 * or the one-line wordmark when the terminal is too small for it plus the `below` lines
 * the screen prints after it.
 */
export function printLogo({ below = 21 } = {}) {
  const cols = process.stdout.columns || 80;
  const rows = process.stdout.rows || 24;
  if (cols < LOGO_WIDTH + 4 || rows < LOGO_LINES + below) {
    console.log(`${wordmark()}  ${tagline()}\n`);
    return;
  }
  const width = Math.min(cols, 80);
  const pad = ' '.repeat(Math.max(0, Math.floor((width - LOGO_WIDTH) / 2)));
  console.log();
  for (const { indent, gnaw, ky } of LOGO_ROWS) {
    console.log(`${pad}${indent}${c.bold(logoWhite(gnaw))} ${c.bold(brand(ky))}`);
  }
  console.log(`\n${center(tagline(), width)}\n`);
}
