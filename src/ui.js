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
 */
export function select(title, options, { initial = null, keys = {}, hint = '' } = {}) {
  return new Promise((resolve, reject) => {
    const input = process.stdin;
    const cols = () => (process.stdout.columns || 80) - 4;
    const maxVisible = () => Math.max(5, (process.stdout.rows || 24) - 10);
    options = options.map((o) => ('static' in o ? { ...o, disabled: true } : o));
    let idx = initial !== null && options[initial] && !options[initial].disabled
      ? initial
      : Math.max(0, options.findIndex((o) => !o.disabled));
    let drawn = 0;
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
      if (drawn) process.stdout.write(`\x1b[${drawn}A\x1b[0J`);
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
      lines.push(c.gray(`↑/↓ move · Enter select · ${numbered ? 'type a number to jump' : 'type a number to pick'}${hint ? ` · ${hint}` : ''} · q/Esc back`));
      process.stdout.write(lines.join('\n') + '\n');
      drawn = lines.length;
    };

    const move = (d) => {
      let i = idx;
      for (let k = 0; k < options.length; k++) {
        i = (i + d + options.length) % options.length;
        if (!options[i].disabled) { idx = i; return; }
      }
    };

    const finish = (value, err) => {
      clearTimeout(pickTimer);
      input.removeListener('keypress', onKey);
      if (input.isTTY) input.setRawMode(false);
      input.pause();
      err ? reject(err) : resolve(value);
    };

    const onKey = (str, key = {}) => {
      if (key.ctrl && (key.name === 'c' || key.name === 'd')) return finish(null, abortError());
      if (key.name === 'up' || key.name === 'k') move(-1);
      else if (key.name === 'down' || key.name === 'j') move(1);
      else if (key.name === 'return' || key.name === 'enter') return finish(options[idx]?.value ?? null);
      else if (key.name === 'escape' || str === 'q') return finish(null);
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
