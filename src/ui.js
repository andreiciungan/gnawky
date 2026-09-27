import readline from 'node:readline';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const wrap = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));

export const c = {
  bold: wrap('1'), dim: wrap('2'), red: wrap('31'), green: wrap('32'), yellow: wrap('33'),
  blue: wrap('34'), cyan: wrap('36'), gray: wrap('90'), inverse: wrap('7'),
};

const SEV_COLOR = { critical: (s) => c.bold(c.red(s)), high: c.red, medium: c.yellow, low: c.blue, info: c.gray };
export const sevTag = (sev) => (SEV_COLOR[sev] ?? String)(sev.toUpperCase().padEnd(8));

const ANSI = /\x1b\[[0-9;]*m/g;
const visibleLen = (s) => s.replace(ANSI, '').length;
export function truncate(s, max) {
  if (visibleLen(s) <= max) return s;
  return s.replace(ANSI, '').slice(0, Math.max(1, max - 1)) + '…';
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
 * Arrow-key menu. options: [{ label, value, disabled }]
 * Resolves with the chosen value, or null for q / Esc (= back).
 */
export function select(title, options) {
  return new Promise((resolve, reject) => {
    const input = process.stdin;
    const cols = () => (process.stdout.columns || 80) - 4;
    const maxVisible = () => Math.max(5, (process.stdout.rows || 24) - 10);
    let idx = Math.max(0, options.findIndex((o) => !o.disabled));
    let drawn = 0;

    const render = () => {
      if (drawn) process.stdout.write(`\x1b[${drawn}A\x1b[0J`);
      const lines = [c.bold(truncate(title, cols()))];
      const n = options.length;
      const size = Math.min(n, maxVisible());
      const start = Math.min(Math.max(0, idx - Math.floor(size / 2)), n - size);
      if (start > 0) lines.push(c.gray('    ↑ more'));
      for (let i = start; i < start + size; i++) {
        const o = options[i];
        const num = i < 9 ? `${i + 1}.` : '  ';
        let label = truncate(`${num} ${o.label}`, cols());
        if (o.disabled) label = c.gray(label.replace(ANSI, ''));
        else if (i === idx) label = c.cyan(label);
        lines.push(`${i === idx ? c.cyan('❯') : ' '} ${label}`);
      }
      if (start + size < n) lines.push(c.gray('    ↓ more'));
      lines.push(c.gray('↑/↓ move · Enter select · 1-9 jump · q/Esc back'));
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
      else if (/^[1-9]$/.test(str ?? '')) {
        const o = options[Number(str) - 1];
        if (o && !o.disabled) return finish(o.value);
        return;
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
