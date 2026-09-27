import fs from 'node:fs';
import path from 'node:path';
import { run } from './scanners.js';

// Detection only reads package.json and file names at known places.
// It never reads file contents beyond that and never walks the whole tree.

const FRAMEWORKS = [
  ['express', 'Express'], ['fastify', 'Fastify'], ['koa', 'Koa'], ['@nestjs/core', 'NestJS'], ['@hapi/hapi', 'hapi'],
  ['next', 'Next.js'], ['react', 'React'], ['vue', 'Vue'], ['@angular/core', 'Angular'], ['svelte', 'Svelte'],
  ['electron', 'Electron'],
];
const DATABASES = [
  ['mongoose', 'MongoDB'], ['mongodb', 'MongoDB'], ['pg', 'PostgreSQL'], ['mysql', 'MySQL'], ['mysql2', 'MySQL'],
  ['sqlite3', 'SQLite'], ['better-sqlite3', 'SQLite'], ['@prisma/client', 'Prisma'], ['sequelize', 'Sequelize'],
  ['typeorm', 'TypeORM'], ['knex', 'Knex'], ['redis', 'Redis'], ['ioredis', 'Redis'],
];
const AUTH = [
  ['jsonwebtoken', 'JWT'], ['jose', 'JWT'], ['passport', 'Passport'], ['express-session', 'sessions'],
  ['next-auth', 'NextAuth'], ['bcrypt', 'bcrypt'], ['bcryptjs', 'bcrypt'],
];
const COMPOSE_FILES = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'];

const readDir = (p) => { try { return fs.readdirSync(p); } catch { return []; } };
const uniq = (xs) => [...new Set(xs)];

export function detectProject(dir) {
  let pkg = null;
  try { pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch { /* none */ }
  const deps = { ...pkg?.dependencies, ...pkg?.devDependencies };
  const pick = (table) => uniq(table.filter(([name]) => deps[name]).map(([, label]) => label));
  const exists = (f) => fs.existsSync(path.join(dir, f));
  const top = readDir(dir);
  const git = exists('.git');

  const envFiles = top
    .filter((f) => /^\.env(\..+)?$/.test(f) && !/\.(example|sample|template|dist)$/.test(f))
    .map((f) => ({ file: f, ignored: git ? run('git', ['check-ignore', '-q', f], { cwd: dir }).status === 0 : null }));

  return {
    name: pkg?.name ?? path.basename(dir),
    hasPackageJson: Boolean(pkg),
    depCount: Object.keys(deps).length,
    lockfile: exists('package-lock.json') || exists('npm-shrinkwrap.json') ? 'npm'
      : exists('yarn.lock') ? 'yarn'
        : exists('pnpm-lock.yaml') ? 'pnpm' : null,
    typescript: Boolean(deps.typescript) || exists('tsconfig.json'),
    frameworks: pick(FRAMEWORKS),
    databases: pick(DATABASES),
    auth: pick(AUTH),
    docker: COMPOSE_FILES.some(exists),
    workflows: readDir(path.join(dir, '.github', 'workflows')).filter((f) => /\.ya?ml$/.test(f)).length,
    envFiles,
    git,
  };
}

/** Semgrep registry rulesets that fit the project (all checked to exist on semgrep.dev). */
export function semgrepRulesFor(p) {
  const rules = ['p/javascript', 'p/nodejsscan'];
  if (p.typescript) rules.push('p/typescript');
  if (p.frameworks.includes('React') || p.frameworks.includes('Next.js')) rules.push('p/react');
  if (p.frameworks.includes('Next.js')) rules.push('p/nextjs');
  if (p.frameworks.includes('Express')) rules.push('p/expressjs');
  if (p.auth.includes('JWT')) rules.push('p/jwt');
  if (p.docker) rules.push('p/dockerfile');
  if (p.workflows) rules.push('p/github-actions');
  return rules;
}
