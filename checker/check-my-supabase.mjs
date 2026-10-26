#!/usr/bin/env node
// check-my-supabase v0.1.0. MIT License. Copyright (c) 2026 PatchAndShip.
// See which tables in YOUR OWN Supabase project a signed-out visitor (the anon role) can read.
// Safety design: table checks are HEAD requests only; the only GETs are robots.txt and the optional /rest/v1/ root.
// No writes, no RPC, no row data, no telemetry, no update checks, no redirects followed, no dependencies.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

export const VERSION = '0.1.0';
export const TOOL = 'check-my-supabase';
export const UA = `${TOOL}/${VERSION} (+https://patchandship.com)`;
export const LIMITS = { maxTables: 200, minDelayMs: 100, delayMs: 250, requestTimeoutMs: 15000, runTimeoutMs: 600000,
  rootMaxBytes: 5 * 1024 * 1024, robotsMaxBytes: 512 * 1024, codeMaxFiles: 5000, codeMaxFileBytes: 2 * 1024 * 1024, retryAfterMaxS: 60 };
export const FOOTER = "Not tested: signed-in users, writes, views' security_invoker, RPC functions, Storage, GraphQL. This is not an audit or penetration test.";
export const DISCLAIMER = 'Provided as is (MIT). Results may be incomplete or wrong. Not a penetration test, an audit or a guarantee of security.';
const CONSENT = 'yes, i own this project';
const TABLE_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const ROTATE_URL = 'https://supabase.com/docs/guides/api/api-keys#leaked-key';
const ALLOWED_METHODS = new Set(['HEAD', 'GET']);

export class UsageError extends Error { constructor(msg, exitCode = 1) { super(msg); this.exitCode = exitCode; } }

export const HELP = `${TOOL} ${VERSION}: see which of your Supabase tables a signed-out visitor can read.

Only run it on a project you own or have written permission to test.

Usage:
  ${TOOL} --from-env [path] --tables profiles,notes      (default target: your own local .env)
  ${TOOL} --url https://<ref>.supabase.co --key sb_publishable_... --tables profiles
  ${TOOL} --from-env --from-code ./src

Options:
  --from-env [path]          Read SUPABASE_URL / VITE_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_URL and the matching
                             publishable or anon key from a local .env file (default: ./.env). Default target.
  --url <url> --key <key>    Pass the project URL and publishable (or legacy anon) key explicitly.
  --tables a,b,c             Tables to check (primary discovery).
  --tables-file <file>       One table name per line.
  --from-code <dir>          Read table names from .from('name') calls in your own local code. Also fails
                             loudly (exit 3) if it finds a secret key or service_role JWT in that code.
  --json                     Machine-readable output.
  --no-count                 Skip the exact row count (for very large tables).
  --delay-ms <n>             Pause between requests (default ${LIMITS.delayMs}, minimum ${LIMITS.minDelayMs}).
  --yes-i-own-this-project   Skip the ownership prompt (for CI). Recorded as "consent: flag".
  --allow-custom-host        Allow a custom domain, or localhost / 127.0.0.1 for a local "supabase start".

Exit codes: 0 nothing returns rows, 2 at least one table returns rows, 1 usage or network error,
3 a secret key or service_role JWT was found in your code (--from-code).

Never scan other people's projects. If you find a problem in someone else's app, report it to them privately
(for example the Contact in their security.txt). A security.txt or robots.txt is not permission to test.

${DISCLAIMER}
`;

// ---------- keys ----------
function b64urlJson(s) {
  try { return JSON.parse(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); } catch { return null; }
}
export function classifyKey(key) {
  if (typeof key !== 'string' || !key.trim()) throw new UsageError('No key found. Use --from-env with your publishable key in .env, or pass --key.');
  key = key.trim();
  if (key.startsWith('sb_secret_')) throw new UsageError('Refusing to run: that is a secret key (sb_secret_). Use your publishable key (sb_publishable_...). A secret key bypasses RLS, so results would be meaningless.');
  if (/^sb_publishable_[A-Za-z0-9_-]+$/.test(key)) return { kind: 'publishable', label: 'sb_publishable_…(hidden)' };
  const parts = key.split('.');
  if (parts.length === 3 && parts.every((p, i) => (i === 2 || p) && /^[A-Za-z0-9_-]*$/.test(p))) {
    const payload = b64urlJson(parts[1]);
    if (payload && payload.role === 'anon') return { kind: 'jwt', label: 'JWT (anon)' };
    const role = payload && typeof payload.role === 'string' ? ` (role: ${payload.role.slice(0, 24)})` : '';
    throw new UsageError(`Refusing to run: this JWT is not an anon key${role}. Use your publishable or legacy anon key, never a service_role key.`);
  }
  throw new UsageError('Unrecognized key. Accepted: sb_publishable_... or a legacy anon JWT.');
}

// ---------- target ----------
export function validateTarget(raw, { allowCustomHost = false } = {}) {
  let u;
  try { u = new URL(String(raw).trim()); } catch { throw new UsageError('Invalid project URL. Expected https://<ref>.supabase.co'); }
  const host = u.hostname.toLowerCase();
  const local = host === 'localhost' || host === '127.0.0.1';
  if (u.username || u.password) throw new UsageError('The project URL must not contain credentials.');
  if (u.pathname !== '/' || u.search || u.hash || /[?#]/.test(String(raw))) throw new UsageError('Pass only the project URL, with no path or query (for example https://abcd1234.supabase.co).');
  if (u.protocol !== 'https:' && !(local && u.protocol === 'http:')) throw new UsageError('HTTPS only. Plain http is allowed only for localhost and 127.0.0.1.');
  if ((/^[\d.]+$/.test(host) || host.startsWith('[')) && !local) throw new UsageError('IP addresses are refused (only 127.0.0.1 for a local stack).');
  if (/(^|\.)(internal|local)$|^metadata\b/.test(host)) throw new UsageError('Internal or metadata hosts are refused.');
  const hosted = /^[a-z0-9]+\.supabase\.co$/.test(host) && !u.port && u.protocol === 'https:';
  if (!hosted && !allowCustomHost) throw new UsageError(`${host} is not a https://<ref>.supabase.co URL. For your own custom domain or a local stack, add --allow-custom-host.`);
  return { origin: u.origin, host: u.host };
}

// ---------- .env ----------
export function parseEnv(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (m) out[m[1]] = /^(['"]).*\1$/.test(m[2]) ? m[2].slice(1, -1) : m[2].replace(/\s+#.*$/, '');
  }
  return out;
}
const URL_VARS = ['SUPABASE_URL', 'VITE_SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_URL'];
const KEY_SUFFIXES = ['PUBLISHABLE_KEY', 'PUBLISHABLE_DEFAULT_KEY', 'ANON_KEY'];
export function pickFromEnv(vars) {
  let first = {};
  for (const uv of URL_VARS) {
    if (!vars[uv]) continue;
    const prefix = uv.slice(0, -3);
    const kv = KEY_SUFFIXES.map((s) => prefix + s).find((k) => vars[k]);
    if (kv) return { url: vars[uv], key: vars[kv], urlVar: uv, keyVar: kv };
    if (!first.url) first = { url: vars[uv], urlVar: uv };
  }
  return first;
}

// ---------- local code (read only, never uploaded) ----------
const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro']);
export function extractTables(text, set = new Set()) {
  for (const m of text.matchAll(/\.from\(\s*(['"`])([^'"`\n]{1,128})\1\s*\)/g)) {
    if (/storage\s*$/.test(text.slice(Math.max(0, m.index - 40), m.index))) continue; // storage.from('bucket') is not a table
    set.add(m[2]);
  }
  return set;
}
export function findSecrets(text) {
  const out = [], lineOf = (i) => text.slice(0, i).split('\n').length;
  for (const m of text.matchAll(/sb_secret_[A-Za-z0-9_-]{10,}/g)) out.push({ line: lineOf(m.index), kind: 'sb_secret_ key' });
  for (const m of text.matchAll(/eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g)) {
    const p = b64urlJson(m[0].split('.')[1]);
    if (p && p.role === 'service_role') out.push({ line: lineOf(m.index), kind: 'service_role JWT' });
  }
  return out;
}
export function scanCode(root) {
  const tables = new Set(), secrets = []; let files = 0, skippedLarge = 0;
  const visit = (p, rel) => {
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) return;
    if (st.isDirectory()) {
      for (const name of fs.readdirSync(p).sort()) if (name !== 'node_modules' && name !== '.git') visit(path.join(p, name), path.join(rel, name));
      return;
    }
    if (!st.isFile() || !CODE_EXT.has(path.extname(p))) return;
    if (++files > LIMITS.codeMaxFiles) throw new UsageError(`--from-code: more than ${LIMITS.codeMaxFiles} code files. Point it at your app's src folder.`);
    if (st.size > LIMITS.codeMaxFileBytes) { skippedLarge++; return; }
    const text = fs.readFileSync(p, 'utf8');
    extractTables(text, tables);
    for (const s of findSecrets(text)) secrets.push({ file: rel || path.basename(p), ...s });
  };
  if (!fs.existsSync(root)) throw new UsageError(`--from-code: ${root} not found.`);
  visit(root, '');
  return { tables: [...tables], secrets, files, skippedLarge };
}

// ---------- robots.txt (RFC 9309); never treated as permission ----------
function ruleMatches(rule, p) {
  const re = rule.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*').replace(/\\\$$/, '$');
  return new RegExp('^' + re).test(p);
}
export function robotsAllows(text, p, token = TOOL) {
  const groups = []; let cur = null, lastUA = false;
  for (const raw of text.split(/\r?\n/)) {
    const m = raw.replace(/#.*/, '').trim().match(/^([A-Za-z-]+)\s*:\s*(.*)$/);
    if (!m) continue;
    const k = m[1].toLowerCase(), v = m[2].trim();
    if (k === 'user-agent') { if (!lastUA) groups.push(cur = { agents: [], rules: [] }); cur.agents.push(v.toLowerCase()); lastUA = true; continue; }
    lastUA = false;
    if ((k === 'allow' || k === 'disallow') && cur && v) cur.rules.push({ allow: k === 'allow', path: v });
  }
  const mine = groups.filter((g) => g.agents.includes(token.toLowerCase()));
  const rules = (mine.length ? mine : groups.filter((g) => g.agents.includes('*'))).flatMap((g) => g.rules);
  let best = null;
  for (const r of rules) if (ruleMatches(r.path, p) && (!best || r.path.length > best.path.length || (r.path.length === best.path.length && r.allow))) best = r;
  return !best || best.allow;
}

// ---------- results ----------
export function proxyErrorCode(h) { const m = /error=("?)([A-Za-z0-9_]+)\1/.exec(h || ''); return m ? m[2] : null; }
export function mapResult(status, headers, counting = true) {
  const code = proxyErrorCode(headers.get('proxy-status'));
  const r = (st, label, detail, rows = null) => ({ status: st, label, detail, http: status, code, rows });
  if (status === 200 || status === 206) {
    const m = /^(\*|\d+-\d+)\/(\*|\d+)$/.exec((headers.get('content-range') || '').trim());
    if (!m) return r('unknown', 'unknown', `HTTP ${status}, no Content-Range`);
    if (counting && m[2] !== '*') {
      const n = Number(m[2]);
      return n > 0 ? r('readable', 'READABLE', `returns rows (${n.toLocaleString('en-US')})`, n) : r('reachable', 'reachable', '0 rows visible', 0);
    }
    return m[1] !== '*' ? r('readable', 'READABLE', 'returns rows') : r('reachable', 'reachable', 'no rows visible');
  }
  if ((status === 401 || status === 403) && code === '42501') return r('blocked', 'blocked', 'no grant (42501)');
  if (status === 404 && code === 'PGRST205') return r('not_found', 'not found', 'PGRST205');
  if (status === 500 && code === '57014') return counting ? r('count_timeout', '', '') // internal only: run() replaces it with the 1-row check result
    : r('unknown', 'unknown', 'the 1-row check hit the database statement timeout (57014)');
  if (status >= 300 && status < 400) return r('redirected', 'redirected', `HTTP ${status}, redirected, not followed`);
  return r('unknown', 'unknown', `HTTP ${status}${code ? ' ' + code : ''}`);
}
// The exact count timed out (57014, or our 15 s abort). Report only what the 1-row check (no count) proves; never a count.
export function countTimeoutResult(first, f) {
  const base = { http: f.http, code: first.code, rows: null }; if (f.status === 'readable') return { ...base, status: 'readable', label: 'READABLE', detail: 'at least 1 row readable (count timed out)' };
  if (f.status === 'reachable') return { ...base, status: 'reachable', label: 'reachable', detail: 'no rows visible (count timed out, 1-row check found none)' };
  return { ...base, status: f.status === 'error' ? 'error' : 'unknown', label: f.status === 'error' ? 'error' : 'unknown', detail: `count timed out; 1-row check: ${f.detail}` };
}
export function retryAfterMs(v, nowMs = Date.now()) {
  if (v == null || v === '') return 5000;
  const s = /^\d+$/.test(v.trim()) ? Number(v) : (Date.parse(v) - nowMs) / 1000;
  return Number.isFinite(s) ? Math.round(Math.min(Math.max(s, 0), LIMITS.retryAfterMaxS) * 1000) : 5000;
}

// ---------- network: the ONLY fetch call site ----------
class CapError extends Error {}
async function request(io, url, method, headers, maxBytes = 0) {
  if (!ALLOWED_METHODS.has(method)) throw new Error('method not allowed');
  if (new URL(url).origin !== io.origin) throw new Error('refusing a request to another host');
  const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), io.requestTimeoutMs);
  try {
    const res = await io.fetch(url, { method, headers: { 'User-Agent': UA, ...headers }, redirect: 'manual', signal: ctl.signal, cache: 'no-store' });
    let body = null;
    if (method === 'GET' && res.status === 200) {
      if (Number(res.headers.get('content-length')) > maxBytes) { await res.body?.cancel(); throw new CapError(); }
      const chunks = []; let n = 0;
      for await (const c of res.body || []) { n += c.byteLength; if (n > maxBytes) { ctl.abort(); throw new CapError(); } chunks.push(c); }
      body = Buffer.concat(chunks).toString('utf8');
    } else await res.body?.cancel().catch(() => {}); // HEAD has no body; error bodies are never read
    return { status: res.status, headers: res.headers, body };
  } finally { clearTimeout(timer); }
}

// ---------- CLI ----------
export function parseArgs(argv) {
  const o = { tables: [] }, a = [...argv];
  const val = (f) => { const v = a.shift(); if (v === undefined || v.startsWith('--')) throw new UsageError(`${f} needs a value.`); return v; };
  while (a.length) {
    let f = a.shift(), inline;
    if (/^--[^=]+=/.test(f)) { inline = f.slice(f.indexOf('=') + 1); f = f.slice(0, f.indexOf('=')); a.unshift(inline); }
    switch (f) {
      case '--url': o.url = val(f); break;
      case '--key': o.key = val(f); break;
      case '--from-env': o.fromEnv = a.length && !a[0].startsWith('--') ? a.shift() : '.env'; break;
      case '--tables': o.tables.push(...val(f).split(',').map((s) => s.trim()).filter(Boolean)); break;
      case '--tables-file': o.tablesFile = val(f); break;
      case '--from-code': o.fromCode = val(f); break;
      case '--json': o.json = true; break;
      case '--no-count': o.noCount = true; break;
      case '--delay-ms': o.delayMs = Number(val(f)); break;
      case '--yes-i-own-this-project': o.yes = true; break;
      case '--allow-custom-host': o.allowCustomHost = true; break;
      case '-h': case '--help': o.help = true; break;
      case '--version': o.version = true; break;
      default: throw new UsageError(`Unknown option ${String(f).slice(0, 40)}. See --help.`);
    }
  }
  return o;
}
function promptLine() {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    let done = false; rl.once('line', (l) => { done = true; rl.close(); resolve(l); });
    rl.once('close', () => { if (!done) resolve(''); });
  });
}

export async function run(argv, ioIn = {}) {
  const io = { fetch: globalThis.fetch, stdout: (s) => process.stdout.write(s), stderr: (s) => process.stderr.write(s), readLine: promptLine,
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => Date.now(), cwd: process.cwd(),
    requestTimeoutMs: LIMITS.requestTimeoutMs, runTimeoutMs: LIMITS.runTimeoutMs, ...ioIn };
  let secret = null;
  const scrub = (s) => (secret && secret.length >= 8 ? String(s).split(secret).join('[hidden]') : String(s));
  const out = (s) => io.stdout(scrub(s)), err = (s) => io.stderr(scrub(s));
  try {
    const o = parseArgs(argv);
    if (o.help) { out(HELP); return 0; }
    if (o.version) { out(VERSION + '\n'); return 0; }
    let env = {}, envFile = null;
    if (o.fromEnv !== undefined || !o.url) {
      envFile = path.resolve(io.cwd, o.fromEnv || '.env');
      if (!fs.existsSync(envFile)) throw new UsageError(`No .env file at ${envFile}. Use --from-env <path>, or --url and --key.`);
      env = pickFromEnv(parseEnv(fs.readFileSync(envFile, 'utf8')));
    }
    const url = o.url || env.url, key = o.key || env.key; secret = typeof key === 'string' ? key.trim() : null;
    if (!url) throw new UsageError(`No project URL found${envFile ? ' in ' + envFile : ''}. Expected ${URL_VARS.join(', ')}.`);
    const keyInfo = classifyKey(key), target = validateTarget(url, o); io.origin = target.origin;
    const from = o.url ? 'from --url' : `from ${path.relative(io.cwd, envFile) || envFile} (${env.urlVar})`;
    if (o.delayMs !== undefined && !(Number.isFinite(o.delayMs) && o.delayMs >= LIMITS.minDelayMs)) throw new UsageError(`--delay-ms must be at least ${LIMITS.minDelayMs}.`);
    const delay = o.delayMs ?? LIMITS.delayMs;

    const names = [...o.tables];
    if (o.tablesFile) names.push(...fs.readFileSync(path.resolve(io.cwd, o.tablesFile), 'utf8').split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#')));
    if (o.fromCode) {
      const sc = scanCode(path.resolve(io.cwd, o.fromCode));
      if (sc.secrets.length) {
        err(`\nRED: secret key material found in your code. Anyone who loads your app can use it to bypass RLS.\n`);
        for (const s of sc.secrets) err(`  ${s.kind} in ${s.file}:${s.line} (value not shown)\n`);
        err(`Remove it from client code, then rotate it: ${ROTATE_URL}\nNo network requests were made.\n`);
        return 3;
      }
      names.push(...sc.tables);
    }
    const seen = new Set(), results = [], valid = [];
    for (const n of names) {
      if (seen.has(n)) continue;
      seen.add(n);
      if (TABLE_RE.test(n) && !(secret && n.includes(secret))) valid.push(n);
      else results.push({ name: n, status: 'skipped', label: 'skipped', detail: 'invalid name', http: null, code: null, rows: null });
    }
    if (valid.length > LIMITS.maxTables) throw new UsageError(`Too many tables (${valid.length}). The cap is ${LIMITS.maxTables} per run.`);

    // consent: nothing is sent before this
    if (!o.yes) {
      err(`This tool checks what a signed-out visitor can read in ONE Supabase project.\nOnly run it on a project you own or have written permission to test.\n\nProject: ${target.host} (${from})\nType "yes, I own this project" to continue: `);
      const ans = String(await io.readLine()).trim().toLowerCase();
      if (ans !== CONSENT) { err('\nNot confirmed. Nothing was sent.\n'); return 1; }
    } else err(`Project: ${target.host} (${from}), consent: flag\n`);

    const deadline = io.now() + io.runTimeoutMs;
    const auth = { apikey: key.trim(), ...(keyInfo.kind === 'jwt' ? { Authorization: `Bearer ${key.trim()}` } : {}) };
    let robots = '', first = true; const pace = async () => { if (!first) await io.sleep(delay); first = false; };
    try {
      await pace();
      const rb = await request(io, `${target.origin}/robots.txt`, 'GET', {}, LIMITS.robotsMaxBytes);
      if (rb.status === 200) robots = rb.body;
      else if (rb.status >= 500) throw new UsageError(`robots.txt returned HTTP ${rb.status}. Per RFC 9309 that means "do not crawl", so the check stopped.`);
    } catch (e) {
      if (e instanceof UsageError) throw e;
      throw new UsageError(e instanceof CapError ? 'robots.txt is larger than 512 KB. Stopped.' : `Network error reaching ${target.host} (${e.name === 'AbortError' ? 'timed out' : 'unreachable'}).`);
    }
    if (!robotsAllows(robots, '/rest/v1/')) throw new UsageError(`robots.txt on ${target.host} disallows /rest/v1/ for ${TOOL}. Stopped.`);

    if (!valid.length && !results.length) {
      const msg = "The API root doesn't list tables to the public key (this is normal on hosted Supabase). Pass --tables or --from-code.";
      let rt;
      try { await pace(); rt = await request(io, `${target.origin}/rest/v1/`, 'GET', { ...auth, Accept: 'application/openapi+json, application/json' }, LIMITS.rootMaxBytes); }
      catch (e) { throw new UsageError(e instanceof CapError ? 'The API root response is larger than 5 MB. Stopped. Pass --tables or --from-code.' : msg); }
      let paths = null;
      try { paths = rt.status === 200 ? JSON.parse(rt.body).paths : null; } catch { paths = null; }
      if (!paths || typeof paths !== 'object') throw new UsageError(msg);
      for (const k of Object.keys(paths)) { const m = /^\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(k); if (m && valid.length < LIMITS.maxTables) valid.push(m[1]); }
      if (!valid.length) throw new UsageError(msg);
    }

    for (let i = 0; i < valid.length; i++) {
      const t = valid[i]; if (io.now() > deadline) {
        err(`Total run timeout reached. Stopped before "${t}" (${i} of ${valid.length} checked).\n`);
        for (const r of valid.slice(i)) results.push({ name: r, status: 'not_checked', label: 'stopped', detail: 'run timeout', http: null, code: null, rows: null });
        break;
      }
      if (!robotsAllows(robots, `/rest/v1/${t}`)) { results.push({ name: t, status: 'skipped', label: 'skipped', detail: 'disallowed by robots.txt', http: null, code: null, rows: null }); continue; }
      const u = `${target.origin}/rest/v1/${t}?select=*&limit=1`;
      const check = async (counting) => {
        const headers = { ...auth, 'Range-Unit': 'items', Range: '0-0', ...(counting ? { Prefer: 'count=exact' } : {}) };
        let res = null;
        for (let attempt = 0; attempt < 2; attempt++) {
          await pace(); res = await request(io, u, 'HEAD', headers);
          if (res.status !== 429 && res.status !== 503) break;
          if (attempt === 0) await io.sleep(retryAfterMs(res.headers.get('retry-after'), io.now()));
        }
        return res.status === 429 || res.status === 503
          ? { status: 'rate_limited', label: 'rate limited', detail: `HTTP ${res.status} after one retry`, http: res.status, code: null, rows: null }
          : mapResult(res.status, res.headers, counting);
      };
      const netError = (e) => ({ status: 'error', label: 'error', detail: e.name === 'AbortError' ? 'request timed out (15 s)' : 'network error', http: null, code: null, rows: null });
      let r; try { r = await check(!o.noCount); } catch (e) { r = !o.noCount && e.name === 'AbortError' ? { status: 'count_timeout', http: null, code: null } : netError(e); }
      results.push({ name: t, ...(r.status === 'count_timeout' ? countTimeoutResult(r, await check(false).catch(netError)) : r) }); // 57014 or 15 s abort
    }
    const order = new Map(names.map((n, i) => [n, i])); results.sort((a, b) => (order.get(a.name) ?? 1e9) - (order.get(b.name) ?? 1e9));
    const readable = results.filter((r) => r.status === 'readable').length;
    if (o.json) {
      out(JSON.stringify({ tool: TOOL, version: VERSION, project_host: target.host, checked_at: new Date(io.now()).toISOString(), consent: o.yes ? 'flag' : 'prompt',
        tables: results.map(({ name, status, http, code, rows }) => ({ name, status, http, code, rows, rows_at_least: status === 'readable' ? rows ?? 1 : null })),
        summary: { readable } }, null, 2) + '\n');
    } else out(formatReport(target.host, keyInfo, o.yes, results, readable));
    return readable > 0 ? 2 : results.some((r) => r.status === 'error') ? 1 : 0;
  } catch (e) {
    if (e instanceof UsageError) { err(`${TOOL}: ${e.message}\n`); return e.exitCode; }
    err(`${TOOL}: unexpected error (${e && e.name}).\n`);
    return 1;
  }
}

export function formatReport(host, keyInfo, flag, results, readable) {
  const w = Math.max(14, ...results.map((r) => shown(r).length)) + 2;
  const lines = [`${TOOL} v${VERSION} · project: ${host} · key: ${keyInfo.label}${flag ? ' · consent: flag' : ''}`,
    `Checked ${results.length} ${results.length === 1 ? 'table' : 'tables'} as the anon role (signed-out visitor). Read-only HEAD requests. No row data was read.`, ''];
  for (const r of results) lines.push(`  ${r.label.padEnd(10)} ${shown(r).padEnd(w)}${r.detail}`);
  lines.push('', `${readable} ${readable === 1 ? 'table returns' : 'tables return'} rows to anyone with your public key.`);
  if (readable) {
    lines.push('If a table is meant to be public (for example a catalog with a using (true) policy), that result is expected.',
      'Compare with the Supabase Security Advisor: supabase db advisors --type security (0013_rls_disabled_in_public flags tables with RLS off).',
      'Its 0024 check skips read policies with using (true) by design, so a READABLE table with RLS on may show no Advisor warning.',
      'Prove the fix with a pgTAP test: supabase test db');
  } else lines.push('No table returned rows to a signed-out visitor in this test. That is not proof the project is safe.');
  lines.push('', 'How to fix: Grant only what each role needs, keep RLS on with policies, and never GRANT ALL to anon.',
    'Guide: https://supabase.com/docs/guides/api/securing-your-api', 'Checklist: https://patchandship.com/supabase-rls-checklist/', '',
    'Want a second pair of eyes? Free check: https://patchandship.com/#free-check', '', FOOTER, DISCLAIMER, '');
  return lines.join('\n');
}
function shown(r) { return TABLE_RE.test(r.name) ? r.name : JSON.stringify(r.name.slice(0, 40)); }

let invoked = ''; try { invoked = fs.realpathSync(process.argv[1] || ''); } catch { invoked = ''; }
if (invoked === fileURLToPath(import.meta.url)) run(process.argv.slice(2)).then((c) => { process.exitCode = c; });
