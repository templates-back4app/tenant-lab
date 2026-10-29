// File: scripts/measure-scale.mjs · Node 22 ESM · hypotheses H3/H4 (LIVE measurements; a --local run is only
// a mechanics proof and is labeled local). One factor at a time, per the amended brief: the CALLER and the
// BACKEND STATE are chosen by the flags; this script only logs in as one seeded user and times one query.
//
//   H3 (tenant count): seed 1 tenant, measure; seed 1,000, measure again —
//     npm run measure:scale -- --live --label tenants-1    --user admin-0
//     npm run measure:scale -- --live --label tenants-1000 --user admin-0
//   H4 (caller's membership count): seed-tenants --join 1 / 10 / 50, then —
//     npm run measure:scale -- --live --label memberships-10 --user joiner
//
// Protocol per the house rules: 20 warm-ups discarded, 100 timed runs, p50/p95, error rate; requests paced by
// a token bucket (default 16 req/s — pacing adds gaps between requests, not latency inside them). One CSV row
// appended to docs/evidence/scale-h3h4-<target>-<date>.csv; indexes, rows per tenant, plan and region are the
// coordinator's to state next to the numbers.
import { writeFileSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { ROOT, target, args } from './lib/env.mjs';
import { makeClient, tokenBucket, parseCloudError, where } from './lib/rest.mjs';
import { seedUsername, seedPassword } from './lib/seed-identity.mjs';

const a = args();
if (!a.local && !a.live) { console.error('say which target: --local (mechanics proof) or --live'); process.exit(2); }
if (!a.label || !a.user) { console.error('usage: measure-scale --local|--live --label <tenants-1000|memberships-10|…> --user <admin-0|joiner> [--seed 42] [--warmups 20] [--runs 100] [--limit 100] [--rps 16] [--tenant-index 0]'); process.exit(2); }
const env = target(a);
const api = makeClient(env, { retry: env.name !== 'local' });
const seed = String(a.seed ?? '42');
const warmups = Number(a.warmups ?? 20);
const runs = Number(a.runs ?? 100);
const limit = Number(a.limit ?? 100);
const bucket = tokenBucket(Number(a.rps ?? 16));
const tenantIndex = Number(a['tenant-index'] ?? 0);

// --user admin-0 → seed-<seed>-admin-0 · --user joiner → seed-<seed>-joiner (as created by seed-tenants).
const m = String(a.user).match(/^(admin|joiner)(?:-(\d+))?$/);
if (!m) { console.error('--user must be admin-<i> or joiner (a user scripts/seed-tenants.mjs created)'); process.exit(2); }
const username = seedUsername(seed, m[1], m[2] === undefined ? undefined : Number(m[2]));

const login = await api.request('POST', '/login', { body: { username, password: seedPassword(seed, username) } });
if (login.status !== 200) { console.error(`login as ${username} failed (${login.status}) — run seed-tenants first`); process.exit(1); }
const session = login.json.sessionToken;

const my = await api.request('POST', '/functions/myTenants', { body: {}, session });
if (my.status !== 200) { console.error(`myTenants failed: ${JSON.stringify(parseCloudError(my.json))}`); process.exit(1); }
const memberships = my.json.result.tenants.length;
const tenant = my.json.result.tenants[tenantIndex];
if (!tenant) { console.error(`the user has ${memberships} membership(s); --tenant-index ${tenantIndex} does not exist`); process.exit(1); }

const q = `/classes/Task?limit=${limit}&where=${where({ tenant: { __type: 'Pointer', className: 'Tenant', objectId: tenant.tenantId } })}`;
console.log(`H3/H4 · target ${env.name} · label ${a.label} · user ${username} (${memberships} membership(s)) · tenant[${tenantIndex}] · limit ${limit} · ${warmups} warm-ups + ${runs} timed`);

let errors = 0;
const times = [];
for (let i = 0; i < warmups + runs; i++) {
  await bucket.take();
  const r = await api.request('GET', q, { session });
  if (r.status !== 200) { errors++; continue; }
  if (i >= warmups) times.push(r.ms);
}
times.sort((x, y) => x - y);
const pct = (p) => times.length ? times[Math.min(times.length - 1, Math.floor((p / 100) * times.length))].toFixed(1) : '';
const date = new Date().toISOString().slice(0, 10);
const csvPath = path.join(ROOT, 'docs', 'evidence', `scale-h3h4-${env.name === 'back4app' ? 'back4app' : 'local'}-${date}.csv`);
if (!existsSync(csvPath)) {
  mkdirSync(path.dirname(csvPath), { recursive: true });
  writeFileSync(csvPath, 'label,target,user,memberships,tenantIndex,limit,warmups,runs,errors,p50_ms,p95_ms,timestamp\n');
}
appendFileSync(csvPath, `${a.label},${env.name},${username},${memberships},${tenantIndex},${limit},${warmups},${runs},${errors},${pct(50)},${pct(95)},${new Date().toISOString()}\n`);
console.log(`p50 ${pct(50)} ms · p95 ${pct(95)} ms · errors ${errors}/${warmups + runs} → ${path.relative(ROOT, csvPath)}`);
