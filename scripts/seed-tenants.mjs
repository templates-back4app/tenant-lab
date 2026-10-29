// File: scripts/seed-tenants.mjs · Node 22 ESM
// Seeds N tenants for the LIVE scale measurements (H3/H4), through the SAME path real clients use: sign up a
// deterministic admin user, createTenant, createProject, createTask — REST key + sessions only, NO master key.
// Token bucket (--rps, default 16 — Back4app's polite ceiling in the sibling repos), retry on throttle
// (HTTP 400 / Parse 155), resumable: usernames are deterministic in --seed and tenant i, so a re-run (or
// --from <i>) logs back in and skips tenants that already exist.
//
//   npm run seed:tenants -- --local --tenants 3 --projects 1 --tasks 2       # tiny local proof
//   npm run seed:tenants -- --tenants 1000 --tasks 100 --from 0              # the live H3 run (LIVE PHASE ONLY)
//   npm run seed:tenants -- --join 50                                        # H4: one user joins the first 50 tenants
//
// Synthetic data only — never run against a backend with real tenants. The deterministic passwords below are
// for throwaway benchmark users; the pattern is NOT for real accounts.
import { target, args } from './lib/env.mjs';
import { makeClient, tokenBucket, parseCloudError } from './lib/rest.mjs';
import { seedUsername, seedPassword, seedEmail } from './lib/seed-identity.mjs';

const a = args();
const env = target(a);
const api = makeClient(env, { retry: true, maxAttempts: 10 });
const nTenants = Number(a.tenants ?? 0);
const nProjects = Number(a.projects ?? 1);
const nTasks = Number(a.tasks ?? 5);
const seed = String(a.seed ?? '42');
const from = Number(a.from ?? 0);
const join = Number(a.join ?? 0);
const bucket = tokenBucket(Number(a.rps ?? 16));
let requests = 0;

if (!nTenants && !join) {
  console.error('usage: seed-tenants [--local] --tenants <n> [--projects 1] [--tasks 5] [--seed 42] [--rps 16] [--from 0] | --join <n>');
  process.exit(2);
}

const username = (kind, i) => seedUsername(seed, kind, i);
const pw = (user) => seedPassword(seed, user);
const email = (user) => seedEmail(user);

async function req(method, path, opts) {
  await bucket.take();
  requests++;
  return api.request(method, path, opts);
}

/** Sign up, or log back in when the username exists (resume). Returns { objectId, token }. */
async function ensureUser(user) {
  const up = await req('POST', '/users', { body: { username: user, password: pw(user), email: email(user) } });
  if (up.status === 201) return { objectId: up.json.objectId, token: up.json.sessionToken };
  if (up.json && (up.json.code === 202 || up.json.code === 203)) {
    const login = await req('POST', '/login', { body: { username: user, password: pw(user) } });
    if (login.status === 200) return { objectId: login.json.objectId, token: login.json.sessionToken };
    throw new Error(`login ${user}: ${login.status} ${JSON.stringify(login.json)}`);
  }
  throw new Error(`signUp ${user}: ${up.status} ${JSON.stringify(up.json)}`);
}

async function call(name, params, session) {
  await bucket.take();
  requests++;
  const r = await api.request('POST', `/functions/${name}`, { body: params, session });
  if (r.status === 200) return r.json.result;
  throw new Error(`${name}: ${r.status} ${JSON.stringify(parseCloudError(r.json))}`);
}

const t0 = Date.now();
console.log(`target ${env.name} (${env.SERVER_URL}) · seed ${seed} · ${a.rps ?? 16} req/s`);

if (nTenants) {
  let created = 0; let skipped = 0;
  for (let i = from; i < nTenants; i++) {
    const adminName = username('admin', i);
    const admin = await ensureUser(adminName);
    const mine = await call('myTenants', {}, admin.token);
    const tenantName = `Seed ${seed} tenant ${i}`;
    let tenant = mine.tenants.find((t) => t.name === tenantName);
    if (tenant) {
      skipped++;
    } else {
      tenant = { tenantId: (await call('createTenant', { name: tenantName }, admin.token)).tenantId };
      for (let p = 0; p < nProjects; p++) {
        const project = await call('createProject', { tenantId: tenant.tenantId, name: `Project ${p}` }, admin.token);
        for (let k = 0; k < nTasks; k++) {
          await call('createTask', { tenantId: tenant.tenantId, projectId: project.projectId, title: `Task ${p}.${k}` }, admin.token);
        }
      }
      created++;
    }
    if ((i + 1) % 10 === 0 || i === nTenants - 1) {
      const s = (Date.now() - t0) / 1000;
      const done = i + 1 - from;
      const eta = Math.round((nTenants - 1 - i) * (s / Math.max(1, done)));
      console.log(`tenant ${i + 1}/${nTenants} · +${created} (skipped ${skipped}) · ${requests} req · ${s.toFixed(0)} s · eta ${eta} s — resume with --from ${i + 1}`);
    }
  }
  console.log(`done: ${created} tenant(s) created, ${skipped} skipped (already seeded), ${requests} requests in ${((Date.now() - t0) / 1000).toFixed(1)} s`);
}

if (join) {
  // H4: one deterministic user joins the first `join` seeded tenants (1, 10 and 50 in the live measurement).
  const joinerName = username('joiner');
  const joiner = await ensureUser(joinerName);
  const already = new Set((await call('myTenants', {}, joiner.token)).tenants.map((t) => t.name));
  let joined = 0;
  for (let i = 0; i < join; i++) {
    const tenantName = `Seed ${seed} tenant ${i}`;
    if (already.has(tenantName)) continue;
    const admin = await ensureUser(username('admin', i));
    const mine = await call('myTenants', {}, admin.token);
    const tenant = mine.tenants.find((t) => t.name === tenantName);
    if (!tenant) throw new Error(`tenant ${i} is not seeded yet — run --tenants first`);
    const inv = await call('invite', { tenantId: tenant.tenantId, email: email(joinerName), role: 'member' }, admin.token);
    await call('acceptInvite', { token: inv.token }, joiner.token);
    joined++;
  }
  console.log(`joiner ${joinerName}: member of ${already.size + joined} tenant(s) (+${joined} this run, ${requests} requests total)`);
}
