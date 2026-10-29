// File: scripts/measure-revocation.mjs · Node 22 ESM · hypothesis H2: revocation is not instant.
// Measures, per run: (a) the time from `removeMember` RETURNING to the first REFUSED fresh REST read by the
// removed member (polled back-to-back), and (b) on an open LiveQuery subscription, when the last event was
// delivered and when delivery had verifiably stopped. 10 runs by default, min/median/max printed, one CSV row
// per run appended to docs/evidence/revocation-h2-<target>-<date>.csv. Nothing is fabricated: the CSV carries
// the label of the target it actually ran against ('back4app' only for the real live host).
//
//   npm run measure:h2 -- --local              # mechanics proof against the local dev server (npm run dev:server)
//   npm run measure:h2 -- --live --runs 10     # the live measurement (LIVEQUERY_URL=wss://… for the drain columns)
//
// Everything it creates carries a fresh zz… run prefix and is deleted afterwards through the SETUP_ENABLED-
// gated testCleanup — no master key involved.
import crypto from 'node:crypto';
import { writeFileSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import WebSocket from 'ws';
import { ROOT, target, args } from './lib/env.mjs';
import { makeClient, parseCloudError, sleep } from './lib/rest.mjs';

const a = args();
if (!a.local && !a.live) { console.error('say which target: --local (dev server must be running) or --live'); process.exit(2); }
const env = target(a);
const api = makeClient(env, { retry: env.name !== 'local' });
const runs = Number(a.runs ?? 10);
const RUN = 'zz' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
const lqUrl = process.env.LIVEQUERY_URL || (env.name === 'local' ? env.SERVER_URL.replace(/^http/, 'ws') : null);
const date = new Date().toISOString().slice(0, 10);
const csvPath = path.join(ROOT, 'docs', 'evidence', `revocation-h2-${env.name === 'back4app' ? 'back4app' : 'local'}-${date}.csv`);

async function call(name, params, session) {
  const r = await api.request('POST', `/functions/${name}`, { body: params, session });
  if (r.status !== 200) throw new Error(`${name}: ${r.status} ${JSON.stringify(parseCloudError(r.json))}`);
  return r.json.result;
}

async function user(prefix) {
  const username = `${RUN}_${prefix}_${crypto.randomBytes(3).toString('hex')}`;
  const r = await api.request('POST', '/users', { body: { username, password: 'Pw-' + crypto.randomBytes(9).toString('base64url'), email: `${username}@example.test` } });
  if (r.status !== 201) throw new Error(`signUp: ${r.status} ${JSON.stringify(r.json)}`);
  return { objectId: r.json.objectId, token: r.json.sessionToken, email: `${username}@example.test` };
}

/** Minimal LiveQuery subscription (raw protocol); returns { lastEventAt: () => ms-timestamp|null, close }. */
async function subscribe(session) {
  const ws = new WebSocket(lqUrl);
  // Each run uses a fresh tenant and the victim is only a member there, so EVERY create/update event this
  // subscription receives belongs to the run — no per-id bookkeeping (which would race the event delivery).
  let lastEventAt = null;
  ws.on('message', (d) => {
    const msg = JSON.parse(d.toString());
    if (['create', 'update'].includes(msg.op)) lastEventAt = performance.now();
  });
  await new Promise((res, rej) => { ws.on('open', res); ws.on('error', rej); });
  const once = (op) => new Promise((res, rej) => {
    const timer = setTimeout(() => rej(new Error(`timeout waiting op:${op}`)), 8000);
    ws.on('message', function fn(d) { const m = JSON.parse(d.toString()); if (m.op === op) { clearTimeout(timer); ws.off('message', fn); res(m); } });
  });
  const connected = once('connected');
  ws.send(JSON.stringify({ op: 'connect', applicationId: env.APP_ID, javascriptKey: env.JS_KEY, sessionToken: session }));
  await connected;
  const subscribed = once('subscribed');
  ws.send(JSON.stringify({ op: 'subscribe', requestId: 1, query: { className: 'Task', where: {} }, sessionToken: session }));
  await subscribed;
  return { lastEventAt: () => lastEventAt, close: () => ws.close() };
}

if (!existsSync(csvPath)) {
  mkdirSync(path.dirname(csvPath), { recursive: true });
  writeFileSync(csvPath, 'run,target,removeCallMs,firstRefusedReadMs,readsBeforeRefusal,lqLastEventMs,lqSilentConfirmedMs\n');
}

const firstRefused = []; const lqLast = [];
console.log(`H2 revocation delay · target ${env.name} · ${runs} run(s) · LiveQuery ${lqUrl ? 'on' : 'OFF (set LIVEQUERY_URL for the drain columns)'} · prefix ${RUN}`);

for (let run = 1; run <= runs; run++) {
  const admin = await user('h2admin');
  const tenantId = (await call('createTenant', { name: `H2 ${RUN} run ${run}` }, admin.token)).tenantId;
  const projectId = (await call('createProject', { tenantId, name: 'p' }, admin.token)).projectId;
  await call('createTask', { tenantId, projectId, title: 'warm' }, admin.token);
  const victim = await user('h2victim');
  const inv = await call('invite', { tenantId, email: victim.email, role: 'member' }, admin.token);
  await call('acceptInvite', { token: inv.token }, victim.token);
  const sanity = await api.request('GET', '/classes/Task', { session: victim.token });
  if ((sanity.json.results || []).length < 1) throw new Error('sanity: the member cannot read before removal');

  let sub = null;
  if (lqUrl) {
    sub = await subscribe(victim.token);
    await call('createTask', { tenantId, projectId, title: 'lq warm' }, admin.token);
    await sleep(300); // let the warm event arrive so "none" after removal really means "stopped"
    if (!sub.lastEventAt()) console.log(`run ${run}: warning — the warm LiveQuery event never arrived; drain columns for this run are unreliable`);
  }

  const tCall = performance.now();
  await call('removeMember', { tenantId, userId: victim.objectId }, admin.token);
  const t0 = performance.now();
  const removeCallMs = t0 - tCall;

  // (a) fresh reads, back-to-back, until the first refused one (0 rows readable).
  let readsBeforeRefusal = 0;
  let firstRefusedReadMs = null;
  for (;;) {
    const r = await api.request('GET', '/classes/Task', { session: victim.token });
    const rows = (r.json && r.json.results) || [];
    if (r.status === 200 && rows.length === 0) { firstRefusedReadMs = performance.now() - t0; break; }
    readsBeforeRefusal++;
    if (performance.now() - t0 > 30000) { firstRefusedReadMs = -1; break; } // never refused within 30 s: record -1
  }

  // (b) LiveQuery drain: probe with creates until 3 s of confirmed silence (or 20 s cap).
  let lqLastEventMs = ''; let lqSilentConfirmedMs = '';
  if (sub) {
    while (performance.now() - t0 < 20000) {
      await call('createTask', { tenantId, projectId, title: `probe ${Math.round(performance.now() - t0)}` }, admin.token);
      await sleep(500);
      const last = sub.lastEventAt();
      if (last && last > t0 && performance.now() - last > 3000) break;
      if (!last || last <= t0) { if (performance.now() - t0 > 8000) break; } // nothing delivered after removal at all
    }
    const last = sub.lastEventAt();
    lqLastEventMs = last && last > t0 ? Math.round(last - t0) : 'none';
    lqSilentConfirmedMs = Math.round(performance.now() - t0);
    sub.close();
  }

  appendFileSync(csvPath, `${run},${env.name},${removeCallMs.toFixed(0)},${firstRefusedReadMs === null ? '' : firstRefusedReadMs.toFixed(0)},${readsBeforeRefusal},${lqLastEventMs},${lqSilentConfirmedMs}\n`);
  console.log(`run ${run}/${runs}: removeMember ${removeCallMs.toFixed(0)} ms · first refused read +${firstRefusedReadMs?.toFixed(0)} ms (${readsBeforeRefusal} read(s) still served) · LQ last event ${lqLastEventMs || 'n/a'} ms`);
  if (typeof firstRefusedReadMs === 'number' && firstRefusedReadMs >= 0) firstRefused.push(firstRefusedReadMs);
  if (typeof lqLastEventMs === 'number') lqLast.push(lqLastEventMs);
}

const stats = (xs) => {
  if (!xs.length) return 'n/a';
  const s = [...xs].sort((x, y) => x - y);
  return `min ${s[0].toFixed(0)} / median ${s[Math.floor(s.length / 2)].toFixed(0)} / max ${s[s.length - 1].toFixed(0)} ms`;
};
console.log(`\nfirst refused fresh read after removeMember returned: ${stats(firstRefused)} over ${firstRefused.length} run(s)`);
console.log(`LiveQuery last delivered event after removal: ${stats(lqLast)} over ${lqLast.length} run(s)`);
console.log(`CSV: ${path.relative(ROOT, csvPath)}`);

const cleanup = await api.request('POST', '/functions/testCleanup', { body: { runPrefix: RUN } });
console.log(cleanup.status === 200
  ? `cleanup: removed ${JSON.stringify(cleanup.json.result)}`
  : `cleanup FAILED (${JSON.stringify(parseCloudError(cleanup.json))}) — rows with prefix ${RUN} remain`);
