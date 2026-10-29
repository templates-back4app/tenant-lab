// File: test/helpers.mjs · shared by the node:test suites. Raw REST only — no Parse SDK, no browser.
//
// Target: by default an in-process parse-server (scripts/dev-server.mjs) on a free port with the database
// postgres://localhost:5433/tenant_test, purged at the start of every suite file. For the LIVE run:
//
//   TEST_SERVER_URL=https://parseapi.back4app.com npm test
//
// which loads the keys from .env.live (APP_ID, JS_KEY, REST_KEY — never the master key), uses the
// SETUP_ENABLED-gated Cloud helpers instead of master-key REST (setupSchema for the schema, testInspect for
// every state read-back, testCleanup to delete what the run created), and SKIPS, with a printed reason, the
// parts that need direct master/database access (hook-vs-master-key probes, failure simulations, SQL
// corruption). Every object a run creates carries the per-execution RUN prefix in its username/tenant name,
// so parallel or crashed runs never collide and cleanup can only ever sweep its own run.
//
// Every suite records matrix rows (persona, attempt, HTTP/Parse code, body assertion, state assertion) into
// docs/evidence/.rows-<target>.jsonl; `npm test` regenerates docs/evidence/isolation-matrix-<target>-<date>.md
// from them afterwards (scripts/evidence.mjs, wired as pretest/posttest).
import { createServer } from 'node:net';
import crypto from 'node:crypto';
import { appendFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import WebSocket from 'ws';
import { LOCAL, ROOT, loadDotEnv } from '../scripts/lib/env.mjs';
import { makeClient, parseCloudError, where, sleep } from '../scripts/lib/rest.mjs';
import { applySchema } from '../scripts/setup.mjs';

export { where, sleep, parseCloudError };
/** Per-execution run prefix: every username and tenant name carries it (shape enforced by testCleanup). */
export const RUN = 'zz' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
export const unique = (prefix) => `${RUN}_${prefix}_${crypto.randomBytes(3).toString('hex')}`;
export const password = () => 'Pw-' + crypto.randomBytes(9).toString('base64url');

/** Evidence label: 'back4app' only for the real live host — a localhost TEST_SERVER_URL is a rehearsal. */
export const TARGET = !process.env.TEST_SERVER_URL ? 'local'
  : /back4app\.com/.test(process.env.TEST_SERVER_URL) ? 'back4app' : 'remote-rehearsal';
const ROWS_FILE = path.join(ROOT, 'docs', 'evidence', `.rows-${TARGET}.jsonl`);

const freePort = () => new Promise((resolve, reject) => {
  const s = createServer(); s.unref();
  s.on('error', reject);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});

/** Starts (or attaches to) the server, applies the schema, purges local data (local) / nothing (live). */
export async function harness({ suite } = {}) {
  let env; let handle = null; let isLocal = true;
  if (process.env.TEST_SERVER_URL) {
    isLocal = false;
    loadDotEnv(path.join(ROOT, '.env.live')); // live keys live here; never printed, never committed
    loadDotEnv();
    env = {
      name: TARGET,
      APP_ID: process.env.APP_ID, JS_KEY: process.env.JS_KEY || '', REST_KEY: process.env.REST_KEY || '',
      MASTER_KEY: process.env.MASTER_KEY || '', SERVER_URL: process.env.TEST_SERVER_URL.replace(/\/+$/, ''),
    };
    if (!env.APP_ID) throw new Error('TEST_SERVER_URL is set but APP_ID is missing — fill .env.live first.');
  } else {
    loadDotEnv();
    const { startServer } = await import('../scripts/dev-server.mjs');
    const port = await freePort();
    handle = await startServer({ port, databaseURI: process.env.TEST_DATABASE_URL || 'postgres://localhost:5433/tenant_test', quiet: true });
    env = { ...LOCAL, name: 'local-test', SERVER_URL: handle.url };
  }
  const api = makeClient(env, { retry: !isLocal }); // live: retry Back4app's 155 throttle with backoff
  const canMaster = !!env.MASTER_KEY;

  if (canMaster) {
    await applySchema(env);
  } else {
    // No master key: the schema goes through the SETUP_ENABLED-gated Cloud function. allowRerun, because a
    // live backend that already ran the suite holds tenants and would trip setupSchema's rerun tripwire.
    const setup = await api.call('setupSchema', { allowRerun: true });
    if (!setup.ok) {
      const why = setup.error.code === 'SETUP_DISABLED' ? 'cloud/config.js has SETUP_ENABLED=false on this backend'
        : /Invalid function/.test(setup.error.message || '') ? 'Cloud Code is not deployed (upload main.js, config.js, guards.js and Deploy — verify with a request)'
        : `HTTP ${setup.status} ${JSON.stringify(setup.error)}`;
      throw new Error(`setupSchema failed: ${why}`);
    }
  }
  if (isLocal) {
    // Purge everything from previous runs so counts (T6) and state assertions are deterministic. Live runs
    // never purge: isolation scoping keeps foreign rows invisible, and testCleanup removes this run's rows.
    for (const cls of ['Task', 'Project', 'Invite', 'Membership', 'FileMeta', 'Tenant', '_Session', '_User', '_Role']) {
      await api.request('DELETE', `/purge/${cls}`, { master: true });
    }
  }

  const observations = [];
  const h = {
    env, api, isLocal, canMaster, observations, suite: suite || 'suite',

    /**
     * Skip helper for live runs: parts that need the master key or direct database access (hook-vs-master
     * probes, failure simulations, SQL corruption) run locally and print a reason live. Usage:
     *   if (h.liveSkip(t, 'needs master-key writes — hook layer proven in the local run')) return;
     */
    liveSkip(t, reason) {
      if (canMaster) return false;
      t.skip(`live run: ${reason}`);
      return true;
    },

    observe(label, value) { observations.push({ label, value }); },

    /** One evidence-matrix row. `id` sorts the final table (T1, T1b, P2a, …). */
    record(row) {
      mkdirSync(path.dirname(ROWS_FILE), { recursive: true });
      appendFileSync(ROWS_FILE, JSON.stringify({ suite: h.suite, at: new Date().toISOString(), ...row }) + '\n');
    },

    // ---- raw REST --------------------------------------------------------------------------------------
    rest: (method, p, body, opts = {}) => api.request(method, p, { ...opts, body }),
    fn: (name, params, session) => api.request('POST', `/functions/${name}`, { body: params || {}, session }),
    /** Cloud call with the envelope unwrapped: {ok, status, result | error:{parseCode, code, message}} */
    call: (name, params, session) => api.call(name, params || {}, { session }),

    /**
     * Master-rights read-back for STATE assertions (equality-where only). Locally: REST with the master key.
     * Live: the SETUP_ENABLED-gated Cloud function testInspect — the master key never leaves the dashboard.
     */
    async master(className, whereObj) {
      if (canMaster) {
        const r = await api.request('GET', `/classes/${className}?where=${where(whereObj)}`, { master: true });
        if (r.status !== 200) throw new Error(`master read ${className} failed: ${r.status} ${JSON.stringify(r.json)}`);
        return r.json.results;
      }
      const r = await api.call('testInspect', { className, where: whereObj, limit: 1000 });
      if (!r.ok) throw new Error(`testInspect ${className} failed: ${JSON.stringify(r.error)}`);
      return r.result.results;
    },

    // ---- personas --------------------------------------------------------------------------------------
    async signUp(prefix) {
      const username = unique(prefix);
      const email = `${username}@example.test`;
      const pw = password();
      const r = await api.request('POST', '/users', { body: { username, password: pw, email } });
      if (r.status !== 201) throw new Error(`signUp failed: ${r.status} ${JSON.stringify(r.json)}`);
      return { username, email, pw, objectId: r.json.objectId, token: r.json.sessionToken };
    },
    async login(username, pw) {
      const r = await api.request('POST', '/login', { body: { username, password: pw } });
      if (r.status !== 200) throw new Error(`login failed: ${r.status}`);
      return { objectId: r.json.objectId, token: r.json.sessionToken };
    },

    /** invite + accept in one step; returns the invited user's handle. */
    async addMember(adminToken, tenantId, roleKind, prefix = 'member') {
      const u = await h.signUp(prefix);
      const inv = await h.call('invite', { tenantId, email: u.email, role: roleKind }, adminToken);
      if (!inv.ok) throw new Error(`invite failed: ${JSON.stringify(inv.error)}`);
      const acc = await h.call('acceptInvite', { token: inv.result.token }, u.token);
      if (!acc.ok) throw new Error(`acceptInvite failed: ${JSON.stringify(acc.error)}`);
      return u;
    },

    /**
     * Builds the two fictitious companies and the five personas of the brief:
     * anonymous (no token), ACME member, ACME admin, dual-tenant user (ACME+Borealis), removed member —
     * plus Borealis admin/member as the "other side", and a project + tasks per tenant.
     */
    async world() {
      const acmeAdmin = await h.signUp('acme_admin');
      const acme = (await mustCall(h, 'createTenant', { name: `ACME ${RUN}` }, acmeAdmin.token)).tenantId;
      const borealisAdmin = await h.signUp('borealis_admin');
      const borealis = (await mustCall(h, 'createTenant', { name: `Borealis ${RUN}` }, borealisAdmin.token)).tenantId;

      const acmeMember = await h.addMember(acmeAdmin.token, acme, 'member', 'acme_member');
      const borealisMember = await h.addMember(borealisAdmin.token, borealis, 'member', 'borealis_member');

      const dual = await h.signUp('dual');
      for (const [admin, tid] of [[acmeAdmin, acme], [borealisAdmin, borealis]]) {
        const inv = await mustCall(h, 'invite', { tenantId: tid, email: dual.email, role: 'member' }, admin.token);
        await mustCall(h, 'acceptInvite', { token: inv.token }, dual.token);
      }

      const removed = await h.addMember(acmeAdmin.token, acme, 'member', 'removed');
      await mustCall(h, 'removeMember', { tenantId: acme, userId: removed.objectId }, acmeAdmin.token);

      const acmeProject = (await mustCall(h, 'createProject', { tenantId: acme, name: 'Roadrunner traps' }, acmeAdmin.token)).projectId;
      const acmeTask = (await mustCall(h, 'createTask', { tenantId: acme, projectId: acmeProject, title: 'Order anvils' }, acmeMember.token)).id;
      const acmeTask2 = (await mustCall(h, 'createTask', { tenantId: acme, projectId: acmeProject, title: 'Paint tunnel on wall' }, acmeAdmin.token)).id;
      const borealisProject = (await mustCall(h, 'createProject', { tenantId: borealis, name: 'Aurora dashboards' }, borealisAdmin.token)).projectId;
      const borealisTask = (await mustCall(h, 'createTask', { tenantId: borealis, projectId: borealisProject, title: 'Calibrate magnetometer' }, borealisMember.token)).id;

      return {
        acme, borealis, acmeAdmin, acmeMember, borealisAdmin, borealisMember, dual, removed,
        acmeProject, acmeTask, acmeTask2, borealisProject, borealisTask,
      };
    },

    // ---- LiveQuery -------------------------------------------------------------------------------------
    /**
     * Raw LiveQuery subscription over ws (no SDK). Returns { events, next(ms), close() }.
     * `events` collects every op:create/update/delete/enter/leave message received.
     */
    async subscribe({ className = 'Task', whereObj = {}, session }) {
      // Back4app LiveQuery runs on its own host: enable Task under Server Settings → Live Query in the
      // dashboard and pass LIVEQUERY_URL=wss://<subdomain>.b4a.io; locally the dev server speaks ws itself.
      const wsUrl = process.env.LIVEQUERY_URL || env.SERVER_URL.replace(/^http/, 'ws');
      const ws = new WebSocket(wsUrl);
      const events = [];
      const waiters = [];
      let onEvent = null;
      ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (['create', 'update', 'delete', 'enter', 'leave'].includes(msg.op)) {
          events.push(msg);
          if (waiters.length) waiters.shift()(msg);
        } else if (onEvent) onEvent(msg);
      });
      const expect = (op) => new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`timed out waiting for op:${op}`)), 5000);
        onEvent = (msg) => {
          if (msg.op === op) { clearTimeout(timer); resolve(msg); }
          else if (msg.op === 'error') { clearTimeout(timer); reject(new Error(`LiveQuery error: ${JSON.stringify(msg)}`)); }
        };
      });
      await new Promise((resolve, reject) => { ws.on('open', resolve); ws.on('error', reject); });
      const connected = expect('connected');
      ws.send(JSON.stringify({ op: 'connect', applicationId: env.APP_ID, javascriptKey: env.JS_KEY, sessionToken: session }));
      await connected;
      const subscribed = expect('subscribed');
      ws.send(JSON.stringify({ op: 'subscribe', requestId: 1, query: { className, where: whereObj }, sessionToken: session }));
      await subscribed;
      let cursor = 0; // events already consumed by waitFor
      return {
        events,
        /**
         * Resolves with the next unconsumed event matching `predicate` (default: any), checking the backlog
         * first, or null after `ms` of silence. Deterministic against events that arrived before the call.
         */
        waitFor(predicate = () => true, ms = 1500) {
          return new Promise((resolve) => {
            const scan = () => {
              while (cursor < events.length) {
                const e = events[cursor++];
                if (predicate(e)) return e;
              }
              return null;
            };
            const hit = scan();
            if (hit) return resolve(hit);
            const timer = setTimeout(() => { const i = waiters.indexOf(fn); if (i !== -1) waiters.splice(i, 1); resolve(null); }, ms);
            const fn = () => { const found = scan(); if (found) { clearTimeout(timer); resolve(found); } else waiters.push(fn); };
            waiters.push(fn);
          });
        },
        close: () => new Promise((resolve) => { ws.on('close', resolve); ws.close(); }),
      };
    },

    /** True when a LiveQuery test can run against this target. */
    liveQueryAvailable: isLocal || !!process.env.LIVEQUERY_URL,

    async cleanup() {
      printObservations(`${h.suite} observations`, observations);
      if (!isLocal) {
        // Delete ONLY what this run created: tenants whose name carries RUN, users whose username starts
        // with RUN and are < 2 h old (plus their sessions). Gated by SETUP_ENABLED like the other helpers.
        const r = await api.call('testCleanup', { runPrefix: RUN });
        if (r.ok) console.log(`cleanup: testCleanup(${RUN}) removed ${JSON.stringify(r.result)}`);
        else console.log(`cleanup: testCleanup failed (${r.error.code}) — rows with prefix ${RUN} remain on the backend`);
      }
      if (handle) await handle.close();
    },
  };
  return h;
}

async function mustCall(h, name, params, session) {
  const r = await h.call(name, params, session);
  if (!r.ok) throw new Error(`${name} failed: HTTP ${r.status} ${JSON.stringify(r.error)}`);
  return r.result;
}
export { mustCall };

/** Prints the observations table so a test run doubles as evidence for the article. */
export function printObservations(title, observations) {
  if (!observations.length) return;
  console.log([`\n## ${title}`, ...observations.map((o) => `- ${o.label}: ${o.value}`)].join('\n'));
}
