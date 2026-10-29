// File: test/livequery.test.mjs · T8/T9 (subscription half): real-time updates scoped to a tenant, over a raw
// websocket speaking the LiveQuery protocol (no SDK). Local parse-server with LiveQuery enabled for Task.
// The revocation DELAY on an already-open subscription is a LIVE-ONLY measurement (brief); here the local run
// records the behaviour and asserts only the scoping, plus that delivery to a removed member ENDS within a
// bounded window (the LiveQuery server caches session auth for ~5 s — cacheTimeout — so "ends" is not "instant").
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { harness, mustCall, sleep } from './helpers.mjs';

let h; let w;
before(async () => {
  h = await harness({ suite: 'livequery' });
  w = await h.world();
});
after(async () => { await h.cleanup(); });

test('T8 an unfiltered Task subscription delivers only the subscriber\'s tenant: Borealis writes never arrive', async () => {
  const sub = await h.subscribe({ session: w.acmeMember.token });
  // Borealis writes first, then an ACME write as the ordering sentinel: if the ACME event arrives and no
  // Borealis event is in the backlog, the Borealis events were filtered, not merely slow.
  await mustCall(h, 'createTask', { tenantId: w.borealis, projectId: w.borealisProject, title: 'T8 borealis create' }, w.borealisMember.token);
  await mustCall(h, 'updateTask', { taskId: w.borealisTask, title: 'T8 borealis update' }, w.borealisAdmin.token);
  const sentinel = await mustCall(h, 'createTask', { tenantId: w.acme, projectId: w.acmeProject, title: 'T8 acme sentinel' }, w.acmeAdmin.token);

  const got = await sub.waitFor((e) => e.op === 'create' && e.object.objectId === sentinel.id, 5000);
  assert.ok(got, 'the ACME sentinel event was delivered (the subscription works)');
  const leaked = sub.events.filter((e) => (e.object.title || '').startsWith('T8 borealis'));
  assert.deepEqual(leaked, [], 'no Borealis event reached the ACME subscriber');
  assert.equal(got.object.title, 'T8 acme sentinel');
  await sub.close();
  h.observe('T8 events seen by the ACME subscriber', sub.events.map((e) => `${e.op}:${e.object.title}`).join(', '));
  h.record({
    id: 'T8', test: 'LiveQuery scoped to the tenant', persona: 'ACME member (open subscription, no tenant filter)',
    attempt: 'subscribe to Task with where:{}; Borealis creates + updates a task; ACME creates a sentinel task',
    status: 'ws', code: 'create delivered for ACME only',
    body: 'sentinel event delivered with its title; zero events for the Borealis writes',
    state: 'LOCAL parse-server 7.5.4; Back4app re-run: live phase',
  });
});

test('T9 (subscription half) a removed member\'s open subscription stops receiving within the auth-cache window', async () => {
  const victim = await h.addMember(w.acmeAdmin.token, w.acme, 'member', 't9lq_victim');
  const sub = await h.subscribe({ session: victim.token });
  const warm = await mustCall(h, 'createTask', { tenantId: w.acme, projectId: w.acmeProject, title: 'T9lq before removal' }, w.acmeAdmin.token);
  assert.ok(await sub.waitFor((e) => e.object.objectId === warm.id, 5000), 'subscription delivers before removal');

  const t0 = Date.now();
  await mustCall(h, 'removeMember', { tenantId: w.acme, userId: victim.objectId }, w.acmeAdmin.token);

  // The LiveQuery server caches the resolved session+roles (default cacheTimeout 5 s), so events may keep
  // arriving briefly. The measured DELAY is live-only; locally we assert the stronger claim that matters for
  // the design: delivery ENDS, and stays ended, within a bounded window (here: 10 s, double the cache TTL).
  let lastDelivered = null;
  let quietSince = null;
  while (Date.now() - t0 < 10000) {
    const probe = await mustCall(h, 'createTask', { tenantId: w.acme, projectId: w.acmeProject, title: `T9lq probe ${Date.now() - t0}ms` }, w.acmeAdmin.token);
    const e = await sub.waitFor((x) => x.object && x.object.objectId === probe.id, 1200);
    if (e) { lastDelivered = Date.now() - t0; quietSince = null; }
    else if (quietSince === null) quietSince = Date.now() - t0;
    if (quietSince !== null && Date.now() - t0 - quietSince >= 3000) break; // 3 s of silence across probes
    await sleep(400);
  }
  assert.notEqual(quietSince, null, `delivery to the removed member never stopped (last event ${lastDelivered} ms after removal)`);
  // And a brand-new subscription after removal delivers nothing at all:
  const fresh = await h.subscribe({ session: victim.token });
  const probe2 = await mustCall(h, 'createTask', { tenantId: w.acme, projectId: w.acmeProject, title: 'T9lq after removal' }, w.acmeAdmin.token);
  assert.equal(await fresh.waitFor((x) => x.object && x.object.objectId === probe2.id, 2500), null,
    'a fresh subscription opened after removal receives nothing');
  await sub.close();
  await fresh.close();
  h.observe('T9 LiveQuery after removeMember (LOCAL)',
    `last delivered event ${lastDelivered === null ? 'none' : `${lastDelivered} ms`} after removal; silent from ${quietSince} ms (LiveQuery auth cacheTimeout is 5 s by default). The per-run delay distribution is a LIVE measurement`);
  h.record({
    id: 'T9lq', test: 'LiveQuery after removal', persona: 'removed member (open + fresh subscription)',
    attempt: 'keep an open subscription through removeMember; probe with new ACME tasks; open a fresh subscription',
    status: 'ws', code: `open subscription: last event ${lastDelivered === null ? 'none' : lastDelivered + ' ms'} after removal, then silent; fresh subscription: 0 events`,
    body: 'delivery ends within the LiveQuery auth-cache window and stays ended; never claimed instant',
    state: 'DELAY distribution (10 runs, min/median/max): LIVE ONLY — not measured locally by design',
  });
});
