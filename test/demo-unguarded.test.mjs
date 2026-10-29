// File: test/demo-unguarded.test.mjs · T10, the enabled half: a Cloud function WITHOUT the membership guard
// leaks tenant data — shown deliberately, then compared with the fixed version (getTask).
//
// DEMO_UNGUARDED=1 is set below, BEFORE cloud/main.js is loaded. node --test runs every test file in its own
// process, so the flag never leaks into the other suites; isolation.test.mjs proves the same function answers
// 141 "Invalid function" in a default deploy. Never set this flag on a backend with real data.
process.env.DEMO_UNGUARDED = '1';

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
// Dynamic import: static imports are hoisted and would load cloud/config.js BEFORE the flag above is set.
const { harness, mustCall } = await import('./helpers.mjs');

let h; let w;
before(async () => {
  if (process.env.TEST_SERVER_URL) return; // skipped on live targets (see the test body)
  h = await harness({ suite: 'demo-unguarded' });
  w = await h.world();
});
after(async () => { if (h) await h.cleanup(); });

test('T10 (demo half) the unguarded function leaks a Borealis task to an ACME member; the guarded version refuses', async (t) => {
  if (process.env.TEST_SERVER_URL) { t.skip('live run: the demo flag must never be set on a shared backend — the default-deploy half (141) runs live as T10'); return; }
  // The vulnerable version: authentication alone, no membership check, master-key read.
  const leak = await h.call('demoTaskById', { taskId: w.borealisTask }, w.acmeMember.token);
  assert.equal(leak.ok, true, 'the unguarded function answers');
  assert.equal(leak.result.title, 'Calibrate magnetometer', 'Borealis data crossed the tenant boundary');
  assert.equal(leak.result.tenantId, w.borealis);

  // Anonymous callers are still refused — which is exactly why "it requires a user" feels safe and is not.
  const anon = await h.call('demoTaskById', { taskId: w.borealisTask });
  assert.equal(anon.error.parseCode, 209);

  // The fixed version: same shape, same caller, membership-guarded by the GUARDS table.
  const fixed = await h.call('getTask', { taskId: w.borealisTask }, w.acmeMember.token);
  assert.equal(fixed.error.code, 'OBJECT_NOT_FOUND');
  assert.equal(fixed.error.parseCode, 101);
  const own = await mustCall(h, 'getTask', { taskId: w.acmeTask }, w.acmeMember.token);
  assert.equal(own.title, 'Order anvils', 'the guarded version still serves the caller\'s own tenant');

  h.observe('T10 demo', `demoTaskById leaked "${leak.result.title}" across tenants; getTask answers 101 for the same call`);
  h.record({
    id: 'T10demo', test: 'unguarded function (DEMO_UNGUARDED=1, throwaway server)', persona: 'ACME member',
    attempt: 'demoTaskById on a Borealis task id; then getTask (the guarded version) on the same id',
    status: '200 / 404', code: 'leak / OBJECT_NOT_FOUND 101',
    body: 'a missing authorization check can leak tenant data: the full Borealis task came back. The guarded version refuses identically to a nonexistent id',
    state: 'flag off by default (see T10); registration without a GUARDS entry refuses to start (R3)',
  });
});
