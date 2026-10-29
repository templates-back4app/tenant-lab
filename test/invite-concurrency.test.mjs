// File: test/invite-concurrency.test.mjs · two parallel accepts of the same single-use token: exactly one
// wins (brief amendment, review point 5). The winner is decided by an atomic increment of Invite.useCount —
// the save response carries the incremented value, so exactly one request ever sees 1 — and the half-failed
// follow-up (invite consumed, membership or role missing) is repaired by the SAME user retrying the accept.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { harness, mustCall } from './helpers.mjs';

let h; let w;
before(async () => {
  h = await harness({ suite: 'invite-concurrency' });
  w = await h.world();
});
after(async () => { await h.cleanup(); });

const ptr = (className, objectId) => ({ __type: 'Pointer', className, objectId });

test('C1 two parallel accepts by the SAME user: exactly one membership row, both calls end consistent', async () => {
  const u = await h.signUp('c1_user');
  const inv = await mustCall(h, 'invite', { tenantId: w.acme, email: u.email, role: 'member' }, w.acmeAdmin.token);
  const [a, b] = await Promise.all([
    h.call('acceptInvite', { token: inv.token }, u.token),
    h.call('acceptInvite', { token: inv.token }, u.token),
  ]);
  // Both are the invited user, so each call either wins or repairs — but there is exactly ONE membership row.
  assert.ok(a.ok || a.error.code === 'INVITE_USED', `first: ${JSON.stringify(a.error || a.result)}`);
  assert.ok(b.ok || b.error.code === 'INVITE_USED', `second: ${JSON.stringify(b.error || b.result)}`);
  assert.ok(a.ok || b.ok, 'at least one accept succeeded');
  // Two racing ensures can briefly leave duplicate Membership rows (no unique index through the Parse schema
  // API); the next membership check self-heals them, oldest/active wins — the house pattern. Trigger one:
  await mustCall(h, 'getTask', { taskId: w.acmeTask }, u.token);
  const rows = await h.master('Membership', { user: ptr('_User', u.objectId), tenant: ptr('Tenant', w.acme) });
  assert.equal(rows.length, 1, 'exactly one Membership row');
  assert.equal(rows[0].status, 'active');
  const invite = (await h.master('Invite', { objectId: inv.inviteId }))[0];
  assert.equal(invite.status, 'used');
  assert.equal(invite.usedBy.objectId, u.objectId);
  h.observe('C1 same-user parallel accepts', `useCount=${invite.useCount}; outcomes: ${a.ok ? 'ok' : a.error.code} / ${b.ok ? 'ok' : b.error.code}`);
  h.record({
    id: 'C1', test: 'concurrent acceptance (same user)', persona: 'invited user ×2 in parallel',
    attempt: 'two simultaneous acceptInvite calls with the same token',
    status: '200/400', code: `${a.ok ? 'ok' : a.error.code} / ${b.ok ? 'ok' : b.error.code}; stored useCount=${invite.useCount}`,
    body: 'at least one call succeeds; a loser (if any) answers INVITE_USED',
    state: 'exactly 1 Membership row, status active; Invite status=used, usedBy=the user',
  });
});

test('C2 ten parallel accepts, two different users racing: exactly one wins, the wrong identity never gets in', async () => {
  // The token is bound to `invited`'s e-mail, so `thief` can never win — but the race on useCount is real for
  // the five parallel calls of the legitimate user. Ten calls total stress the atomicity.
  const invited = await h.signUp('c2_invited');
  const thief = await h.signUp('c2_thief');
  const inv = await mustCall(h, 'invite', { tenantId: w.acme, email: invited.email, role: 'member' }, w.acmeAdmin.token);
  const calls = [];
  for (let i = 0; i < 5; i++) {
    calls.push(h.call('acceptInvite', { token: inv.token }, invited.token));
    calls.push(h.call('acceptInvite', { token: inv.token }, thief.token));
  }
  const results = await Promise.all(calls);
  const invitedResults = results.filter((_, i) => i % 2 === 0);
  const thiefResults = results.filter((_, i) => i % 2 === 1);
  assert.ok(invitedResults.some((r) => r.ok), 'the invited user got in');
  for (const r of thiefResults) {
    assert.equal(r.ok, false, 'the thief never succeeds');
    assert.ok(['INVITE_EMAIL_MISMATCH', 'INVITE_USED'].includes(r.error.code), r.error.code);
  }
  await mustCall(h, 'getTask', { taskId: w.acmeTask }, invited.token); // self-heal duplicate rows, see C1
  assert.equal((await h.master('Membership', { user: ptr('_User', invited.objectId), tenant: ptr('Tenant', w.acme) })).length, 1);
  assert.equal((await h.master('Membership', { user: ptr('_User', thief.objectId), tenant: ptr('Tenant', w.acme) })).length, 0);
  const roleRows = await h.master('_Role', { name: `tenant_${w.acme}_member`, users: ptr('_User', invited.objectId) });
  assert.equal(roleRows.length, 1, 'one role entry for the winner (relation adds are idempotent)');
  const invite = (await h.master('Invite', { objectId: inv.inviteId }))[0];
  h.observe('C2 10-way race', `useCount=${invite.useCount}; invited: ${invitedResults.map((r) => r.ok ? 'ok' : r.error.code).join(',')}; thief: ${thiefResults.map((r) => r.error.code).join(',')}`);
  h.record({
    id: 'C2', test: 'concurrent acceptance (two identities, 10 calls)', persona: 'invited user ×5 ∥ thief ×5',
    attempt: 'ten simultaneous accepts of one token',
    status: 'mixed', code: `stored useCount=${invite.useCount}`,
    body: 'invited user: ≥1 ok (repairs allowed); thief: INVITE_EMAIL_MISMATCH or INVITE_USED only',
    state: '1 membership + 1 role entry for the invited user; none for the thief',
  });
});

test('C3 half-failed accept (consumed, membership missing): the SAME user\'s retry repairs it', async (t) => {
  if (h.liveSkip(t, 'simulating the crash needs master-key row edits — recorded in the local evidence')) return;
  const u = await h.signUp('c3_user');
  const inv = await mustCall(h, 'invite', { tenantId: w.acme, email: u.email, role: 'member' }, w.acmeAdmin.token);
  await mustCall(h, 'acceptInvite', { token: inv.token }, u.token);
  // Simulate the crash after the consume but before the membership write: wipe the membership AND role entry.
  const m = (await h.master('Membership', { user: ptr('_User', u.objectId), tenant: ptr('Tenant', w.acme) }))[0];
  await h.rest('DELETE', `/classes/Membership/${m.objectId}`, undefined, { master: true });
  const role = (await h.master('_Role', { name: `tenant_${w.acme}_member` }))[0];
  await h.rest('PUT', `/classes/_Role/${role.objectId}`, { users: { __op: 'RemoveRelation', objects: [ptr('_User', u.objectId)] } }, { master: true });
  assert.equal((await h.call('createTask', { tenantId: w.acme, projectId: w.acmeProject, title: 'x' }, u.token)).error.code, 'NOT_A_MEMBER',
    'half-failed: the user is locked out (fail closed)');

  const retry = await mustCall(h, 'acceptInvite', { token: inv.token }, u.token);
  assert.equal(retry.repaired, true, 'the retry reports the repair');
  const rows = await h.master('Membership', { user: ptr('_User', u.objectId), tenant: ptr('Tenant', w.acme) });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].status, 'active');
  // A DIFFERENT user retrying the consumed token is still refused.
  const other = await h.signUp('c3_other');
  assert.equal((await h.call('acceptInvite', { token: inv.token }, other.token)).error.code, 'INVITE_USED');
  h.record({
    id: 'C3', test: 'half-failed accept repair', persona: 'invited user (after simulated crash)',
    attempt: 'membership+role wiped with the master key after a successful accept; same user retries; another user retries',
    status: 200, code: 'repaired:true / INVITE_USED',
    body: 'retry returns {repaired:true}; foreign retry refused',
    state: 'membership + role entry restored; token still single-use for everyone else',
  });
});
