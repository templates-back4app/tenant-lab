// File: test/roles.test.mjs · the role hierarchy (member role CONTAINS admin role — review point 1), the
// guard registry (cloud/guards.js — review point 3) and the negative tests for the membership helper.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { harness, mustCall } from './helpers.mjs';

const { createRegistry } = createRequire(import.meta.url)('../cloud/guards.js');

let h; let w;
before(async () => {
  h = await harness({ suite: 'roles' });
  w = await h.world();
});
after(async () => { await h.cleanup(); });

const ptr = (className, objectId) => ({ __type: 'Pointer', className, objectId });

test('R1 hierarchy direction: the member role contains the admin role, and only that way around', async () => {
  // Database state: tenant_<id>_member's roles relation contains tenant_<id>_admin.
  const memberRole = (await h.master('_Role', { name: `tenant_${w.acme}_member` }))[0];
  const adminRole = (await h.master('_Role', { name: `tenant_${w.acme}_admin` }))[0];
  const nested = await h.master('_Role', { $relatedTo: { object: ptr('_Role', memberRole.objectId), key: 'roles' } });
  assert.deepEqual(nested.map((r) => r.objectId), [adminRole.objectId], 'member.roles = [admin]');
  const reverse = await h.master('_Role', { $relatedTo: { object: ptr('_Role', adminRole.objectId), key: 'roles' } });
  assert.deepEqual(reverse, [], 'admin.roles is empty — members never inherit admin');
  // Direct role membership: the admin user is ONLY in the admin role; the member only in the member role.
  assert.equal((await h.master('_Role', { name: `tenant_${w.acme}_admin`, users: ptr('_User', w.acmeAdmin.objectId) })).length, 1);
  assert.equal((await h.master('_Role', { name: `tenant_${w.acme}_member`, users: ptr('_User', w.acmeAdmin.objectId) })).length, 0,
    'the admin has no direct member-role entry; their member reads come from the nesting (P3 proves they work)');
  assert.equal((await h.master('_Role', { name: `tenant_${w.acme}_admin`, users: ptr('_User', w.acmeMember.objectId) })).length, 0);
  h.record({
    id: 'R1', test: 'role hierarchy direction', persona: 'database state',
    attempt: 'master read of _Role rows and relations',
    status: 200, code: null,
    body: 'n/a (state test)',
    state: 'member.roles=[admin], admin.roles=[]; admin user only in admin role, member user only in member role',
  });
});

test('R2 hierarchy negative: a plain member gains nothing admin-only', async () => {
  const t = w.acmeMember.token;
  // Admin-only READ: Membership rows of OTHER users (ACL: owner + admin role). The member sees only their own.
  const memberships = await h.rest('GET', '/classes/Membership', undefined, { session: t });
  assert.equal(memberships.json.results.length, 1);
  assert.equal(memberships.json.results[0].user.objectId, w.acmeMember.objectId);
  const admins = await h.rest('GET', `/classes/Membership/${(await h.master('Membership', { user: ptr('_User', w.acmeAdmin.objectId), tenant: ptr('Tenant', w.acme) }))[0].objectId}`, undefined, { session: t });
  assert.equal(admins.json.code, 101, "the admin's own Membership row reads as Object not found for a member");
  // Admin-only WRITE paths are T13 (ADMIN_REQUIRED). State: the member role grants no admin-role entry:
  assert.equal((await h.master('_Role', { name: `tenant_${w.acme}_admin`, users: ptr('_User', w.acmeMember.objectId) })).length, 0);
  h.record({
    id: 'R2', test: 'hierarchy negative', persona: 'ACME member',
    attempt: "read another member's Membership row; (writes: see T13)",
    status: admins.status, code: `101`,
    body: 'unfiltered Membership find returns exactly the own row; a foreign row answers 101',
    state: 'no admin-role entry exists for the member user',
  });
});

test('R3 guard registry: a function missing from GUARDS, an unknown guard, double registration, a stale entry — all refuse to start', () => {
  // These are the load-time checks cloud/main.js runs through; a violation would fail the deploy, not the tenant.
  const r1 = createRegistry({ listed: 'authenticated' });
  assert.throws(() => r1.define('unlisted', () => {}), /not listed in the GUARDS table/);

  assert.throws(() => createRegistry({ broken: 'sudo' }), /unknown guard "sudo"/);

  const r2 = createRegistry({ twice: 'member' });
  r2.define('twice', () => {});
  assert.throws(() => r2.define('twice', () => {}), /registered twice/);

  const r3 = createRegistry({ ghost: 'admin' });
  assert.throws(() => r3.assertAllRegistered(), /never registered: ghost/);

  // The demo guard registers nothing while the demo flag is off…
  const r4 = createRegistry({ demoFn: 'demo-unguarded' }, { demoEnabled: false });
  let ran = false;
  r4.define('demoFn', () => { ran = true; });
  assert.equal(ran, false, 'demo-unguarded functions are skipped when the flag is off');
  r4.assertAllRegistered();
  // …and registers when it is on.
  const r5 = createRegistry({ demoFn: 'demo-unguarded' }, { demoEnabled: true });
  r5.define('demoFn', () => { ran = true; });
  assert.equal(ran, true);
  h.record({
    id: 'R3', test: 'guard registration check', persona: 'developer (load time)',
    attempt: 'register a function without a GUARDS entry / with an unknown guard / twice / leave a stale entry',
    status: 'n/a', code: 'throws at load',
    body: 'each violation throws with a message naming the function — the server refuses to start',
    state: 'n/a (unit test of cloud/guards.js, the module cloud/main.js registers through)',
  });
});

test('R4 membership helper negatives: non-member, removed member, deleted tenant, admin check', async () => {
  // Exercised through the functions, which is the only way the helper is reachable.
  const outsider = await h.signUp('r4_outsider');
  const r1 = await h.call('createProject', { tenantId: w.acme, name: 'nope' }, outsider.token);
  assert.equal(r1.error.code, 'NOT_A_MEMBER');
  const r2 = await h.call('createProject', { tenantId: w.acme, name: 'nope' }, w.removed.token);
  assert.equal(r2.error.code, 'NOT_A_MEMBER', 'a removed membership row does not satisfy the guard');
  const r3 = await h.call('createProject', { tenantId: 'AAAAAAAAAA', name: 'nope' }, outsider.token);
  assert.equal(r3.error.code, 'NOT_A_MEMBER', 'a nonexistent tenant answers exactly like a foreign one');
  const r4 = await h.call('invite', { tenantId: w.acme, email: 'x@example.test', role: 'member' }, w.acmeMember.token);
  assert.equal(r4.error.code, 'ADMIN_REQUIRED');
  assert.equal((await h.master('Project', { name: 'nope' })).length, 0);
  h.record({
    id: 'R4', test: 'membership helper negatives', persona: 'outsider / removed member / member',
    attempt: 'createProject as non-member, as removed member, into a nonexistent tenant; invite as plain member',
    status: 400, code: 'NOT_A_MEMBER ×3 (119), ADMIN_REQUIRED (119)',
    body: 'NOT_A_MEMBER is identical for "no such tenant" and "not yours"',
    state: 'no Project row was created',
  });
});

test('R5 reconciliation: a missing role entry is restored from the Membership row by myTenants', async () => {
  // Simulate the half-granted state (crash between Membership write and role write): remove the role entry.
  const user = await h.addMember(w.acmeAdmin.token, w.acme, 'member', 'r5_member');
  const before = await h.rest('GET', '/classes/Task', undefined, { session: user.token });
  assert.equal(before.json.results.length, 2, 'sanity: the fresh member reads the ACME tasks');

  const role = (await h.master('_Role', { name: `tenant_${w.acme}_member` }))[0];
  const unlink = await h.rest('PUT', `/classes/_Role/${role.objectId}`,
    { users: { __op: 'RemoveRelation', objects: [ptr('_User', user.objectId)] } }, { master: true });
  assert.equal(unlink.status, 200);
  const broken = await h.rest('GET', '/classes/Task', undefined, { session: user.token });
  assert.equal(broken.json.results.length, 0, 'half-granted: functions would work, reads fail CLOSED');

  const my = await mustCall(h, 'myTenants', {}, user.token);
  assert.equal(my.repairedRoleEntries, 1, 'myTenants reports the repair');
  const after2 = await h.rest('GET', '/classes/Task', undefined, { session: user.token });
  assert.equal(after2.json.results.length, 2, 'reads work again');
  h.record({
    id: 'R5', test: 'membership→role reconciliation', persona: 'ACME member (half-granted)',
    attempt: 'role entry removed with the master key; member calls myTenants',
    status: 200, code: null,
    body: 'myTenants returns repairedRoleEntries:1',
    state: 'reads: 2 tasks → 0 (fail closed) → 2 after repair; Membership row was the source of truth throughout',
  });
});
