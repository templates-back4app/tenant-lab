// File: test/positive.test.mjs · P-series: positive controls (brief amendment, review point 8).
// A system that denies everything would pass many isolation tests; these rows prove every persona CAN do what
// the design permits, asserting response bodies AND database state (read back with the master key), never
// just status codes.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { harness, mustCall } from './helpers.mjs';

let h; let w;
before(async () => {
  h = await harness({ suite: 'positive' });
  w = await h.world();
});
after(async () => { await h.cleanup(); });

test('P1 anonymous: can sign up and log in (the only permitted operations)', async () => {
  const u = await h.signUp('p1_user');
  assert.ok(u.objectId && u.token, 'sign-up returns objectId and session token');
  const back = await h.login(u.username, u.pw);
  assert.equal(back.objectId, u.objectId);
  h.record({
    id: 'P1', test: 'positive control', persona: 'anonymous',
    attempt: 'POST /users (sign up), POST /login',
    status: 201, code: null,
    body: 'objectId + sessionToken returned; login returns the same objectId',
    state: `_User row ${u.objectId} exists`,
  });
});

test('P2 ACME member: reads tenant, projects, tasks, own membership; creates and updates a task', async () => {
  const t = w.acmeMember.token;

  const tenant = await h.rest('GET', `/classes/Tenant/${w.acme}`, undefined, { session: t });
  assert.equal(tenant.status, 200);
  assert.match(tenant.json.name, /^ACME /, 'member reads the tenant row (name present)');

  const projects = await h.rest('GET', `/classes/Project?where=${encodeURIComponent(JSON.stringify({ tenant: ptr('Tenant', w.acme) }))}`, undefined, { session: t });
  assert.equal(projects.status, 200);
  assert.deepEqual(projects.json.results.map((p) => p.objectId), [w.acmeProject], 'exactly the ACME project');

  const tasks = await h.rest('GET', '/classes/Task', undefined, { session: t });
  assert.equal(tasks.status, 200);
  assert.deepEqual(new Set(tasks.json.results.map((x) => x.objectId)), new Set([w.acmeTask, w.acmeTask2]),
    'an unfiltered Task find returns exactly the two ACME tasks — the ACL does the scoping, not the query');

  const mine = await h.rest('GET', '/classes/Membership', undefined, { session: t });
  assert.equal(mine.json.results.length, 1, 'a plain member sees exactly their own Membership row');
  assert.equal(mine.json.results[0].role, 'member');

  const created = await mustCall(h, 'createTask', { tenantId: w.acme, projectId: w.acmeProject, title: 'Test rocket skates', assigneeId: w.acmeMember.objectId }, t);
  assert.equal(created.tenantId, w.acme);
  assert.equal(created.assigneeId, w.acmeMember.objectId);
  const rows = await h.master('Task', { objectId: created.id });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].title, 'Test rocket skates');
  assert.deepEqual(rows[0].ACL, { [`role:tenant_${w.acme}_member`]: { read: true } },
    'stored ACL is exactly member-role read, nothing else');

  const updated = await mustCall(h, 'updateTask', { taskId: created.id, title: 'Return rocket skates' }, t);
  assert.equal(updated.title, 'Return rocket skates');
  assert.equal((await h.master('Task', { objectId: created.id }))[0].title, 'Return rocket skates');
  await mustCall(h, 'deleteTask', { taskId: created.id }, t);
  assert.equal((await h.master('Task', { objectId: created.id })).length, 0, 'deleted row is gone');

  h.record({
    id: 'P2', test: 'positive control', persona: 'ACME member',
    attempt: 'read tenant/projects/tasks/own membership; createTask/updateTask/deleteTask via functions',
    status: 200, code: null,
    body: 'reads return exactly the ACME rows; function results echo the created/updated task',
    state: `Task stored with ACL {role:tenant_<acme>_member: read}; title updated; row gone after delete`,
  });
});

test('P3 ACME admin: inherits member reads (role nesting) and performs admin-only operations', async () => {
  const t = w.acmeAdmin.token;

  // Admin reads rows whose ACL names only the MEMBER role — the member role contains the admin role.
  const tasks = await h.rest('GET', '/classes/Task', undefined, { session: t });
  assert.deepEqual(new Set(tasks.json.results.map((x) => x.objectId)), new Set([w.acmeTask, w.acmeTask2]),
    'admin reads member-role rows without being in the member role (inheritance direction is member ⊃ admin)');

  // Admin reads every ACME Membership row (ACL: owner + admin role) — 4: admin, member, dual, removed.
  const members = await h.rest('GET', '/classes/Membership', undefined, { session: t });
  assert.equal(members.json.results.length, 4, 'admin lists all four ACME membership rows');

  // Admin-only lifecycle: invite (P-series uses a fresh invitee), then clean up with removeMember.
  const u = await h.addMember(t, w.acme, 'member', 'p3_member');
  const m1 = await h.master('Membership', { user: ptr('_User', u.objectId), tenant: ptr('Tenant', w.acme) });
  assert.equal(m1[0].status, 'active');
  const roles = await h.master('_Role', { name: `tenant_${w.acme}_member`, users: ptr('_User', u.objectId) });
  assert.equal(roles.length, 1, 'accept added the user to the member role');

  const removed = await mustCall(h, 'removeMember', { tenantId: w.acme, userId: u.objectId }, t);
  assert.equal(removed.removed, true);
  const m2 = await h.master('Membership', { user: ptr('_User', u.objectId), tenant: ptr('Tenant', w.acme) });
  assert.equal(m2[0].status, 'removed');
  assert.equal((await h.master('_Role', { name: `tenant_${w.acme}_member`, users: ptr('_User', u.objectId) })).length, 0,
    'role entry gone after removal');

  const project = await mustCall(h, 'createProject', { tenantId: w.acme, name: 'P3 throwaway' }, t);
  await mustCall(h, 'deleteProject', { projectId: project.projectId }, t);
  assert.equal((await h.master('Project', { objectId: project.projectId })).length, 0);

  h.record({
    id: 'P3', test: 'positive control', persona: 'ACME admin',
    attempt: 'read member-role rows; list memberships; invite+accept; removeMember; create/deleteProject',
    status: 200, code: null,
    body: 'admin sees both tasks and all 4 membership rows; lifecycle calls return their documented shapes',
    state: 'Membership active→removed; role entry added then removed; project row created then gone',
  });
});

test('P4 dual-tenant user: reads and writes BOTH tenants, each request scoped to the tenant it names', async () => {
  const t = w.dual.token;
  const tenants = await mustCall(h, 'myTenants', {}, t);
  assert.deepEqual(new Set(tenants.tenants.map((x) => x.tenantId)), new Set([w.acme, w.borealis]));

  const tasks = await h.rest('GET', '/classes/Task', undefined, { session: t });
  assert.deepEqual(new Set(tasks.json.results.map((x) => x.objectId)), new Set([w.acmeTask, w.acmeTask2, w.borealisTask]),
    'dual member reads the rows of both tenants — and nothing else');

  const inAcme = await mustCall(h, 'createTask', { tenantId: w.acme, projectId: w.acmeProject, title: 'Dual in ACME' }, t);
  const inBorealis = await mustCall(h, 'createTask', { tenantId: w.borealis, projectId: w.borealisProject, title: 'Dual in Borealis' }, t);
  const a = (await h.master('Task', { objectId: inAcme.id }))[0];
  const b = (await h.master('Task', { objectId: inBorealis.id }))[0];
  assert.equal(a.tenant.objectId, w.acme);
  assert.equal(b.tenant.objectId, w.borealis);
  assert.deepEqual(Object.keys(a.ACL), [`role:tenant_${w.acme}_member`], 'ACME write got the ACME ACL');
  assert.deepEqual(Object.keys(b.ACL), [`role:tenant_${w.borealis}_member`], 'Borealis write got the Borealis ACL');

  h.record({
    id: 'P4', test: 'positive control', persona: 'dual-tenant user (ACME+Borealis)',
    attempt: 'myTenants; unfiltered Task find; createTask in each tenant',
    status: 200, code: null,
    body: 'both tenants listed; find returns the union of both tenants and nothing else',
    state: 'each created task stored under the tenant it named, with that tenant\'s member-role ACL',
  });
});

test('P5 removed member: account and other access intact (removal is scoped to the tenant)', async () => {
  // The isolation side (fresh ACME requests refused) is T9/isolation; here the POSITIVE control: the user
  // still has a working account and could be a member elsewhere.
  const t = w.removed.token;
  const me = await h.rest('GET', '/users/me', undefined, { session: t });
  assert.equal(me.status, 200, 'the removed member\'s user account and session survive removal');
  const tenants = await mustCall(h, 'myTenants', {}, t);
  assert.deepEqual(tenants.tenants, [], 'no active memberships left');
  const users = await h.master('_User', { objectId: w.removed.objectId });
  assert.equal(users.length, 1, 'user account preserved');
  h.record({
    id: 'P5', test: 'positive control', persona: 'removed member',
    attempt: 'GET /users/me; myTenants after removal',
    status: 200, code: null,
    body: 'session still valid; myTenants returns an empty list',
    state: '_User row preserved; ACME Membership row status=removed (kept for audit)',
  });
});

function ptr(className, objectId) {
  return { __type: 'Pointer', className, objectId };
}
