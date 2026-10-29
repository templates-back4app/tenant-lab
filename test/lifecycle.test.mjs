// File: test/lifecycle.test.mjs · member removal (the fresh-request half of T9; the LiveQuery half lives in
// livequery.test.mjs) and tenant deletion (T15): pagination, deterministic interruption via the operation
// budget, retry, idempotency, and what must SURVIVE a deletion (user accounts, other tenants, other
// memberships). The deletion claim covers the live API only — never backups or platform logs (README).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { harness, mustCall, RUN } from './helpers.mjs';

let h; let w;
before(async () => {
  h = await harness({ suite: 'lifecycle' });
  w = await h.world();
});
after(async () => { await h.cleanup(); });

const ptr = (className, objectId) => ({ __type: 'Pointer', className, objectId });

test('T9 (fresh requests) removing a member: every fresh request after removeMember returns is refused', async () => {
  const victim = await h.addMember(w.acmeAdmin.token, w.acme, 'member', 't9_victim');
  // Sanity before: reads and writes work.
  assert.equal((await h.rest('GET', '/classes/Task', undefined, { session: victim.token })).json.results.length, 2);
  const task = await mustCall(h, 'createTask', { tenantId: w.acme, projectId: w.acmeProject, title: 'T9 victim task' }, victim.token);

  const t0 = Date.now();
  await mustCall(h, 'removeMember', { tenantId: w.acme, userId: victim.objectId }, w.acmeAdmin.token);
  // FRESH requests, immediately after return — the revocation guarantee (amendment 7). The brief's
  // revocation-DELAY measurement (time till an already-open LiveQuery stops delivering) is live-only.
  const read = await h.rest('GET', '/classes/Task', undefined, { session: victim.token });
  const readMs = Date.now() - t0;
  assert.equal(read.status, 200);
  assert.deepEqual(read.json.results, [], 'fresh REST find returns 0 rows');
  const write = await h.call('updateTask', { taskId: task.id, title: 'still mine?' }, victim.token);
  assert.equal(write.error.code, 'OBJECT_NOT_FOUND', 'fresh function write refused (id now hidden)');
  const create = await h.call('createTask', { tenantId: w.acme, projectId: w.acmeProject, title: 'nope' }, victim.token);
  assert.equal(create.error.code, 'NOT_A_MEMBER');
  const tenantRead = await h.rest('GET', `/classes/Tenant/${w.acme}`, undefined, { session: victim.token });
  assert.equal(tenantRead.json.code, 101);
  // The session itself stays valid (removal ≠ sign-out) and the task the victim created stays with the tenant.
  assert.equal((await h.rest('GET', '/users/me', undefined, { session: victim.token })).status, 200);
  assert.equal((await h.master('Task', { objectId: task.id }))[0].title, 'T9 victim task');
  await mustCall(h, 'deleteTask', { taskId: task.id }, w.acmeAdmin.token); // keep later counts clean (admin passes the member guard)
  h.observe('T9 first refused fresh read', `${readMs} ms after removeMember returned (local; the open-subscription delay is live-only)`);
  h.record({
    id: 'T9', test: 'revocation of fresh requests', persona: 'removed member',
    attempt: 'REST find, function write, function create, tenant get — all AFTER removeMember returned',
    status: '200/400/404', code: '0 rows / OBJECT_NOT_FOUND / NOT_A_MEMBER / 101',
    body: `every fresh request refused, first read ${readMs} ms after return; session itself stays valid`,
    state: 'Membership status=removed; both role entries gone; the rows the member created remain with the tenant',
  });
});

test('T9b dual-tenant and nested-role removal: losing ACME does not touch Borealis; a removed ADMIN loses both inherited and direct access', async () => {
  // Dual-tenant case (amendment 7): remove the dual user from ACME only.
  const inv = await mustCall(h, 'invite', { tenantId: w.acme, email: (await (async () => w.dual)()).email, role: 'member' }, w.acmeAdmin.token);
  void inv; // the dual user is already a member; this invite is unused — removal is the point here
  await mustCall(h, 'removeMember', { tenantId: w.acme, userId: w.dual.objectId }, w.acmeAdmin.token);
  const read = await h.rest('GET', '/classes/Task', undefined, { session: w.dual.token });
  assert.deepEqual(read.json.results.map((x) => x.objectId), [w.borealisTask],
    'after ACME removal the dual user still reads exactly the Borealis rows');
  const my = await mustCall(h, 'myTenants', {}, w.dual.token);
  assert.deepEqual(my.tenants.map((x) => x.tenantId), [w.borealis]);

  // Nested-role case: an ADMIN's member-reads come through the nesting; removing them must kill those too.
  const admin2 = await h.addMember(w.acmeAdmin.token, w.acme, 'admin', 't9b_admin');
  assert.equal((await h.rest('GET', '/classes/Task', undefined, { session: admin2.token })).json.results.length, 2,
    'the second admin reads member-ACL rows via the nesting');
  await mustCall(h, 'removeMember', { tenantId: w.acme, userId: admin2.objectId }, w.acmeAdmin.token);
  assert.deepEqual((await h.rest('GET', '/classes/Task', undefined, { session: admin2.token })).json.results, [],
    'after removal the ex-admin reads nothing — the admin-role entry (and with it the inherited member read) is gone');
  const adminCall = await h.call('invite', { tenantId: w.acme, email: 'x@example.test', role: 'member' }, admin2.token);
  assert.equal(adminCall.error.code, 'NOT_A_MEMBER');
  h.record({
    id: 'T9b', test: 'revocation: dual-tenant + nested-role', persona: 'dual-tenant user / removed admin',
    attempt: 'remove dual user from ACME only; remove a second admin',
    status: '200/400', code: 'scoped rows / NOT_A_MEMBER',
    body: 'dual user keeps exactly Borealis; ex-admin reads 0 rows and admin calls refuse',
    state: 'Borealis membership row still active; ACME memberships removed; admin-role entry gone',
  });
});

test('L1 removeMember is retryable: a half-failed removal (roles still granted) is finished by calling it again', async (t) => {
  if (h.liveSkip(t, 'simulating the half-failed removal needs a master-key role edit — recorded in the local evidence')) return;
  const victim = await h.addMember(w.acmeAdmin.token, w.acme, 'member', 'l1_victim');
  await mustCall(h, 'removeMember', { tenantId: w.acme, userId: victim.objectId }, w.acmeAdmin.token);
  // Simulate the half-failed case: the membership row is 'removed' but a role entry survived the crash.
  const role = (await h.master('_Role', { name: `tenant_${w.acme}_member` }))[0];
  await h.rest('PUT', `/classes/_Role/${role.objectId}`, { users: { __op: 'AddRelation', objects: [ptr('_User', victim.objectId)] } }, { master: true });
  assert.equal((await h.rest('GET', '/classes/Task', undefined, { session: victim.token })).json.results.length, 2,
    'half-failed: the lingering role entry still grants reads (the documented window)');
  const again = await mustCall(h, 'removeMember', { tenantId: w.acme, userId: victim.objectId }, w.acmeAdmin.token);
  assert.equal(again.alreadyRemoved, true, 'retry reports the already-removed membership');
  assert.deepEqual((await h.rest('GET', '/classes/Task', undefined, { session: victim.token })).json.results, [],
    'retry finished the role cleanup');
  h.record({
    id: 'L1', test: 'removeMember retry', persona: 'ACME admin',
    attempt: 'removeMember; role entry re-added with the master key (simulated crash); removeMember again',
    status: 200, code: null,
    body: 'second call answers {removed:true, alreadyRemoved:true}',
    state: 'reads 2 rows during the simulated half-failure, 0 after the retry',
  });
});

test('L2 the last admin cannot be removed (best effort — documented as not concurrency-safe)', async () => {
  const r = await h.call('removeMember', { tenantId: w.borealis, userId: w.borealisAdmin.objectId }, w.borealisAdmin.token);
  assert.equal(r.error.code, 'LAST_ADMIN');
  assert.equal((await h.master('Membership', { user: ptr('_User', w.borealisAdmin.objectId), tenant: ptr('Tenant', w.borealis) }))[0].status, 'active');
  h.record({
    id: 'L2', test: 'last admin', persona: 'Borealis admin',
    attempt: 'remove themselves while being the only admin',
    status: r.status, code: 'LAST_ADMIN 119',
    body: 'refusal points to deleteTenant instead',
    state: 'membership still active',
  });
});

test('T15 deleteTenant: paginated, interruptible (budget), retryable, idempotent — and everything shared survives', async () => {
  // A disposable tenant rich enough to need several pages: 1 admin, 1 member who is ALSO an ACME member
  // (the shared user whose other membership must survive), 2 projects, 25 tasks, 1 attachment, 2 open invites.
  const admin = await h.signUp('t15_admin');
  const doomed = (await mustCall(h, 'createTenant', { name: `Doomed ${RUN}` }, admin.token)).tenantId;
  const shared = await h.addMember(admin.token, doomed, 'member', 't15_shared');
  const invA = await mustCall(h, 'invite', { tenantId: w.acme, email: shared.email, role: 'member' }, w.acmeAdmin.token);
  await mustCall(h, 'acceptInvite', { token: invA.token }, shared.token);

  const p1 = (await mustCall(h, 'createProject', { tenantId: doomed, name: 'to delete 1' }, admin.token)).projectId;
  const p2 = (await mustCall(h, 'createProject', { tenantId: doomed, name: 'to delete 2' }, admin.token)).projectId;
  const taskIds = [];
  for (let i = 0; i < 25; i++) {
    taskIds.push((await mustCall(h, 'createTask', { tenantId: doomed, projectId: i % 2 ? p1 : p2, title: `doomed ${i}` }, shared.token)).id);
  }
  const att = await mustCall(h, 'attachFile', { taskId: taskIds[0], name: 'doomed.txt', base64: Buffer.from('to be deleted').toString('base64') }, shared.token);
  await mustCall(h, 'invite', { tenantId: doomed, email: 'never1@example.test', role: 'member' }, admin.token);
  await mustCall(h, 'invite', { tenantId: doomed, email: 'never2@example.test', role: 'admin' }, admin.token);

  // (a) interrupted run: a budget of 10 operations cannot finish 25 tasks + the rest.
  const first = await mustCall(h, 'deleteTenant', { tenantId: doomed, budget: 10 }, admin.token);
  assert.equal(first.done, false, 'the budget interrupts the run — this is the partial-failure case, deterministically');
  // During the partial state: new writes into the tenant are refused (concurrent-writes case, amendment 11)…
  const during = await h.call('createTask', { tenantId: doomed, projectId: p1, title: 'racing the delete' }, shared.token);
  assert.equal(during.error.code, 'TENANT_DELETING');
  if (h.canMaster) {
    const masterDuring = await h.rest('POST', '/classes/Task', { tenant: ptr('Tenant', doomed), project: ptr('Project', p1), title: 'master racing' }, { master: true });
    assert.match(masterDuring.json.error, /TENANT_DELETING/, '…even with the master key (the hook, not the guard)');
  } else {
    h.observe('T15 master-key write during deletion', 'SKIP live: needs the master key — hook refusal proven in the local run');
  }
  // …and the OTHER tenant is untouched mid-deletion.
  assert.equal((await h.master('Task', { tenant: ptr('Tenant', w.acme) })).length, 2);

  // (b) retries until done — the same call, no special resume arguments.
  let rounds = 1; let last = first;
  while (!last.done) {
    last = await mustCall(h, 'deleteTenant', { tenantId: doomed, budget: 10 }, admin.token);
    rounds++;
    assert.ok(rounds < 20, 'deletion converges');
  }
  h.observe('T15 deleteTenant rounds at budget 10', `${rounds} calls; final tallies ${JSON.stringify(last.deleted)}`);

  // (c) what is GONE: rows of every class, both roles, the attachment file.
  for (const cls of ['Task', 'Project', 'Invite', 'Membership', 'FileMeta']) {
    assert.equal((await h.master(cls, { tenant: ptr('Tenant', doomed) })).length, 0, `${cls}: no rows left`);
  }
  assert.equal((await h.master('Tenant', { objectId: doomed })).length, 0, 'tenant row gone');
  assert.equal((await h.master('_Role', { name: `tenant_${doomed}_member` })).length, 0, 'member role gone');
  assert.equal((await h.master('_Role', { name: `tenant_${doomed}_admin` })).length, 0, 'admin role gone');
  const file = await fetch(att.url);
  assert.ok([404, 403].includes(file.status), `the attachment URL no longer serves (HTTP ${file.status})`);

  // (d) what SURVIVES: the user accounts, the shared user's ACME membership, ACME's data, open sessions.
  assert.equal((await h.master('_User', { objectId: admin.objectId })).length, 1);
  assert.equal((await h.master('_User', { objectId: shared.objectId })).length, 1);
  const sharedAcme = await h.master('Membership', { user: ptr('_User', shared.objectId), tenant: ptr('Tenant', w.acme) });
  assert.equal(sharedAcme[0].status, 'active', "the shared user's ACME membership survives");
  assert.equal((await h.rest('GET', '/classes/Task', undefined, { session: shared.token })).json.results.length, 2,
    'and still reads the ACME tasks');

  // (e) idempotency after completion: the tenant is gone, so the guard answers NOT_A_MEMBER — no zombie path.
  const again = await h.call('deleteTenant', { tenantId: doomed }, admin.token);
  assert.equal(again.error.code, 'NOT_A_MEMBER');

  h.record({
    id: 'T15', test: 'delete a tenant', persona: 'tenant admin (of the doomed tenant)',
    attempt: `deleteTenant with budget 10, retried ${rounds}× until done; writes raced the deletion; repeat call after completion`,
    status: 200, code: `done:false ×${rounds - 1} then done:true; racing writes TENANT_DELETING 119; repeat NOT_A_MEMBER`,
    body: `final tallies ${JSON.stringify(last.deleted)}`,
    state: `all tenant rows/roles gone; attachment URL → HTTP ${file.status}; user accounts, ACME membership and ACME rows survive. Live API only — backups/logs out of scope`,
  });
});
