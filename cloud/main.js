// File: cloud/main.js · CommonJS · Parse Server 7.x (Back4app runs Cloud Code on Node 19: no Node 20+ only features)
//
// ONE write path: every create/update/delete of tenant data (Tenant, Membership, Project, Task, Invite,
// FileMeta, _Role membership) goes through the Cloud functions below, which run with the master key. Clients
// only read, through a session plus the row ACL. The class-level permissions (cloud/config.js, applied by
// scripts/setup.mjs or setupSchema) close every client write before an ACL or hook is even consulted, and the
// hooks in section 5 are the second guard: they validate even master-key writes, so a Cloud function that
// forgets a check cannot move a row across tenants or hand out a foreign ACL.
//
// Guards: every function is registered through `define` (cloud/guards.js), which refuses to start the server
// unless the function is listed in the GUARDS table below. 'member'/'admin' functions declare how to resolve
// their target tenant and the wrapper runs requireMembership before the handler ever sees the request.
//
// Error convention (same as the sibling repos): functions throw Parse.Error with a numeric Parse code and a
// JSON string message {"code":"NOT_A_MEMBER","message":"…", …extra}. Parse.Error only carries (number,
// string), so the string is the envelope; scripts/lib/rest.mjs parseCloudError() unwraps it.
'use strict';

const crypto = require('crypto');
const config = require('./config.js');
const guards = require('./guards.js');

const MASTER = { useMasterKey: true };
const PE = Parse.Error;

// ---------------------------------------------------------------------------------------------------------
// 1. Helpers
// ---------------------------------------------------------------------------------------------------------

function fail(code, message, extra, parseCode) {
  const payload = Object.assign({ code: code, message: message }, extra || {});
  throw new PE(parseCode || PE.VALIDATION_ERROR, JSON.stringify(payload));
}

function requireUser(request) {
  if (!request.user) {
    fail('UNAUTHENTICATED', 'Sign in before calling this function.', null, PE.INVALID_SESSION_TOKEN);
  }
  return request.user;
}

function requireName(value, field) {
  if (typeof value !== 'string') fail('INVALID_ARGS', field + ' must be a string', { field: field });
  const trimmed = value.replace(/\s+/g, ' ').trim();
  if (trimmed.length < config.NAME_MIN || trimmed.length > config.NAME_MAX) {
    fail('INVALID_ARGS', field + ' must be ' + config.NAME_MIN + '..' + config.NAME_MAX + ' characters', { field: field });
  }
  return trimmed;
}

function requireId(value, field) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9]{8,32}$/.test(value)) {
    fail('INVALID_ARGS', field + ' must be an objectId', { field: field });
  }
  return value;
}

function requireRoleKind(value) {
  if (config.MEMBERSHIP_ROLES.indexOf(value) === -1) {
    fail('INVALID_ARGS', "role must be one of '" + config.MEMBERSHIP_ROLES.join("'/'") + "'", { field: 'role' });
  }
  return value;
}

function normalizeEmail(value) {
  if (typeof value !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
    fail('INVALID_ARGS', 'email must look like an e-mail address', { field: 'email' });
  }
  return value.trim().toLowerCase();
}

function sha256(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function iso(d) {
  return d instanceof Date ? d.toISOString() : d || null;
}

function tenantPointer(tenantId) {
  const t = new Parse.Object('Tenant');
  t.id = tenantId;
  return t;
}

async function fetchById(className, objectId) {
  const q = new Parse.Query(className);
  q.equalTo('objectId', objectId);
  return q.first(MASTER); // undefined when missing — never throws 101 like .get()
}

// Active membership of `user` in `tenant`, or null. The Membership row is the source of truth the write path
// trusts; the per-tenant roles only grant row READS (ACLs), so a half-granted role never widens the write path.
// Self-heals the duplicate rows two concurrent accepts can create (the Parse schema API cannot declare a
// unique index on {user, tenant}): active-before-removed, then oldest, wins; the rest are deleted. Best
// effort, same pattern and caveat as the sibling repos — see README "Guarantees and limits".
async function findMembership(userId, tenantId, anyStatus) {
  const q = new Parse.Query('Membership');
  q.equalTo('user', (function () { const u = new Parse.Object('_User'); u.id = userId; return u; })());
  q.equalTo('tenant', tenantPointer(tenantId));
  if (!anyStatus) q.equalTo('status', 'active');
  q.ascending('createdAt');
  q.limit(5);
  const rows = await q.find(MASTER);
  if (rows.length > 1) {
    rows.sort(function (a, b) {
      const act = (a.get('status') === 'active' ? 0 : 1) - (b.get('status') === 'active' ? 0 : 1);
      return act !== 0 ? act : a.createdAt - b.createdAt;
    });
    await Parse.Object.destroyAll(rows.slice(1), MASTER);
  }
  return rows[0] || null;
}

// The guard helper every tenant-scoped function goes through (wired in by `define` below, never called ad hoc
// by a handler alone). role === 'admin' additionally requires the membership's role to be admin.
async function requireMembership(user, tenantId, role, options) {
  const opts = options || {};
  const tenant = await fetchById('Tenant', tenantId);
  if (!tenant) fail('NOT_A_MEMBER', 'No such tenant, or you are not an active member of it.', { tenantId: tenantId }, PE.OPERATION_FORBIDDEN);
  const membership = await findMembership(user.id, tenantId);
  if (!membership) fail('NOT_A_MEMBER', 'No such tenant, or you are not an active member of it.', { tenantId: tenantId }, PE.OPERATION_FORBIDDEN);
  if (tenant.get('status') === 'deleting' && !opts.allowDeleting) {
    fail('TENANT_DELETING', 'This tenant is being deleted.', { tenantId: tenantId }, PE.OPERATION_FORBIDDEN);
  }
  if (role === 'admin' && membership.get('role') !== 'admin') {
    fail('ADMIN_REQUIRED', 'Only a tenant admin may do this.', { tenantId: tenantId }, PE.OPERATION_FORBIDDEN);
  }
  return { tenant: tenant, membership: membership };
}

async function findRole(name) {
  const q = new Parse.Query(Parse.Role);
  q.equalTo('name', name);
  return q.first(MASTER);
}

// Adds `user` to the tenant role for `roleKind` ('admin' → tenant_<id>_admin, 'member' → tenant_<id>_member).
// Idempotent: Parse relations ignore duplicate adds.
async function addUserToTenantRole(user, tenantId, roleKind) {
  const role = await findRole(config.roleName(tenantId, roleKind));
  if (!role) fail('ROLE_MISSING', 'Role ' + config.roleName(tenantId, roleKind) + ' does not exist.', { tenantId: tenantId }, PE.INTERNAL_SERVER_ERROR);
  role.getUsers().add(user);
  await role.save(null, MASTER);
}

async function removeUserFromTenantRoles(user, tenantId) {
  for (const kind of config.MEMBERSHIP_ROLES) {
    const role = await findRole(config.roleName(tenantId, kind));
    if (!role) continue; // deleteTenant may have removed it already
    role.getUsers().remove(user);
    await role.save(null, MASTER);
  }
}

async function userHasRoleEntry(userId, name) {
  const q = new Parse.Query(Parse.Role);
  q.equalTo('name', name);
  q.equalTo('users', (function () { const u = new Parse.Object('_User'); u.id = userId; return u; })());
  return !!(await q.first(MASTER));
}

function membershipJson(membership, tenant) {
  return {
    tenantId: tenant.id,
    name: tenant.get('name'),
    role: membership.get('role'),
    status: membership.get('status'),
    since: iso(membership.createdAt),
  };
}

function taskJson(task) {
  const attachment = task.get('attachment');
  return {
    id: task.id,
    tenantId: task.get('tenant') ? task.get('tenant').id : null,
    projectId: task.get('project') ? task.get('project').id : null,
    title: task.get('title'),
    assigneeId: task.get('assignee') ? task.get('assignee').id : null,
    attachment: attachment ? { name: attachment.name(), url: attachment.url() } : null,
    updatedAt: iso(task.updatedAt),
  };
}

// ---------------------------------------------------------------------------------------------------------
// 2. Guard registration: the GUARDS table and the `define` wrapper
// ---------------------------------------------------------------------------------------------------------
// Every Parse.Cloud.define in this file goes through `define(name, spec)`. cloud/guards.js refuses names that
// are missing from this table (the server throws while loading Cloud Code — a forgotten guard fails the
// deploy, not the tenant). For 'member'/'admin' guards the spec must say how to find the target tenant:
//   spec.tenantFrom: 'params'  → request.params.tenantId names the tenant (the caller knows which tenant).
//   spec.target:     className → request.params.<idParam> names an object; its `tenant` pointer is the
//                                target, and refusals answer OBJECT_NOT_FOUND (101) whether the object is
//                                missing or belongs to a tenant the caller is no member of, so probing ids
//                                cannot distinguish "does not exist" from "not yours".

const GUARDS = {
  createTenant: 'authenticated',
  myTenants: 'authenticated',
  acceptInvite: 'authenticated',
  createProject: 'member',
  updateProject: 'member',
  createTask: 'member',
  updateTask: 'member',
  deleteTask: 'member',
  getTask: 'member',
  attachFile: 'member',
  getAttachment: 'member',
  invite: 'admin',
  removeMember: 'admin',
  deleteProject: 'admin',
  deleteTenant: 'admin',
  setupSchema: 'setup',
  testInspect: 'setup',  // live test runs: master-key state read-backs without the master key leaving the dashboard
  testCleanup: 'setup',  // live test runs: delete ONLY what a suite run created (its run prefix, users < 2 h old)
  demoTaskById: 'demo-unguarded', // T10: only registered when config.DEMO_UNGUARDED (never in a default deploy)
};

const registry = guards.createRegistry(GUARDS, { demoEnabled: config.DEMO_UNGUARDED });

function define(name, spec) {
  registry.define(name, function (guard) {
    Parse.Cloud.define(name, async function (request) {
      if (guard === 'setup') {
        requireSetupEnabled();
        return spec.handler(request, {});
      }
      if (guard === 'demo-unguarded') {
        return spec.handler(request, {});
      }
      const user = requireUser(request);
      if (guard === 'authenticated') {
        return spec.handler(request, { user: user });
      }
      // 'member' / 'admin'
      const ctx = { user: user };
      let tenantId;
      if (spec.tenantFrom === 'params') {
        tenantId = requireId(request.params && request.params.tenantId, 'tenantId');
      } else {
        const idParam = spec.idParam;
        const objectId = requireId(request.params && request.params[idParam], idParam);
        const target = await fetchById(spec.target, objectId);
        if (!target || !target.get('tenant')) {
          fail('OBJECT_NOT_FOUND', 'Object not found.', { id: objectId }, PE.OBJECT_NOT_FOUND);
        }
        ctx[spec.targetAs || 'target'] = target;
        tenantId = target.get('tenant').id;
      }
      try {
        const got = await requireMembership(user, tenantId, guard === 'admin' ? 'admin' : undefined, spec.guardOptions);
        ctx.tenant = got.tenant;
        ctx.membership = got.membership;
      } catch (e) {
        // Id-targeted functions hide the object's existence from non-members.
        if (spec.target && e instanceof PE) {
          let env = null;
          try { env = JSON.parse(e.message); } catch (_) { /* not an envelope */ }
          if (env && env.code === 'NOT_A_MEMBER') {
            fail('OBJECT_NOT_FOUND', 'Object not found.', { id: request.params[spec.idParam] }, PE.OBJECT_NOT_FOUND);
          }
        }
        throw e;
      }
      return spec.handler(request, ctx);
    });
  });
}

function requireSetupEnabled() {
  if (!config.SETUP_ENABLED) {
    fail('SETUP_DISABLED', 'Setup helpers are disabled (cloud/config.js: SETUP_ENABLED=false).', null, PE.OPERATION_FORBIDDEN);
  }
}

// ---------------------------------------------------------------------------------------------------------
// 3. Tenant lifecycle
// ---------------------------------------------------------------------------------------------------------

// createTenant({name}) → {tenantId, name, role:'admin'}. Any signed-in user can found a tenant and becomes
// its first admin. Write order (here and in acceptInvite): Membership row first, then the role entry — the
// Membership row is what the function guard checks, so a crash in between leaves the user able to call
// functions but unable to READ rows (fail-closed); myTenants() reconciles the missing role entry from the
// Membership row on the user's next listing. The reverse order would leave readable rows with no governing
// membership, which has no safe reconciliation.
define('createTenant', {
  handler: async function (request, ctx) {
    const name = requireName(request.params && request.params.name, 'name');
    const user = ctx.user;

    const tenant = new Parse.Object('Tenant');
    tenant.set('name', name);
    tenant.set('status', 'active');
    tenant.set('createdBy', user);
    await tenant.save(null, MASTER); // ACL is recomputed by the hook on the update below, once the id exists

    // Roles: tenant_<id>_member CONTAINS tenant_<id>_admin, so admins inherit member read; members inherit
    // nothing (review point 1). Role rows carry an empty ACL: master-key-only, like everything role-related.
    const adminRole = new Parse.Role(config.roleName(tenant.id, 'admin'), new Parse.ACL());
    await adminRole.save(null, MASTER);
    const memberRole = new Parse.Role(config.roleName(tenant.id, 'member'), new Parse.ACL());
    memberRole.getRoles().add(adminRole);
    await memberRole.save(null, MASTER);

    tenant.set('memberRole', memberRole);
    tenant.set('adminRole', adminRole);
    await tenant.save(null, MASTER);

    const membership = new Parse.Object('Membership');
    membership.set('user', user);
    membership.set('tenant', tenant);
    membership.set('role', 'admin');
    membership.set('status', 'active');
    await membership.save(null, MASTER);

    await addUserToTenantRole(user, tenant.id, 'admin');

    return { tenantId: tenant.id, name: name, role: 'admin' };
  },
});

// myTenants() → {tenants:[{tenantId, name, role, status, since}]}. Also the reconciliation path for the
// half-granted case: for every active membership it checks the role entry the Membership row implies and
// re-adds it when missing (master-key write, scoped to the caller's own memberships).
define('myTenants', {
  handler: async function (request, ctx) {
    const q = new Parse.Query('Membership');
    q.equalTo('user', ctx.user);
    q.equalTo('status', 'active');
    q.include('tenant');
    q.ascending('createdAt');
    q.limit(1000);
    const memberships = await q.find(MASTER);
    const out = [];
    let repaired = 0;
    for (const m of memberships) {
      const tenant = m.get('tenant');
      if (!tenant) continue; // tenant deleted mid-flight
      const kind = m.get('role') === 'admin' ? 'admin' : 'member';
      if (!(await userHasRoleEntry(ctx.user.id, config.roleName(tenant.id, kind)))) {
        await addUserToTenantRole(ctx.user, tenant.id, kind);
        repaired++;
      }
      out.push(membershipJson(m, tenant));
    }
    return { tenants: out, repairedRoleEntries: repaired };
  },
});

// ---------------------------------------------------------------------------------------------------------
// 4. Invitations and members
// ---------------------------------------------------------------------------------------------------------

// invite({tenantId, email, role}) → {inviteId, token, expiresAt}. Admin only. The raw token is returned ONCE
// to the inviting admin (a real product would e-mail it; the lab has no mailer) and only its SHA-256 hex is
// stored. Invite rows are unreadable by every client (CLP), so the hash never leaves the server either.
define('invite', {
  tenantFrom: 'params',
  handler: async function (request, ctx) {
    const email = normalizeEmail(request.params.email);
    const roleKind = requireRoleKind(request.params.role);
    const token = crypto.randomBytes(config.INVITE_TOKEN_BYTES).toString('hex');
    const invite = new Parse.Object('Invite');
    invite.set('tenant', ctx.tenant);
    invite.set('email', email);
    invite.set('role', roleKind);
    invite.set('tokenHash', sha256(token));
    invite.set('expiresAt', new Date(Date.now() + config.INVITE_TTL_MS));
    invite.set('status', 'pending');
    invite.set('useCount', 0);
    invite.set('createdBy', ctx.user);
    await invite.save(null, MASTER);
    return { inviteId: invite.id, token: token, expiresAt: iso(invite.get('expiresAt')) };
  },
});

// acceptInvite({token}) → {tenantId, name, role} (+ repaired:true on the reconciliation path).
// Single-use, expiring, bound to the invited e-mail (compared against the caller's stored e-mail — the lab
// does not verify e-mail addresses; production should require a verified address, see README).
// Concurrency: the winner of two parallel accepts is decided by an atomic increment of useCount (the save
// response carries the incremented value); exactly one caller sees 1. The winner then (a) marks the invite
// used, (b) writes the Membership row, (c) adds the role entry — in that order. A retry by the SAME user with
// the same token repairs whatever of (b)/(c) is missing. A crash between the increment and (a) burns the
// token with no usedBy recorded; only the master key can untangle that, and README "Guarantees and limits"
// says so.
define('acceptInvite', {
  handler: async function (request, ctx) {
    const user = ctx.user;
    if (typeof request.params.token !== 'string' || request.params.token.length < 16) {
      fail('INVALID_ARGS', 'token must be the invite token string', { field: 'token' });
    }
    const q = new Parse.Query('Invite');
    q.equalTo('tokenHash', sha256(request.params.token));
    q.include('tenant');
    const invite = await q.first(MASTER);
    if (!invite) fail('INVITE_INVALID', 'This invite does not exist.', null, PE.OPERATION_FORBIDDEN);
    const tenant = invite.get('tenant');
    if (!tenant || tenant.get('status') !== 'active') {
      fail('INVITE_INVALID', 'This invite no longer has a tenant.', null, PE.OPERATION_FORBIDDEN);
    }
    // A consumed token answers INVITE_USED to everyone but the user who consumed it (reconciliation path) —
    // checked before the e-mail comparison so a replay reveals nothing about the invited address.
    const usedStatus = invite.get('status') === 'used';
    if (usedStatus) {
      const usedBy = invite.get('usedBy');
      if (!usedBy || usedBy.id !== user.id) fail('INVITE_USED', 'This invite was already used.', null, PE.OPERATION_FORBIDDEN);
    }
    const myEmail = (user.get('email') || '').toLowerCase();
    if (!myEmail || myEmail !== invite.get('email')) {
      fail('INVITE_EMAIL_MISMATCH', 'This invite was issued to a different e-mail address.', null, PE.OPERATION_FORBIDDEN);
    }
    if (invite.get('expiresAt') < new Date()) {
      fail('INVITE_EXPIRED', 'This invite has expired.', { expiresAt: iso(invite.get('expiresAt')) }, PE.OPERATION_FORBIDDEN);
    }

    const ensure = async function (repaired) {
      let membership = await findMembership(user.id, tenant.id, true);
      if (!membership) {
        membership = new Parse.Object('Membership');
        membership.set('user', user);
        membership.set('tenant', tenant);
      }
      membership.set('role', invite.get('role'));
      membership.set('status', 'active');
      await membership.save(null, MASTER);
      await findMembership(user.id, tenant.id, true); // heal the duplicate a concurrent ensure may have created
      await addUserToTenantRole(user, tenant.id, invite.get('role'));
      const result = { tenantId: tenant.id, name: tenant.get('name'), role: invite.get('role') };
      if (repaired) result.repaired = true;
      return result;
    };

    if (usedStatus) return ensure(true); // reconciliation: the user who consumed the token retries



    invite.increment('useCount');
    await invite.save(null, MASTER);
    if (invite.get('useCount') !== 1) {
      // A concurrent accept won the increment race. If it was this same user (double-click), repair; else refuse.
      await invite.fetch(MASTER);
      const usedBy = invite.get('usedBy');
      if (usedBy && usedBy.id === user.id) return ensure(true);
      fail('INVITE_USED', 'This invite was already used.', null, PE.OPERATION_FORBIDDEN);
    }
    invite.set('status', 'used');
    invite.set('usedBy', user);
    await invite.save(null, MASTER);
    return ensure(false);
  },
});

// removeMember({tenantId, userId}) → {removed:true}. Admin only. Revocation model (brief amendment 7): when
// this function returns, every FRESH request by the removed user against this tenant is refused — the
// Membership row is 'removed' (function guard) and both role entries are gone (row reads). Open LiveQuery
// subscriptions are a measured delay, never claimed instant (T9); already-downloaded data is unrecoverable.
// Order: Membership first (writes die), then roles (reads die). Retrying after a half-failure finishes the
// role cleanup ({alreadyRemoved:true}).
define('removeMember', {
  tenantFrom: 'params',
  handler: async function (request, ctx) {
    const userId = requireId(request.params.userId, 'userId');
    const membership = await findMembership(userId, ctx.tenant.id, true);
    if (!membership) fail('MEMBER_NOT_FOUND', 'That user has no membership in this tenant.', { userId: userId }, PE.OBJECT_NOT_FOUND);
    const target = new Parse.Object('_User');
    target.id = userId;

    const alreadyRemoved = membership.get('status') === 'removed';
    if (!alreadyRemoved) {
      if (membership.get('role') === 'admin') {
        // Best-effort last-admin check: not safe under concurrent removals (no cross-row transaction here);
        // see README "Guarantees and limits".
        const admins = new Parse.Query('Membership');
        admins.equalTo('tenant', ctx.tenant);
        admins.equalTo('role', 'admin');
        admins.equalTo('status', 'active');
        if ((await admins.count(MASTER)) <= 1) {
          fail('LAST_ADMIN', 'This is the last admin; delete the tenant instead.', null, PE.OPERATION_FORBIDDEN);
        }
      }
      membership.set('status', 'removed');
      await membership.save(null, MASTER);
    }
    await removeUserFromTenantRoles(target, ctx.tenant.id);
    return { removed: true, alreadyRemoved: alreadyRemoved };
  },
});

// deleteTenant({tenantId, budget?}) → {done, deleted:{…}}. Admin only; works while status='deleting', so an
// interrupted run can be RETRIED by calling it again (same answer shape; already-deleted rows simply no
// longer show up). `budget` caps delete operations per call (default cloud/config.js DELETE_DEFAULT_BUDGET):
// when the budget runs out mid-way the call returns done:false and the caller calls again — that is also how
// the partial-failure test interrupts it deterministically. Order: files, FileMeta, Task, Project, Invite —
// then roles (reads die), memberships, and the Tenant row last. User accounts and their memberships in OTHER
// tenants are never touched. The claim covers the live API only: backups and platform logs are out of scope
// (README). A crash between the last membership and the tenant row leaves an empty 'deleting' tenant that
// only the master key can remove — "Guarantees and limits".
define('deleteTenant', {
  tenantFrom: 'params',
  guardOptions: { allowDeleting: true },
  handler: async function (request, ctx) {
    const budget = request.params.budget === undefined ? config.DELETE_DEFAULT_BUDGET : request.params.budget;
    if (typeof budget !== 'number' || !Number.isInteger(budget) || budget < 1) {
      fail('INVALID_ARGS', 'budget must be a positive integer', { field: 'budget' });
    }
    const r = await wipeTenant(ctx.tenant, budget);
    return { done: r.done, deleted: r.deleted, budget: budget };
  },
});

// The sweep deleteTenant and testCleanup share. Order: files, FileMeta, Task, Project, Invite — then roles
// (reads die), memberships, and the Tenant row last. Stops when `budget` delete operations are spent
// (done:false); calling again resumes.
async function wipeTenant(tenant, budget) {
  if (tenant.get('status') !== 'deleting') {
    tenant.set('status', 'deleting'); // from here the hooks refuse every new write into this tenant
    await tenant.save(null, MASTER);
  }

  let ops = 0;
  const deleted = { files: 0, fileMeta: 0, tasks: 0, projects: 0, invites: 0, memberships: 0, roles: 0, tenant: 0 };
  const out = function (done) { return { done: done, deleted: deleted, ops: ops }; };

  // Attachment files first (while FileMeta still knows their names), then the rows, page by page.
  for (;;) {
    if (ops >= budget) return out(false);
    const q = new Parse.Query('FileMeta');
    q.equalTo('tenant', tenant);
    q.limit(Math.min(config.DELETE_PAGE_SIZE, budget - ops));
    const metas = await q.find(MASTER);
    if (!metas.length) break;
    for (const meta of metas) {
      const file = new Parse.File(meta.get('fileName'));
      try {
        await file.destroy(MASTER);
        deleted.files++;
      } catch (e) {
        // Already gone (retry) or the adapter cannot delete; the row still goes, and T15 measures what is
        // left reachable.
      }
    }
    await Parse.Object.destroyAll(metas, MASTER);
    deleted.fileMeta += metas.length;
    ops += metas.length;
  }

  for (const step of [
    { className: 'Task', key: 'tasks' },
    { className: 'Project', key: 'projects' },
    { className: 'Invite', key: 'invites' },
  ]) {
    for (;;) {
      if (ops >= budget) return out(false);
      const q = new Parse.Query(step.className);
      q.equalTo('tenant', tenant);
      q.limit(Math.min(config.DELETE_PAGE_SIZE, budget - ops));
      const rows = await q.find(MASTER);
      if (!rows.length) break;
      await Parse.Object.destroyAll(rows, MASTER);
      deleted[step.key] += rows.length;
      ops += rows.length;
    }
  }

  // Roles before memberships: once the roles are gone no row of this tenant is readable by anyone.
  for (const kind of config.MEMBERSHIP_ROLES) {
    const role = await findRole(config.roleName(tenant.id, kind));
    if (role) {
      if (ops >= budget) return out(false);
      await role.destroy(MASTER);
      deleted.roles++;
      ops++;
    }
  }

  for (;;) {
    if (ops >= budget) return out(false);
    const q = new Parse.Query('Membership');
    q.equalTo('tenant', tenant);
    q.limit(Math.min(config.DELETE_PAGE_SIZE, budget - ops));
    const rows = await q.find(MASTER);
    if (!rows.length) break;
    await Parse.Object.destroyAll(rows, MASTER);
    deleted.memberships += rows.length;
    ops += rows.length;
  }

  await tenant.destroy(MASTER);
  deleted.tenant = 1;
  return out(true);
}

// ---------------------------------------------------------------------------------------------------------
// 5. Projects and tasks (per-tenant data)
// ---------------------------------------------------------------------------------------------------------

define('createProject', {
  tenantFrom: 'params',
  handler: async function (request, ctx) {
    const name = requireName(request.params.name, 'name');
    const project = new Parse.Object('Project');
    project.set('tenant', ctx.tenant);
    project.set('name', name);
    await project.save(null, MASTER); // the hook stamps the ACL (member-role read, no writes)
    return { projectId: project.id, tenantId: ctx.tenant.id, name: name };
  },
});

define('updateProject', {
  target: 'Project', idParam: 'projectId', targetAs: 'project',
  handler: async function (request, ctx) {
    const name = requireName(request.params.name, 'name');
    ctx.project.set('name', name);
    await ctx.project.save(null, MASTER);
    return { projectId: ctx.project.id, name: name };
  },
});

// deleteProject({projectId}): admin; refused while the project still has tasks (no silent cascade).
define('deleteProject', {
  target: 'Project', idParam: 'projectId', targetAs: 'project',
  handler: async function (request, ctx) {
    const q = new Parse.Query('Task');
    q.equalTo('project', ctx.project);
    const n = await q.count(MASTER);
    if (n > 0) fail('PROJECT_NOT_EMPTY', 'Delete or move its ' + n + ' task(s) first.', { tasks: n }, PE.OPERATION_FORBIDDEN);
    await ctx.project.destroy(MASTER);
    return { deleted: true, projectId: ctx.project.id };
  },
});

// createTask({tenantId, projectId, title, assigneeId?}). The handler validates the pointers and the hook
// validates them AGAIN (second guard): a future function that forgets cannot cross tenants either.
define('createTask', {
  tenantFrom: 'params',
  handler: async function (request, ctx) {
    const title = requireName(request.params.title, 'title');
    const projectId = requireId(request.params.projectId, 'projectId');
    const project = await fetchById('Project', projectId);
    if (!project || project.get('tenant').id !== ctx.tenant.id) {
      fail('OBJECT_NOT_FOUND', 'Object not found.', { id: projectId }, PE.OBJECT_NOT_FOUND);
    }
    const task = new Parse.Object('Task');
    task.set('tenant', ctx.tenant);
    task.set('project', project);
    task.set('title', title);
    if (request.params.assigneeId !== undefined) {
      const assigneeId = requireId(request.params.assigneeId, 'assigneeId');
      const m = await findMembership(assigneeId, ctx.tenant.id);
      if (!m) fail('ASSIGNEE_NOT_MEMBER', 'assignee must be an active member of the tenant.', { assigneeId: assigneeId }, PE.OPERATION_FORBIDDEN);
      const assignee = new Parse.Object('_User');
      assignee.id = assigneeId;
      task.set('assignee', assignee);
    }
    await task.save(null, MASTER);
    return taskJson(task);
  },
});

// updateTask({taskId, title?, projectId?, assigneeId?|null}). The tenant is immutable: there is no parameter
// to change it, and both the handler and the hook refuse an attempt that names one anyway (T11 dual-tenant).
define('updateTask', {
  target: 'Task', idParam: 'taskId', targetAs: 'task',
  handler: async function (request, ctx) {
    const p = request.params;
    if (p.tenantId !== undefined && p.tenantId !== ctx.tenant.id) {
      fail('TENANT_IMMUTABLE', 'A task cannot change tenant.', { taskId: ctx.task.id }, PE.OPERATION_FORBIDDEN);
    }
    if (p.title !== undefined) ctx.task.set('title', requireName(p.title, 'title'));
    if (p.projectId !== undefined) {
      const project = await fetchById('Project', requireId(p.projectId, 'projectId'));
      if (!project || project.get('tenant').id !== ctx.tenant.id) {
        fail('OBJECT_NOT_FOUND', 'Object not found.', { id: p.projectId }, PE.OBJECT_NOT_FOUND);
      }
      ctx.task.set('project', project);
    }
    if (p.assigneeId !== undefined) {
      if (p.assigneeId === null) {
        ctx.task.unset('assignee');
      } else {
        const assigneeId = requireId(p.assigneeId, 'assigneeId');
        if (!(await findMembership(assigneeId, ctx.tenant.id))) {
          fail('ASSIGNEE_NOT_MEMBER', 'assignee must be an active member of the tenant.', { assigneeId: assigneeId }, PE.OPERATION_FORBIDDEN);
        }
        const assignee = new Parse.Object('_User');
        assignee.id = assigneeId;
        ctx.task.set('assignee', assignee);
      }
    }
    await ctx.task.save(null, MASTER);
    return taskJson(ctx.task);
  },
});

define('deleteTask', {
  target: 'Task', idParam: 'taskId', targetAs: 'task',
  handler: async function (request, ctx) {
    const attachment = ctx.task.get('attachment');
    if (attachment) {
      try { await new Parse.File(attachment.name()).destroy(MASTER); } catch (e) { /* already gone */ }
      const q = new Parse.Query('FileMeta');
      q.equalTo('fileName', attachment.name());
      const metas = await q.find(MASTER);
      if (metas.length) await Parse.Object.destroyAll(metas, MASTER);
    }
    await ctx.task.destroy(MASTER);
    return { deleted: true, taskId: ctx.task.id };
  },
});

// getTask({taskId}): the GUARDED read-by-id — what demoTaskById (T10) should have been.
define('getTask', {
  target: 'Task', idParam: 'taskId', targetAs: 'task',
  handler: async function (request, ctx) {
    return taskJson(ctx.task);
  },
});

// ---------------------------------------------------------------------------------------------------------
// 6. Attachments (hypothesis H1)
// ---------------------------------------------------------------------------------------------------------

// attachFile({taskId, name, base64}) → {name, url}. The file is written by the server, recorded in FileMeta
// (fileName → tenant) BEFORE it is attached, and the Task hook refuses any attachment whose FileMeta row
// names a different tenant — that is the "cross-tenant attachment pointer" guard of the brief. Whether the
// returned URL is readable WITHOUT a session is exactly what H1 measures; this function makes no promise.
define('attachFile', {
  target: 'Task', idParam: 'taskId', targetAs: 'task',
  handler: async function (request, ctx) {
    const p = request.params;
    const name = requireName(p.name, 'name').replace(/[^A-Za-z0-9._-]/g, '_');
    if (typeof p.base64 !== 'string' || !p.base64.length) fail('INVALID_ARGS', 'base64 must be a non-empty base64 string', { field: 'base64' });
    const bytes = Buffer.from(p.base64, 'base64').length;
    if (bytes > config.MAX_ATTACHMENT_BYTES) {
      fail('ATTACHMENT_TOO_LARGE', 'attachment exceeds ' + config.MAX_ATTACHMENT_BYTES + ' bytes', { bytes: bytes, max: config.MAX_ATTACHMENT_BYTES });
    }
    const file = new Parse.File(name, { base64: p.base64 });
    await file.save(MASTER);
    const meta = new Parse.Object('FileMeta');
    meta.set('fileName', file.name());
    meta.set('tenant', ctx.tenant);
    meta.set('task', ctx.task);
    await meta.save(null, MASTER);
    ctx.task.set('attachment', file);
    await ctx.task.save(null, MASTER);
    return { taskId: ctx.task.id, name: file.name(), url: file.url() };
  },
});

// getAttachment({taskId}) → {name, base64}. The membership-checked read path (H1 mitigation candidate): the
// server fetches the bytes and hands them to a verified member. It does NOT make the raw URL private — the
// evidence file records both measurements, before and after.
define('getAttachment', {
  target: 'Task', idParam: 'taskId', targetAs: 'task',
  handler: async function (request, ctx) {
    const attachment = ctx.task.get('attachment');
    if (!attachment) fail('NO_ATTACHMENT', 'This task has no attachment.', { taskId: ctx.task.id }, PE.OBJECT_NOT_FOUND);
    // A File decoded from a master-key query carries a relative URL here (observed locally: "undefined/files/…");
    // compose the absolute one from the server's own configuration when that happens.
    let url = attachment.url();
    if (!/^https?:\/\//.test(url || '')) {
      url = String(Parse.serverURL).replace(/\/+$/, '') + '/files/' + Parse.applicationId + '/' + attachment.name();
    }
    const res = await fetch(url); // Node 19 on Back4app has global fetch; verify in the live run
    if (!res.ok) fail('ATTACHMENT_UNREADABLE', 'The file adapter answered HTTP ' + res.status + '.', { status: res.status }, PE.FILE_READ_ERROR);
    const buf = Buffer.from(await res.arrayBuffer());
    return { taskId: ctx.task.id, name: attachment.name(), base64: buf.toString('base64') };
  },
});

// ---------------------------------------------------------------------------------------------------------
// 7. T10: the deliberately vulnerable function (never in a default deploy — cloud/config.js DEMO_UNGUARDED)
// ---------------------------------------------------------------------------------------------------------

// demoTaskById({taskId}): reads ANY task with the master key and no membership check. This is the bug the
// article demonstrates: a missing authorization check can leak tenant data. The guarded version is getTask.
define('demoTaskById', {
  handler: async function (request) {
    requireUser(request); // authentication alone does NOT isolate tenants — that is the point of the demo
    const task = await fetchById('Task', requireId(request.params && request.params.taskId, 'taskId'));
    if (!task) fail('OBJECT_NOT_FOUND', 'Object not found.', null, PE.OBJECT_NOT_FOUND);
    return taskJson(task);
  },
});

// ---------------------------------------------------------------------------------------------------------
// 8. Setup helper (behind cloud/config.js SETUP_ENABLED)
// ---------------------------------------------------------------------------------------------------------

async function fetchSchema(className) {
  try {
    return await new Parse.Schema(className).get();
  } catch (e) {
    if (e && e.code === PE.INVALID_CLASS_NAME) return null; // 103: class does not exist
    throw e;
  }
}

function addFieldsTo(schema, fields) {
  Object.keys(fields).forEach(function (name) {
    const spec = fields[name];
    if (spec.type === 'Pointer') schema.addPointer(name, spec.targetClass);
    else schema.addField(name, spec.type);
  });
}

// setupSchema({allowRerun?}) → {classes:[…]}. Creates the classes with fields, CLPs and indexes, or brings
// existing ones up to date (fields and indexes added, CLPs re-applied, nothing removed), plus the master-only
// CLP on _Role. Idempotent. Tripwire: refuses once 2+ Tenants exist unless {allowRerun:true} — a stray call
// on an app with data should be noisy, not silent. It is not a security boundary: SETUP_ENABLED is.
define('setupSchema', {
  handler: async function (request) {
    const p = request.params || {};
    const tenantCount = (await fetchSchema('Tenant')) ? await new Parse.Query('Tenant').count(MASTER) : 0;
    if (tenantCount >= 2 && p.allowRerun !== true) {
      fail('SETUP_LOCKED', 'Tenant already holds ' + tenantCount + ' rows; pass {allowRerun:true} to re-apply the schema.', { tenantCount: tenantCount });
    }
    const classes = [];
    for (const def of config.SCHEMA) {
      const have = await fetchSchema(def.className);
      const schema = new Parse.Schema(def.className);
      schema.setCLP(def.classLevelPermissions);
      if (!have) {
        addFieldsTo(schema, def.fields);
        Object.keys(def.indexes || {}).forEach(function (name) { schema.addIndex(name, def.indexes[name]); });
        await schema.save();
        classes.push({ className: def.className, action: 'created', newFields: Object.keys(def.fields), newIndexes: Object.keys(def.indexes || {}) });
        continue;
      }
      const newFields = {};
      Object.keys(def.fields).forEach(function (name) { if (!have.fields || !have.fields[name]) newFields[name] = def.fields[name]; });
      const haveIdx = have.indexes || {};
      const newIndexes = Object.keys(def.indexes || {}).filter(function (name) { return !haveIdx[name]; });
      addFieldsTo(schema, newFields);
      newIndexes.forEach(function (name) { schema.addIndex(name, def.indexes[name]); });
      await schema.update();
      classes.push({ className: def.className, action: 'updated', newFields: Object.keys(newFields), newIndexes: newIndexes });
    }
    const roleSchema = new Parse.Schema('_Role');
    roleSchema.setCLP(config.ROLE_CLP);
    await roleSchema.update();
    classes.push({ className: '_Role', action: 'updated', newFields: [], newIndexes: [] });
    return { classes: classes, tenantCount: tenantCount };
  },
});

// ---------------------------------------------------------------------------------------------------------
// 8b. Live-run test helpers (behind the same SETUP_ENABLED). Why they exist: on Back4app the master key stays
// in the dashboard, but the suite's STATE assertions read rows back with master rights and its teardown must
// delete what it created. Cloud Code runs with master rights, so these do it on the caller's behalf. Nothing
// authenticates the caller — that is what SETUP_ENABLED is for; switch it off before real users arrive.
// ---------------------------------------------------------------------------------------------------------

const INSPECT_CLASSES = config.SCHEMA.map(function (d) { return d.className; }).concat(['_Role', '_User']);

// Parse Server may hand Cloud functions their params already decoded (pointers as Parse.Object) or raw
// (REST JSON, as on Back4app). Normalize either into what Parse.Query accepts.
function decodeParam(value) {
  if (value instanceof Parse.Object || value instanceof Date) return value;
  return Parse._decode(null, value);
}

// A Parse.Query from a `where` object of field → value EQUALITIES (values REST-encoded: a pointer is
// {__type:'Pointer',…}, a date {__type:'Date', iso}). Operators ($in, $regex, …) are not accepted; an
// equality on a relation column (e.g. _Role.users or _Role.roles against a pointer) works and is how the
// suite asserts role state. Same pattern as the sibling repo.
function queryFromWhere(className, where) {
  const q = new Parse.Query(className);
  Object.keys(where).forEach(function (key) {
    const value = decodeParam(where[key]);
    if (value && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Parse.Object) && !(value instanceof Date) && !(value instanceof Parse.File)) {
      fail('INVALID_ARGS', 'where.' + key + ' must be a plain value or a REST-encoded pointer/date (no operators)', { field: 'where.' + key });
    }
    q.equalTo(key, value);
  });
  return q;
}

// testInspect({className, where?, limit?, count?}) → {results:[toJSON…]} or {count}. Master-rights read of one
// whitelisted class, equality-where only. The live suite's state assertions run through this.
define('testInspect', {
  handler: async function (request) {
    const p = request.params || {};
    if (INSPECT_CLASSES.indexOf(p.className) === -1) {
      fail('INVALID_ARGS', 'className must be one of ' + INSPECT_CLASSES.join(', '), { field: 'className' });
    }
    const where = p.where === undefined ? {} : p.where;
    if (!where || typeof where !== 'object' || Array.isArray(where)) fail('INVALID_ARGS', 'where must be an object', { field: 'where' });
    const q = queryFromWhere(p.className, where);
    if (p.count === true) return { className: p.className, count: await q.count(MASTER) };
    const limit = p.limit === undefined ? 100 : p.limit;
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) fail('INVALID_ARGS', 'limit must be an integer in 1..1000', { field: 'limit' });
    q.limit(limit);
    q.ascending('createdAt');
    const rows = await q.find(MASTER);
    return { className: p.className, results: rows.map(function (r) { return r.toJSON(); }) };
  },
});

// testCleanup({runPrefix}) → {tenants, users, sessions}. Deletes ONLY what one suite run created:
//   - every Tenant whose name contains the run prefix (full wipeTenant sweep: rows, roles, files), and
//   - every _User whose username starts with the prefix AND was created less than 2 hours ago (+ its sessions).
// The prefix shape is enforced (zz + ≥8 base36 chars, as test/helpers.mjs generates) so a stray call can
// never sweep real tenants or users. Parallel runs have distinct prefixes and never touch each other.
define('testCleanup', {
  handler: async function (request) {
    const p = request.params || {};
    if (typeof p.runPrefix !== 'string' || !/^zz[a-z0-9]{8,32}$/.test(p.runPrefix)) {
      fail('INVALID_ARGS', 'runPrefix must match ^zz[a-z0-9]{8,32}$ (the suite run prefix)', { field: 'runPrefix' });
    }
    const counts = { tenants: 0, users: 0, sessions: 0 };
    for (;;) {
      const tq = new Parse.Query('Tenant');
      tq.contains('name', p.runPrefix);
      tq.limit(20);
      const tenants = await tq.find(MASTER);
      if (!tenants.length) break;
      for (const tenant of tenants) {
        let r;
        do { r = await wipeTenant(tenant, config.DELETE_DEFAULT_BUDGET); } while (!r.done);
        counts.tenants++;
      }
    }
    const cutoff = new Date(Date.now() - 2 * 60 * 60 * 1000);
    for (;;) {
      const uq = new Parse.Query('_User');
      uq.startsWith('username', p.runPrefix);
      uq.greaterThan('createdAt', cutoff);
      uq.limit(100);
      const users = await uq.find(MASTER);
      if (!users.length) break;
      const sq = new Parse.Query('_Session');
      sq.containedIn('user', users);
      sq.limit(1000);
      const sessions = await sq.find(MASTER);
      if (sessions.length) await Parse.Object.destroyAll(sessions, MASTER);
      counts.sessions += sessions.length;
      await Parse.Object.destroyAll(users, MASTER);
      counts.users += users.length;
    }
    return counts;
  },
});

registry.assertAllRegistered();

// getAttachment relies on global fetch (Node 18+; Back4app Cloud Code runs Node 19). Log — never throw — when
// it is missing, so a deploy on an older runtime degrades that one function instead of the whole app.
if (typeof fetch !== 'function') {
  console.log('tenant-lab warning: global fetch is not available in this Cloud Code runtime — getAttachment will fail; port it to Parse.Cloud.httpRequest.');
}

// ---------------------------------------------------------------------------------------------------------
// 9. Hooks: the second guard. They run for EVERY write, master key included, so a Cloud function that forgot
// its membership check (or a future seed script) still cannot cross tenants.
// ---------------------------------------------------------------------------------------------------------

function hookFail(code, message, extra) {
  throw new PE(PE.OPERATION_FORBIDDEN, JSON.stringify(Object.assign({ code: code, message: message }, extra || {})));
}

function denyClientWrites(request, className, action) {
  if (!request.master) {
    hookFail('CLOUD_CODE_ONLY', className + ' rows are ' + action + ' by Cloud Code only.');
  }
}

// Reject a changed `tenant` pointer on update. On create, require it.
function enforceTenantField(request, className) {
  const obj = request.object;
  if (!obj.existed()) {
    if (!obj.get('tenant')) hookFail('TENANT_REQUIRED', className + ' rows must carry a tenant pointer.');
    return;
  }
  if (obj.dirty('tenant')) {
    const before = request.original ? request.original.get('tenant') : null;
    const after = obj.get('tenant');
    if (!after || !before || before.id !== after.id) {
      hookFail('TENANT_IMMUTABLE', className + '.tenant is immutable after create.', { className: className });
    }
  }
}

// New rows (and updates) are refused while their tenant is being deleted; missing tenants are refused too.
async function requireActiveTenant(request) {
  const tenant = await fetchById('Tenant', request.object.get('tenant').id);
  if (!tenant) hookFail('TENANT_MISSING', 'The tenant of this row does not exist.');
  if (tenant.get('status') === 'deleting') hookFail('TENANT_DELETING', 'This tenant is being deleted; no new writes.');
  return tenant;
}

function aclReadRole(roleNames, userIds) {
  const acl = new Parse.ACL();
  acl.setPublicReadAccess(false);
  acl.setPublicWriteAccess(false);
  (roleNames || []).forEach(function (name) { acl.setRoleReadAccess(name, true); });
  (userIds || []).forEach(function (id) { acl.setReadAccess(id, true); });
  return acl;
}

Parse.Cloud.beforeSave('Tenant', async function (request) {
  denyClientWrites(request, 'Tenant', 'written');
  const obj = request.object;
  if (obj.existed()) {
    for (const field of ['memberRole', 'adminRole', 'createdBy']) {
      if (obj.dirty(field) && request.original && request.original.get(field)) {
        hookFail('IMMUTABLE_FIELD', 'Tenant.' + field + ' is immutable once set.', { field: field });
      }
    }
    // The row ACL is recomputed from the tenant's own id, whatever the caller supplied (T4-class forgery).
    obj.setACL(aclReadRole([config.roleName(obj.id, 'member')]));
  } else {
    obj.setACL(new Parse.ACL()); // unreadable until the roles exist; createTenant's second save fixes it
  }
});

Parse.Cloud.beforeSave('Membership', async function (request) {
  denyClientWrites(request, 'Membership', 'written');
  const obj = request.object;
  enforceTenantField(request, 'Membership');
  if (!obj.existed()) {
    if (!obj.get('user')) hookFail('INVALID_ROW', 'Membership rows must carry a user pointer.');
    await requireActiveTenant(request);
  } else if (obj.dirty('user')) {
    hookFail('IMMUTABLE_FIELD', 'Membership.user is immutable after create.', { field: 'user' });
  }
  if (config.MEMBERSHIP_ROLES.indexOf(obj.get('role')) === -1) hookFail('INVALID_ROW', 'Membership.role must be admin or member.');
  if (['active', 'removed'].indexOf(obj.get('status')) === -1) hookFail('INVALID_ROW', 'Membership.status must be active or removed.');
  // ACL: the member themselves + the tenant's admins read it; nobody writes it.
  obj.setACL(aclReadRole([config.roleName(obj.get('tenant').id, 'admin')], [obj.get('user').id]));
});

Parse.Cloud.beforeSave('Project', async function (request) {
  denyClientWrites(request, 'Project', 'written');
  enforceTenantField(request, 'Project');
  if (!request.object.existed()) await requireActiveTenant(request);
  request.object.setACL(aclReadRole([config.roleName(request.object.get('tenant').id, 'member')]));
});

Parse.Cloud.beforeSave('Task', async function (request) {
  denyClientWrites(request, 'Task', 'written');
  const obj = request.object;
  enforceTenantField(request, 'Task');
  if (!obj.existed()) await requireActiveTenant(request);
  const tenantId = obj.get('tenant').id;

  // Cross-tenant pointers are rejected AT WRITE TIME, whoever is writing (review point 4).
  if (obj.dirty('project') || !obj.existed()) {
    const project = obj.get('project');
    if (!project) hookFail('INVALID_ROW', 'Task.project is required.');
    const row = await fetchById('Project', project.id);
    if (!row || row.get('tenant').id !== tenantId) {
      hookFail('CROSS_TENANT_POINTER', 'Task.project must belong to the task\'s tenant.', { field: 'project' });
    }
  }
  if (obj.dirty('assignee') && obj.get('assignee')) {
    if (!(await findMembership(obj.get('assignee').id, tenantId))) {
      hookFail('CROSS_TENANT_POINTER', 'Task.assignee must be an active member of the task\'s tenant.', { field: 'assignee' });
    }
  }
  if (obj.dirty('attachment') && obj.get('attachment')) {
    const q = new Parse.Query('FileMeta');
    q.equalTo('fileName', obj.get('attachment').name());
    const meta = await q.first(MASTER);
    if (!meta || meta.get('tenant').id !== tenantId) {
      hookFail('CROSS_TENANT_POINTER', 'Task.attachment must be a file uploaded for this tenant (attachFile).', { field: 'attachment' });
    }
  }
  obj.setACL(aclReadRole([config.roleName(tenantId, 'member')]));
});

Parse.Cloud.beforeSave('Invite', async function (request) {
  denyClientWrites(request, 'Invite', 'written');
  enforceTenantField(request, 'Invite');
  if (!request.object.existed()) await requireActiveTenant(request);
  if (typeof request.object.get('tokenHash') !== 'string' || !/^[0-9a-f]{64}$/.test(request.object.get('tokenHash'))) {
    hookFail('INVALID_ROW', 'Invite.tokenHash must be a SHA-256 hex digest (never the raw token).');
  }
  request.object.setACL(new Parse.ACL()); // no client reads Invite rows, ever
});

Parse.Cloud.beforeSave('FileMeta', async function (request) {
  denyClientWrites(request, 'FileMeta', 'written');
  enforceTenantField(request, 'FileMeta');
  request.object.setACL(new Parse.ACL());
});

// _Role: membership in tenant roles is managed by Cloud Code alone (review point 5). The CLP already denies
// clients; this hook is the second guard for the role class itself.
Parse.Cloud.beforeSave('_Role', function (request) {
  denyClientWrites(request, '_Role', 'written');
});
Parse.Cloud.beforeDelete('_Role', function (request) {
  denyClientWrites(request, '_Role', 'deleted');
});

['Tenant', 'Membership', 'Project', 'Task', 'Invite', 'FileMeta'].forEach(function (className) {
  Parse.Cloud.beforeDelete(className, function (request) {
    denyClientWrites(request, className, 'deleted');
  });
});
