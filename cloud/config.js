// File: cloud/config.js · CommonJS · Parse Server 7.x (Back4app runs Cloud Code on Node 19 — no Node 20+ only
// features here). Tunables, the schema definition and the two switches (SETUP_ENABLED, DEMO_UNGUARDED), shared
// by cloud/main.js, the scripts and the tests. Upload this file together with main.js and guards.js.
'use strict';

// ---------------------------------------------------------------------------------------------------------
// Switches
// ---------------------------------------------------------------------------------------------------------

// Setup helper (setupSchema in cloud/main.js). It runs with the master key on behalf of an UNAUTHENTICATED
// caller, so a fresh Back4app app can be set up with the REST key only (the master key never leaves the
// dashboard). While it is true, anyone holding the App ID + REST/JS key can (re-)apply the schema.
//   >>> Before the backend has real tenants: set SETUP_ENABLED = false, upload config.js again, Deploy. <<<
const SETUP_ENABLED = true;

// The deliberately vulnerable demonstration function (demoTaskById, test T10 of the brief): a Cloud function
// that reads a Task by id with the master key and NO membership check. It exists to show that a missing
// authorization check can leak tenant data. With DEMO_UNGUARDED=false (the default, and the only value that
// should ever be deployed) the function is NOT registered at all: calling it answers Parse 141
// "Invalid function". The local test suite enables it for one test file only, via the environment variable
// DEMO_UNGUARDED=1 in a throwaway server process.
const DEMO_UNGUARDED = process.env.DEMO_UNGUARDED === '1';

// ---------------------------------------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------------------------------------

const NAME_MIN = 1;
const NAME_MAX = 80;                           // Tenant.name, Project.name, Task.title
const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // invites expire after 7 days
const INVITE_TOKEN_BYTES = 32;                 // raw token entropy; only its SHA-256 hex lands in the database
const DELETE_PAGE_SIZE = 200;                  // rows deleted per query page in deleteTenant
const DELETE_DEFAULT_BUDGET = 10000;           // max delete operations per deleteTenant call (resumable)
const MAX_ATTACHMENT_BYTES = 100 * 1024;       // attachFile: decoded size cap (this is a lab, not a file host)
const MEMBERSHIP_ROLES = ['admin', 'member'];

// Role names carry the tenant's objectId, never customer-identifying text.
function roleName(tenantId, which) {
  return 'tenant_' + tenantId + '_' + which;
}

// ---------------------------------------------------------------------------------------------------------
// Schema: fields, class-level permissions, indexes. One definition for the local parse-server (Postgres)
// and for Back4app (MongoDB), applied by scripts/setup.mjs (master key) or the Cloud function setupSchema.
//
// The write path is ONE: every create/update/delete of tenant data goes through the Cloud functions in
// main.js. The CLPs below therefore deny every client write; clients only read, through a session plus the
// row ACL. What each layer is responsible for:
//   - CLP:      no anonymous reads, no client writes at all (even before any ACL or hook is consulted).
//   - row ACL:  which signed-in users see a row — read via the tenant's member role (Project, Task, Tenant),
//               or owner + admin role (Membership). It never grants client writes.
//   - roles:    tenant_<id>_member CONTAINS tenant_<id>_admin, so admins inherit member read and members
//               inherit nothing (Parse grants a containing role's permissions to the roles it contains).
//   - hooks:    second guard behind the functions — they validate even master-key writes (tenant immutable,
//               cross-tenant pointers rejected, ACL recomputed server-side). See cloud/main.js section 5.
//   - functions:the only write path; each one declares its guard in the GUARDS table (cloud/main.js) and the
//               server refuses to start if a function is registered without one.
// ---------------------------------------------------------------------------------------------------------

const CLP_MASTER_ONLY = {};                              // nobody but the master key
const CLP_AUTHENTICATED = { requiresAuthentication: true };
const pointerTo = function (targetClass) { return { type: 'Pointer', targetClass: targetClass }; };

// Readable classes: a session is required, then the row ACL decides. All writes are master-only.
function readableByMembers(extra) {
  return Object.assign({
    find: CLP_AUTHENTICATED, get: CLP_AUTHENTICATED, count: CLP_AUTHENTICATED,
    create: CLP_MASTER_ONLY, update: CLP_MASTER_ONLY, delete: CLP_MASTER_ONLY, addField: CLP_MASTER_ONLY,
  }, extra || {});
}

// Sensitive classes: not even reads from clients. Invite rows hold token hashes; FileMeta maps files to
// tenants; _Role membership is managed by Cloud Code alone.
const CLP_ALL_MASTER = {
  find: CLP_MASTER_ONLY, get: CLP_MASTER_ONLY, count: CLP_MASTER_ONLY,
  create: CLP_MASTER_ONLY, update: CLP_MASTER_ONLY, delete: CLP_MASTER_ONLY, addField: CLP_MASTER_ONLY,
};

const SCHEMA = [
  {
    className: 'Tenant',
    why: 'one row per company; row ACL read = member role, so only members ever see it',
    fields: {
      name: { type: 'String' },
      memberRole: pointerTo('_Role'),
      adminRole: pointerTo('_Role'),
      createdBy: pointerTo('_User'),
      status: { type: 'String' }, // 'active' | 'deleting'
    },
    classLevelPermissions: readableByMembers(),
    indexes: { tenant_status: { status: 1 } },
  },
  {
    className: 'Membership',
    why: 'one row per user × tenant; the source of truth the function guard checks. Row ACL: the user + the tenant admin role (admins list members, a member sees only their own row).',
    fields: {
      user: pointerTo('_User'),
      tenant: pointerTo('Tenant'),
      role: { type: 'String' },   // 'admin' | 'member'
      status: { type: 'String' }, // 'active' | 'removed'
    },
    classLevelPermissions: readableByMembers(),
    indexes: {
      membership_user_tenant: { user: 1, tenant: 1 },
      membership_tenant: { tenant: 1 },
    },
  },
  {
    className: 'Project',
    why: 'per-tenant data; row ACL read = member role, write = nobody (writes go through functions)',
    fields: {
      tenant: pointerTo('Tenant'),
      name: { type: 'String' },
    },
    classLevelPermissions: readableByMembers(),
    indexes: { project_tenant: { tenant: 1 } },
  },
  {
    className: 'Task',
    why: 'per-tenant data with cross-class pointers (project, assignee) and a file attachment — the surfaces T3–T7 attack',
    fields: {
      tenant: pointerTo('Tenant'),
      project: pointerTo('Project'),
      title: { type: 'String' },
      assignee: pointerTo('_User'),
      attachment: { type: 'File' },
    },
    classLevelPermissions: readableByMembers(),
    indexes: {
      task_tenant: { tenant: 1 },
      task_project: { project: 1 },
    },
  },
  {
    className: 'Invite',
    why: 'pending invitations. Clients never read them: the token is a secret (stored as SHA-256), the e-mail is personal data. All access through invite/acceptInvite.',
    fields: {
      tenant: pointerTo('Tenant'),
      email: { type: 'String' },
      role: { type: 'String' },
      tokenHash: { type: 'String' },
      expiresAt: { type: 'Date' },
      status: { type: 'String' }, // 'pending' | 'used'
      usedBy: pointerTo('_User'),
      useCount: { type: 'Number' }, // atomic increment decides the winner of concurrent accepts
      createdBy: pointerTo('_User'),
    },
    classLevelPermissions: CLP_ALL_MASTER,
    indexes: {
      invite_tokenHash: { tokenHash: 1 },
      invite_tenant: { tenant: 1 },
    },
  },
  {
    className: 'FileMeta',
    why: 'maps every uploaded attachment (by file name) to its tenant and task, so the Task hook can reject a cross-tenant attachment pointer and deleteTenant can find the files to destroy',
    fields: {
      fileName: { type: 'String' },
      tenant: pointerTo('Tenant'),
      task: pointerTo('Task'),
    },
    classLevelPermissions: CLP_ALL_MASTER,
    indexes: {
      filemeta_fileName: { fileName: 1 },
      filemeta_tenant: { tenant: 1 },
    },
  },
];

// _Role gets a master-only CLP too (applied by setup): role membership is managed by Cloud Code alone, and
// clients have no reason to read role rows. Role resolution for ACL checks happens server-side and is not
// affected by the CLP.
const ROLE_CLP = CLP_ALL_MASTER;

module.exports = {
  SETUP_ENABLED: SETUP_ENABLED,
  DEMO_UNGUARDED: DEMO_UNGUARDED,
  NAME_MIN: NAME_MIN,
  NAME_MAX: NAME_MAX,
  INVITE_TTL_MS: INVITE_TTL_MS,
  INVITE_TOKEN_BYTES: INVITE_TOKEN_BYTES,
  DELETE_PAGE_SIZE: DELETE_PAGE_SIZE,
  DELETE_DEFAULT_BUDGET: DELETE_DEFAULT_BUDGET,
  MAX_ATTACHMENT_BYTES: MAX_ATTACHMENT_BYTES,
  MEMBERSHIP_ROLES: MEMBERSHIP_ROLES,
  roleName: roleName,
  SCHEMA: SCHEMA,
  ROLE_CLP: ROLE_CLP,
};
