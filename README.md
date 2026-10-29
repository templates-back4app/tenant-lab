# tenant-lab

Companion lab for the Back4app blog post on multi-tenant SaaS isolation (Phase A — the article is not written
yet; title and scope are decided by what this lab measures). Two fictitious companies, **ACME** and
**Borealis**, share one Parse backend, and one rule holds: neither ever sees the other. Every cross-tenant
attack in the test matrix is a raw REST request holding only what a browser holds — App ID, REST/JS key, a
session token — and every refusal is recorded with its HTTP status, Parse code, response body and the
database state read back afterwards.

Built by Back4app Engineering · MIT. Local-only for now: nothing here has run against a live backend yet, and
the evidence files say so in their first paragraph.

## What it shows

One backend, four layers, each with ONE responsibility (they compose; none is claimed to hold alone):

| Layer | Responsibility | Where |
|---|---|---|
| Class-level permissions | no anonymous reads; **no client writes at all** — every create/update/delete goes through Cloud functions | `cloud/config.js` SCHEMA |
| Row ACLs | which signed-in users see a row: the tenant's member role reads `Tenant`/`Project`/`Task`; a `Membership` row is read by its user + the tenant's admins; `Invite`, `FileMeta` and `_Role` are read by nobody | set by the hooks, never by clients |
| Roles per tenant | `tenant_<id>_member` **contains** `tenant_<id>_admin`, so admins inherit member read and members inherit nothing | created by `createTenant` |
| Cloud functions + hooks | the single write path; every function declares its guard in a `GUARDS` table (the server refuses to start otherwise), and `beforeSave`/`beforeDelete` hooks re-validate **even master-key writes**: `tenant` is immutable, cross-tenant pointers (project, assignee, attachment) are rejected at write time, ACLs are recomputed server-side | `cloud/main.js`, `cloud/guards.js` |

The matrix (35 recorded rows, `docs/evidence/`): cross-tenant reads/writes/creates (T1–T3), forged ACLs (T4),
corrupted pointers written below the API with SQL (T5), count/where probes (T6), raw attachment URLs (T7/H1),
LiveQuery scoping and revocation (T8/T9), the deliberately unguarded function (T10, never in a default
deploy), dual-tenant users (T11), invite-token abuse and two parallel accepts of one single-use token
(T12/C-series), member-vs-admin boundaries (T13, R-series), anonymous access (T14), tenant deletion with
budget-interrupted retries (T15) — plus positive controls for every persona (P-series), because a system that
denies everything would pass most isolation tests.

## Repository layout

```
cloud/config.js        tunables, the schema (classes, CLPs, indexes), SETUP_ENABLED and DEMO_UNGUARDED switches
cloud/guards.js        the guard registry: a Cloud function missing from the GUARDS table fails the deploy at load
cloud/main.js          17 Cloud functions (the single write path) + the beforeSave/beforeDelete second guard
scripts/dev-server.mjs local parse-server 7.5.4: Postgres on 5433, LiveQuery for Task, fs files adapter, request log
scripts/setup.mjs      schema + CLPs: master key locally; Cloud function setupSchema (SETUP_ENABLED) on a live backend
scripts/seed-tenants.mjs  N tenants through the real client path (no master key), 16 req/s token bucket, resumable
scripts/evidence.mjs   turns the rows the tests record into docs/evidence/isolation-matrix-local-<date>.md + files-h1…
scripts/lib/           env/target selection, raw REST client (throttle retry, token bucket)
test/                  node:test suites, raw REST + raw websockets, no SDK: isolation, positive, roles, lifecycle,
                       invite-concurrency, files-h1, livequery, demo-unguarded (own process, DEMO_UNGUARDED=1)
docs/evidence/         generated evidence (local run); the live run will add its own dated files + local-vs-live.md
docs/notes/build-diary.md  what was observed while building, dated, including what failed
```

## Run it locally

Prerequisites: Node 22+, PostgreSQL on port 5433 (`brew install postgresql@17`, started on 5433). No Back4app
account, no `.env` needed — the local server uses fixed throwaway keys (`scripts/lib/env.mjs`).

```bash
npm install
npm test                      # 35 tests: starts its own parse-server per suite file (database tenant_test),
                              # regenerates docs/evidence/isolation-matrix-local-<date>.md and files-h1-local-<date>.md
npm run dev:server            # long-running server on http://localhost:1341/parse (database tenant_dev)
npm run setup -- --local      # classes, CLPs (incl. master-only _Role), indexes — against the dev server
npm run seed:tenants -- --local --tenants 3 --projects 1 --tasks 2    # tiny proof of the live seeding script
npm run seed:tenants -- --local --join 3                              # one user joining N tenants (H4 shape)
```

The T10 demonstration (`demoTaskById`, the function that forgets the membership check) only exists while
`DEMO_UNGUARDED=1` is set in the environment of a throwaway server; the suite proves both halves: 141
"Invalid function" by default, and the leak + the fixed `getTask` in a separate flagged process.

## Pointing it at a live backend — LATER

The live phase (Back4app run of the same suites, H2 revocation-delay distribution, H3/H4 scale measurements,
storage per tenant) is deliberately **not** part of this repository state. When the coordinator opens it:

1. Create a backend app, copy App ID + JS/REST key into `.env` (leave `MASTER_KEY` empty — everything
   privileged runs inside Cloud Code).
2. Upload `cloud/main.js`, `cloud/config.js` **and** `cloud/guards.js` in the Cloud Code editor, confirm the
   "Files pending deploy (3)" badge, Deploy — and prove it with a request, never with the dialog:
   `POST /functions/myTenants` must answer `{"code":209,…}`; `141 Invalid function` means it did not ship
   (the sibling repos hit a first-deploy-ships-nothing quirk on fresh backends: reload the editor, make each
   file dirty, confirm the badge, Deploy again).
3. `npm run setup` (no master key → calls `setupSchema`, gated by `cloud/config.js` `SETUP_ENABLED`).
4. `TEST_SERVER_URL=https://parseapi.back4app.com npm test` — note the suites currently purge and master-read
   only locally; the live run needs the gated inspection/cleanup helpers to be added (open point for the live
   phase, see the diary).
5. Before the backend has real tenants: `SETUP_ENABLED = false` in `cloud/config.js`, re-upload, Deploy,
   verify you get `SETUP_DISABLED`.

## Security model in one paragraph

Sign-up is public; everything else requires a session (CLP) and a row ACL that only the tenant's roles ever
appear in, written exclusively by the server. The membership row — not the role — is what every Cloud function
checks (`requireMembership`), so the grant order Membership→role fails closed: a half-granted user can call
functions but reads nothing until `myTenants` reconciles the role entry from the membership row. Invites are
single-use (atomic `useCount` increment decides concurrent accepts), expire, are bound to the invited e-mail
and stored only as SHA-256 hashes. Removal flips the membership row first (fresh writes die), then the role
entries (fresh reads die); open LiveQuery subscriptions drain within the server's auth-cache window, which is
measured, never claimed instant. Deleting a tenant is a budgeted, retryable sweep that preserves user accounts
and their other memberships, and its claim covers the live API only — never backups or platform logs.

## Guarantees and limits (do not overstate them)

- Hooks are validation, **not database constraints**. Cross-record invariants are best effort under
  concurrency: duplicate `Membership` rows from racing accepts are self-healed on the next membership check
  (active-then-oldest wins); the last-admin check can race; the Parse schema API cannot declare unique indexes.
- A crash between an invite's atomic consume and the `usedBy` write burns the token with no self-service
  repair (master-key fix only). A crash between the last membership and the tenant row in `deleteTenant`
  leaves an empty `deleting` tenant that only the master key can remove.
- **Attachments are excluded from the local isolation claim**: the raw file URL serves without a session on
  the local fs adapter (H1 supported locally), and the membership-checked `getAttachment` is an access path,
  not URL protection. Back4app behaviour is to measure in the live phase.
- The invite e-mail binding compares the *stored* `_User.email`; production should require a verified address.
- Revocation: fresh requests are refused when `removeMember` returns; an open LiveQuery subscription drains
  within the auth cache window (~5 s locally); data already downloaded is unrecoverable by definition.
- No rate limiting is configured by this lab. Local numbers (latency, delays) are loopback numbers; only the
  live run will be quoted in the article.

## License

MIT — see `LICENSE`.
