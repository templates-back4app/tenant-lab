# Build diary — tenant-lab

## 2026-10-29 — Phase A built and green locally (35 tests, 0 skipped isolation rows)

Built against the amended brief (`brief-multi-tenant-saas-blog-post-v1.md` + amendments, amendments win).
Local only: parse-server 7.5.4, Postgres 17 on :5433, Node 25 (engines >=22). No Back4app backend was touched.

**Decisions**

- **Role hierarchy** per amendment 1: `tenant_<id>_member.roles` contains `tenant_<id>_admin`. Admin users are
  added ONLY to the admin role and read member-ACL rows through the nesting (P3); R1 asserts both relation
  directions in the database, R2/T13 are the negative. Role names carry the tenant objectId, nothing
  customer-identifying.
- **One write path** per amendment 2: CLPs close create/update/delete on every tenant class to the master key;
  the 17 Cloud functions are the only writers. Forged inputs (foreign tenantId, ACL param, cross-tenant
  pointers) are tested THROUGH the functions (T3/T4/T11); direct-REST refusals are separate assertions that
  prove only the CLP layer (T2/T3).
- **Guard registry** per amendment 3: `cloud/guards.js` has no Parse dependency so the suite can unit-test it
  (R3). `define()` in main.js resolves the target tenant (param `tenantId`, or the `tenant` pointer of a
  loaded object) and runs `requireMembership` BEFORE the handler. Id-targeted functions answer 101 for
  "missing" and "not yours" alike, so object ids are not an existence oracle (T2). A function missing from
  GUARDS throws at load — a forgotten guard fails the deploy, not the tenant.
- **Membership row is the source of truth** for the write path; roles only grant row reads. Grant order
  Membership→role therefore fails closed; `myTenants` reconciles a missing role entry from the membership row
  (R5). Revocation order is the same (membership first: writes die; roles second: reads die), and
  `removeMember` retries finish a half-done role cleanup (L1).
- **Invites** per amendment 5: token returned once to the inviting admin (no mailer in the lab), stored as
  SHA-256 hex (hook enforces the shape), expiring, bound to the invited e-mail, single-use. Concurrent accepts
  are decided by an atomic `increment('useCount')` — the save response carries the new value, so exactly one
  caller sees 1. Used tokens answer INVITE_USED before the e-mail comparison, so a replay reveals nothing
  about the invited address (T12; originally the mismatch fired first — fixed after the test caught it).
- **T10** ships OFF: `demoTaskById` is not even registered unless `DEMO_UNGUARDED=1` (env var read at Cloud
  Code load). `node --test` runs each file in its own process, so `demo-unguarded.test.mjs` sets the flag for
  a throwaway server only. Static ESM imports are hoisted, which silently defeated the flag until the test
  failed — the file now uses a dynamic `import()` after setting the env var.
- **deleteTenant** takes a `budget` (max delete ops per call) and returns `done:false` when it runs out — that
  is both the live-plan throttle safety and the deterministic "partial failure": the T15 test interrupts it at
  budget 10, proves racing writes get TENANT_DELETING (hook — even master-key writes), retries to completion,
  and checks what survives (accounts, the shared user's other membership, the other tenant).
- **Files**: `FileMeta` (fileName → tenant, master-only) exists so the Task hook can reject a cross-tenant
  `attachment` pointer at write time (amendment 4 lists attachment among the pointers; a Parse File itself has
  no tenant) and so deleteTenant can find files to destroy.

**Findings while running it locally**

- Parse Server CLP refusals: anonymous find/get on `requiresAuthentication` classes → 400/404 Parse **101** on
  member-readable classes, **119** on master-only classes and on client writes. Recorded per class in T14.
- `include=` across a deliberately corrupted pointer (SQL `UPDATE "Task" SET project = <borealis id>`) does
  NOT leak: parse-server drops the unreadable included object from the response entirely (the `project` key
  vanishes). No afterFind mitigation needed locally; re-verify on Back4app/MongoDB in the live phase (T5).
- A Parse.File decoded from a master-key query inside Cloud Code returned `url()` of
  `undefined/files/<appId>/<name>` — composed the absolute URL from `Parse.serverURL` as a fallback in
  `getAttachment`. Worth re-checking on Back4app.
- **H1 locally: supported.** The raw file URL serves the full contents with no App ID, key or session
  (fs-files-adapter; `fileUpload` client paths closed, POST /files → 400/130). The membership-checked
  `getAttachment` works for member+admin, refuses foreign/anonymous/removed — and the raw URL re-measured
  afterwards still answers 200. Guessing the name without the random prefix: 404. Evidence:
  `docs/evidence/files-h1-local-2026-10-29.md`; Back4app columns all "to measure (live)".
- **LiveQuery works locally** (T8/T9 are NOT live-only): `ParseServer.createLiveQueryServer(httpServer, {appId,
  masterKey, serverURL}, parseOptions)` on the same express server, raw ws protocol in the tests. An
  unfiltered Task subscription by an ACME member delivered the ACME sentinel and zero Borealis events. First
  attempt had no events at all — two self-inflicted bugs: (a) my test helper's `next()` ignored events that
  arrived before it was called (fixed: backlog-aware `waitFor`); (b) a master-key subscription gets `Failed
  matching CLP … user needs to be authenticated` verbose-logged and NOTHING delivered — the LQ server's CLP
  check does not honour the master key, so don't debug with master subscriptions.
- **Revocation on an open subscription (local observation, delay itself is live-only):** last event 4.9–5.0 s
  after `removeMember` returned, silent from ~6.6 s — the LiveQuery server's auth cache (`cacheTimeout`,
  default 5 s). Matches the prior single-tenant data point in the brief (4.4–6.4 s, feasibility-lab
  2026-10-20). Also found in RestWrite: saving a _User clears that user's cached roles, but removal edits the
  _Role rows, not the user, so the cache runs its TTL out. Fresh REST requests were refused 8 ms after
  `removeMember` returned (T9).
- **Concurrent accepts created duplicate Membership rows** under a 10-way race (C2 caught it): the winner's
  `ensure()` and a repair-path `ensure()` both saw "no membership" and both created one. No unique index is
  possible through the Parse schema API (same caveat as game-backend-starter's Player.user), so the fix is the
  house pattern: `findMembership` self-heals duplicates (active-before-removed, then oldest, wins) on every
  membership check. A loser of the increment race can also transiently see INVITE_USED before the winner
  records `usedBy` (observed in C2: 4 ok + 1 INVITE_USED for the same user); a later retry repairs (C3).
- Postgres adapter stores pointers as plain objectId text and ACLs in `_rperm`/`_wperm` — corrupting a row for
  T5 is a one-line `UPDATE` via psql.
- `seed-tenants` proof run (local, rps 50): 3 tenants × 1 project × 2 tasks = 18 requests in 0.5 s; re-run
  skipped all 3 (9 requests); `--join 3` made `seed-42-joiner` a member of all three. Resume = deterministic
  usernames + login-on-202 + skip-by-tenant-name; `--from` jumps the loop.
- Suite runtime: ~35 s total; the T9 LiveQuery drain test alone takes ~12 s (bounded 10 s probe window).

**Deviations from the brief (with reasons)**

- Export-per-tenant: cut by amendment 11 — not built.
- `deleteProject` refuses while tasks exist (PROJECT_NOT_EMPTY) instead of cascading — no silent mass delete
  outside deleteTenant.
- Id-targeted refusals use 101 instead of 119 (existence oracle, see Decisions). The brief's T2 says
  "refused"; 101 is the refusal.
- The brief's §4.2 row-ACL design ("write: admin role or the row's owner") was superseded by amendment 2's
  one-write-path: row ACLs grant READS only, writes stay master-only everywhere.
- `LAST_ADMIN`: removeMember refuses to remove the only admin (not in the brief; without it a tenant is
  orphaned one call after creation). Best effort under concurrency, documented.

**Open for the live phase (and questions for the coordinator)**

1. The live suites need a gated inspection/cleanup path: locally the tests purge the database and read state
   back with the master key; on Back4app the master key stays in the dashboard. Proposal: add
   `testInspect`/`testCleanup` behind SETUP_ENABLED like game-backend-starter — OK to add, or should the live
   run put MASTER_KEY in .env instead (sibling repos avoid that)?
2. Cloud Code upload is now three files (main.js, config.js, guards.js) — the deploy quirk recipe (badge must
   say 3) is in the README; worth a dry run on a scratch backend first.
3. Does Back4app's Cloud Code (Node 19, Parse Server 7.5.2 per the game-backend diary) have global `fetch` for
   `getAttachment`? Fallback would be Parse.Cloud.httpRequest.
4. Re-verify on MongoDB: include-across-corrupted-pointer (T5 read side — needs a Mongo-side corruption
   method; the dashboard's data browser can write the raw pointer), CLP code pairs (101/119), index creation
   (the brief's risk note about createdAt indexes), and the LiveQuery auth-cache drain timing (H2 proper,
   10 runs).
5. H1 live: raw URL behaviour on Back4app's file store, and whether any signed/expiring URL option exists
   (brief amendment 6 wants the gate decided by measurement).
6. Scale (H3/H4): seed-tenants is ready (16 req/s default, resumable); needs the plan decision from brief §0
   (Free plan cap vs 1,000 tenants) before the live run.

Next: hand back for the live phase. Nothing in this repo has been pushed anywhere.
