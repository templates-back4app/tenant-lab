# Plan Usage (dashboard) — storage measurement for H3/H4

Plan: MVP (500K requests/month, 1 GB database storage, 50 GB file storage), region USA East.
Dashboard note: the Plan Usage page updates lazily ("Last Update: (N.A.)" right after upgrade).

| When | Total requests/month | Database storage | File storage |
|---|---|---|---|
| 2026-10-29 ~16:30 UTC-3, after suite runs, BEFORE scale seeding | 0 (not yet refreshed) | 0.00 MB (not yet refreshed) | 0.00 MB (not yet refreshed) |
| 2026-10-30, after the 1,000-tenant seed (1 project, 100 tasks each) and all measurements | 102.98 K | 34.59 MB | 0.00 MB |

Per-tenant average at this fixed size: 34.59 MB / 1,000 seeded tenants ≈ 35 KB per tenant (includes users, roles, memberships, projects, tasks; derived from measured usage, not per-row accounting).
