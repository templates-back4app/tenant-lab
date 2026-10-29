// File: scripts/lib/seed-identity.mjs · Node 22 ESM
// Deterministic identities shared by scripts/seed-tenants.mjs (which creates them) and
// scripts/measure-scale.mjs (which signs in as them). Synthetic benchmark users only — the deterministic
// password derivation is NOT a pattern for real accounts.
import crypto from 'node:crypto';

export const seedUsername = (seed, kind, i) => `seed-${seed}-${kind}${i === undefined ? '' : '-' + i}`;
export const seedPassword = (seed, user) => 'Pw-' + crypto.createHash('sha256').update(`${seed}:${user}:tenant-lab`).digest('base64url').slice(0, 18);
export const seedEmail = (user) => `${user}@seed.example.test`;
