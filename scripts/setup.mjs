// File: scripts/setup.mjs · Node 22 ESM
// Creates or updates the classes, class-level permissions and indexes (and the master-only CLP on _Role).
// Idempotent: run it again after editing the schema in cloud/config.js. Two paths, same definition:
//   - MASTER_KEY available (the LOCAL dev server, whose fixed keys include one): schema REST API directly.
//   - no MASTER_KEY (Back4app, where the key stays in the dashboard): calls the Cloud function setupSchema
//     with the REST key; Cloud Code must be deployed first and config.SETUP_ENABLED must still be true.
// Usage: npm run setup [-- --local] [-- --dry-run] [-- --allow-rerun]
import { createRequire } from 'node:module';
import { target, args } from './lib/env.mjs';
import { makeClient } from './lib/rest.mjs';

const config = createRequire(import.meta.url)('../cloud/config.js');
// The CLI part only runs when invoked directly (the tests import applySchema without side effects).
let a; let env; let api; let failures = 0;
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  a = args();
  env = target(a);
  api = makeClient(env, { retry: true });
  if (env.MASTER_KEY) await setupWithMasterKey();
  else await setupWithCloudCode();

  // Smoke-test that Cloud Code is live: an anonymous call to myTenants must be rejected by the function itself
  // (209 UNAUTHENTICATED), not with "Invalid function" (141). Prove deploys with a request, never with a dialog.
  const probe = await api.call('myTenants', {});
  if (!probe.ok && probe.error.code === 'UNAUTHENTICATED') console.log('cloud code: live (myTenants rejects anonymous calls)');
  else if (!probe.ok && /Invalid function/.test(probe.error.message || '')) { failures++; console.error('cloud code: NOT deployed (Invalid function "myTenants") — upload cloud/main.js, cloud/config.js and cloud/guards.js'); }
  else console.log(`cloud code: unexpected probe result ${JSON.stringify(probe)}`);

  process.exit(failures ? 1 : 0);
}

export async function applySchema(targetEnv) {
  const client = makeClient(targetEnv, { retry: true });
  for (const def of config.SCHEMA) {
    const existing = await client.request('GET', `/schemas/${def.className}`, { master: true });
    if (existing.status === 200) {
      const have = existing.json;
      const newFields = {};
      for (const [name, spec] of Object.entries(def.fields)) if (!have.fields || !have.fields[name]) newFields[name] = spec;
      const haveIdx = have.indexes || {};
      const newIndexes = {};
      for (const [name, key] of Object.entries(def.indexes || {})) if (!haveIdx[name]) newIndexes[name] = key;
      const body = { className: def.className, fields: newFields, classLevelPermissions: def.classLevelPermissions };
      if (Object.keys(newIndexes).length) body.indexes = newIndexes;
      const r = await client.request('PUT', `/schemas/${def.className}`, { master: true, body });
      if (r.status !== 200) throw new Error(`schema ${def.className}: update failed ${r.status} ${JSON.stringify(r.json)}`);
    } else if (existing.status === 400 && existing.json && existing.json.code === 103) {
      const body = { className: def.className, fields: def.fields, classLevelPermissions: def.classLevelPermissions, indexes: def.indexes };
      const r = await client.request('POST', `/schemas/${def.className}`, { master: true, body });
      if (r.status !== 200 && r.status !== 201) throw new Error(`schema ${def.className}: create failed ${r.status} ${JSON.stringify(r.json)}`);
    } else {
      throw new Error(`schema ${def.className}: GET failed ${existing.status} ${JSON.stringify(existing.json)}`);
    }
  }
  // _Role: master-only CLP (role membership is managed by Cloud Code alone).
  const role = await client.request('PUT', '/schemas/_Role', { master: true, body: { className: '_Role', classLevelPermissions: config.ROLE_CLP } });
  if (role.status !== 200) throw new Error(`schema _Role: CLP update failed ${role.status} ${JSON.stringify(role.json)}`);
}

async function setupWithMasterKey() {
  for (const def of config.SCHEMA) {
    const existing = await api.request('GET', `/schemas/${def.className}`, { master: true });
    const verb = existing.status === 200 ? 'updated' : 'created';
    if (a['dry-run']) { console.log(`schema ${def.className}: would be ${verb}`); continue; }
    void verb;
  }
  if (a['dry-run']) return;
  await applySchema(env);
  for (const def of config.SCHEMA) {
    const r = await api.request('GET', `/schemas/${def.className}`, { master: true });
    console.log(`schema ${def.className}: ok (${Object.keys((r.json && r.json.fields) || {}).length} fields, indexes: ${Object.keys((r.json && r.json.indexes) || {}).join(', ') || 'none'})`);
  }
  console.log('schema _Role: CLP set to master-only');
}

async function setupWithCloudCode() {
  console.log(`no MASTER_KEY — applying the schema through the Cloud function setupSchema at ${env.SERVER_URL}`);
  if (a['dry-run']) { console.log('dry-run has no effect on the Cloud Code path (setupSchema is idempotent)'); return; }
  const r = await api.call('setupSchema', { allowRerun: !!a['allow-rerun'] });
  if (!r.ok) {
    failures++;
    console.error(`setupSchema failed: HTTP ${r.status} ${JSON.stringify(r.error)}`);
    if (r.error.code === 'SETUP_DISABLED') console.error('cloud/config.js has SETUP_ENABLED=false on that backend.');
    return;
  }
  for (const c of r.result.classes) {
    console.log(`schema ${c.className}: ${c.action} (${c.newFields.length} new field(s), ${c.newIndexes.length} new index(es))`);
  }
}
