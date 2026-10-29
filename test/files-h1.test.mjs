// File: test/files-h1.test.mjs · T7 / hypothesis H1: are file attachments protected by the row's permissions?
// Local measurement only (parse-server 7.5.4, @parse/fs-files-adapter). The Back4app result is TO MEASURE in
// the live phase — nothing here claims it. Rows marked evidence:'h1' end up in docs/evidence/files-h1-local-<date>.md.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { harness, mustCall } from './helpers.mjs';

let h; let w; let att;
const SECRET = 'ACME quarterly numbers: 42';
before(async () => {
  h = await harness({ suite: 'files-h1' });
  w = await h.world();
  att = await mustCall(h, 'attachFile', {
    taskId: w.acmeTask, name: 'acme-numbers.txt', base64: Buffer.from(SECRET).toString('base64'),
  }, w.acmeMember.token);
});
after(async () => { await h.cleanup(); });

test('H1a upload path: only members attach, and only to their tenant\'s tasks', async () => {
  assert.ok(att.url.includes('/files/'), `attachFile returned a file URL`);
  const foreign = await h.call('attachFile', { taskId: w.acmeTask2, name: 'x.txt', base64: 'eA==' }, w.borealisMember.token);
  assert.equal(foreign.error.code, 'OBJECT_NOT_FOUND', 'a Borealis member cannot attach to an ACME task');
  const anon = await h.call('attachFile', { taskId: w.acmeTask, name: 'x.txt', base64: 'eA==' });
  assert.equal(anon.error.parseCode, 209);
  // Direct client upload is closed too (fileUpload.enableForPublic/ForAuthenticatedUser = false locally):
  const direct = await h.rest('POST', '/files/direct.txt', undefined, { session: w.acmeMember.token, headers: { 'Content-Type': 'text/plain' } });
  h.observe('H1a direct POST /files by a signed-in client', `HTTP ${direct.status} code ${direct.json && direct.json.code}`);
  const meta = await h.master('FileMeta', { fileName: att.name });
  assert.equal(meta.length, 1);
  assert.equal(meta[0].tenant.objectId, w.acme);
  h.record({
    evidence: 'h1', id: 'H1a', test: 'upload path', persona: 'ACME member / Borealis member / anonymous',
    attempt: 'attachFile to an own task, to a foreign task, without a session; direct POST /files',
    status: `200 / 404 / 400 / ${direct.status}`, code: `ok / OBJECT_NOT_FOUND / 209 / ${direct.json && direct.json.code}`,
    body: 'only the member upload succeeds',
    state: 'FileMeta maps the stored file name to the ACME tenant',
  });
});

test('T7/H1b the raw file URL, without any session — the measurement', async () => {
  const res = await fetch(att.url); // no App ID, no key, no session: what anyone holding the URL has
  const body = res.ok ? await res.text() : '';
  const leaks = res.status === 200 && body === SECRET;
  h.observe('H1 raw URL without a session (LOCAL, fs-files-adapter)',
    `HTTP ${res.status}${leaks ? ' — full file contents served. H1 SUPPORTED locally' : ''}`);
  // The brief predicts the leak (H1); the matrix row records the measurement either way. The assertion pins
  // the MEASURED local behaviour so a parse-server upgrade that changes it fails loudly here.
  assert.equal(res.status, 200, 'local parse-server serves the file to anyone holding the URL');
  assert.equal(body, SECRET);
  const guessed = await fetch(att.url.replace(/[^/]+$/, 'acme-numbers.txt'));
  h.observe('H1 guessing the URL without its random prefix', `HTTP ${guessed.status} (file names carry a random prefix; guessing is not the threat model, possession of the URL is)`);
  h.record({
    evidence: 'h1', id: 'T7', test: 'open the raw attachment URL', persona: 'anonymous (URL holder)',
    attempt: 'GET the Parse File URL with no App ID, key or session',
    status: res.status, code: null,
    body: leaks ? 'the full file contents are served — H1 SUPPORTED on the local server' : `unexpected: HTTP ${res.status}`,
    state: 'the Task row itself stays invisible to anonymous reads (T14); only the file URL leaks. Back4app: TO MEASURE (live)',
  });
});

test('H1c the mitigation candidate (membership-checked getAttachment) works — and does NOT fix the raw URL', async () => {
  const member = await h.call('getAttachment', { taskId: w.acmeTask }, w.acmeMember.token);
  assert.equal(member.ok, true);
  assert.equal(Buffer.from(member.result.base64, 'base64').toString(), SECRET, 'a member receives the bytes');
  const admin = await h.call('getAttachment', { taskId: w.acmeTask }, w.acmeAdmin.token);
  assert.equal(admin.ok, true, 'the admin inherits the member read');
  const foreign = await h.call('getAttachment', { taskId: w.acmeTask }, w.borealisMember.token);
  assert.equal(foreign.error.code, 'OBJECT_NOT_FOUND');
  const anon = await h.call('getAttachment', { taskId: w.acmeTask });
  assert.equal(anon.error.parseCode, 209);
  const removed = await h.call('getAttachment', { taskId: w.acmeTask }, w.removed.token);
  assert.equal(removed.error.code, 'OBJECT_NOT_FOUND', 'a removed member lost the attachment too');

  // Re-measure the ORIGINAL URL after the mitigation exists (review point 6): the proxy does not secure it.
  const raw = await fetch(att.url);
  assert.equal(raw.status, 200, 'the raw URL still serves — the function is an ACCESS PATH, not protection for the URL');
  h.observe('H1 raw URL re-measured with the mitigation in place', `HTTP ${raw.status} — unchanged. On this storage, attachments are EXCLUDED from the isolation claim unless the URL itself is protected`);
  h.record({
    evidence: 'h1', id: 'H1c', test: 'mitigation candidate: getAttachment', persona: 'member/admin/foreign/anonymous/removed',
    attempt: 'getAttachment for each persona; then GET the raw URL again',
    status: '200/404/400 + raw 200', code: 'ok / ok / OBJECT_NOT_FOUND / 209 / OBJECT_NOT_FOUND; raw URL still 200',
    body: 'the function path enforces membership; the underlying URL is unchanged by it',
    state: 'LOCAL conclusion: membership-checked delivery works, but the raw URL stays public → attachments excluded from the local isolation claim. Back4app raw-URL behaviour and any signed-URL option: TO MEASURE (live)',
  });
});
