// File: scripts/dev-server.mjs · local parse-server ^7 with the Postgres adapter, the same Cloud Code as a
// Back4app deploy, LiveQuery enabled for Task, and a filesystem files adapter (files land in .files/, gitignored).
//   npm run dev:server            → http://localhost:1341/parse (database postgres://localhost:5433/tenant_dev)
// Imported by the tests, which start their own instance on a free port and the database tenant_test.
// Needs a Postgres listening on 5433 (brew: postgresql@17). The database is created with `createdb` if missing.
import express from 'express';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { ParseServer } from 'parse-server';
import { LOCAL, ROOT, loadDotEnv } from './lib/env.mjs';

const PG_BIN = [process.env.PG_BIN, '/opt/homebrew/opt/postgresql@17/bin', '/opt/homebrew/bin', '/usr/local/bin'].filter(Boolean);

export function ensureDatabase(databaseURI) {
  const u = new URL(databaseURI);
  const dbName = u.pathname.replace(/^\//, '');
  const dir = PG_BIN.find((d) => existsSync(path.join(d, 'createdb')));
  if (!dir) { console.warn(`createdb not found in ${PG_BIN.join(', ')} (set PG_BIN) — assuming ${dbName} exists`); return; }
  const common = ['-h', u.hostname, '-p', u.port || '5432', ...(u.username ? ['-U', u.username] : [])];
  const list = execFileSync(path.join(dir, 'psql'), [...common, '-lqt'], { encoding: 'utf8' });
  if (list.split('\n').some((l) => l.split('|')[0].trim() === dbName)) return;
  execFileSync(path.join(dir, 'createdb'), [...common, dbName], { stdio: 'inherit' });
  console.log(`created database ${dbName}`);
}

/** Starts parse-server + express + LiveQuery. Returns { server, http, url, close() }. */
export async function startServer({ port = LOCAL.PORT, databaseURI = LOCAL.DATABASE_URL, quiet = false } = {}) {
  ensureDatabase(databaseURI);
  const dbName = new URL(databaseURI).pathname.replace(/^\//, '');
  const serverURL = `http://localhost:${port}/parse`;

  const parseOptions = {
    appId: LOCAL.APP_ID,
    javascriptKey: LOCAL.JS_KEY,
    restAPIKey: LOCAL.REST_KEY,
    masterKey: LOCAL.MASTER_KEY,
    serverURL,
    databaseURI,
    cloud: path.join(ROOT, 'cloud', 'main.js'),
    appName: 'tenant-lab (local)',
    // Mirrors the Back4app settings that matter for the matrix; any difference found on the live run is a
    // finding for docs/evidence/local-vs-live.md.
    allowClientClassCreation: false,
    enableAnonymousUsers: false,       // personas sign up with username/password; "anonymous" = no session at all
    enforcePrivateUsers: true,
    allowExpiredAuthDataToken: false,
    masterKeyIps: ['127.0.0.1', '::1', '::ffff:127.0.0.1'],
    // Attachments: plain filesystem adapter (closest local analogue to a public files host). H1 measures
    // whether these URLs answer without a session.
    filesAdapter: {
      module: '@parse/fs-files-adapter',
      options: { filesSubDirectory: path.join(ROOT, '.files', dbName) },
    },
    fileUpload: { enableForAuthenticatedUser: false, enableForPublic: false }, // direct client uploads closed; attachFile is the path
    liveQuery: { classNames: ['Task'] }, // T8/T9
    logLevel: quiet ? 'error' : (process.env.PARSE_LOG_LEVEL || 'info'),
    silent: quiet,
    verbose: process.env.PARSE_VERBOSE === '1',
  };
  const server = new ParseServer(parseOptions);

  const app = express();
  app.disable('x-powered-by');
  if (!quiet) {
    app.use((req, _res, next) => { // one line per request, so the diary can show what a client really sent
      console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
      next();
    });
  }
  app.use('/parse', server.app);
  // Listen first: start() probes serverURL over HTTP and warns "Unable to connect" if nothing answers yet.
  const http = await new Promise((resolve) => { const h = app.listen(port, () => resolve(h)); });
  await server.start();
  const liveQueryServer = await ParseServer.createLiveQueryServer(
    http,
    { appId: LOCAL.APP_ID, masterKey: LOCAL.MASTER_KEY, serverURL },
    parseOptions,
  );
  const startedAt = Date.now();
  if (!quiet) console.log(`parse-server ${version()} on ${serverURL} · db ${databaseURI} · cloud/main.js mounted · LiveQuery ws://localhost:${port}/parse (Task)`);
  return {
    server, http, url: serverURL,
    close: async () => {
      // parse-server probes serverURL/health ~1 s after mount; a suite faster than that would log a spurious warning.
      await new Promise((r) => setTimeout(r, Math.max(0, 1500 - (Date.now() - startedAt))));
      if (liveQueryServer && liveQueryServer.server && liveQueryServer.server !== http) {
        await new Promise((r) => liveQueryServer.server.close(r));
      }
      await new Promise((r) => http.close(r));
      await server.handleShutdown();
    },
  };
}

function version() {
  try { return createRequire(import.meta.url)('parse-server/package.json').version; } catch { return ''; }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(ROOT, 'scripts', 'dev-server.mjs')) {
  loadDotEnv();
  startServer({ databaseURI: process.env.DATABASE_URL || LOCAL.DATABASE_URL }).catch((e) => { console.error(e); process.exit(1); });
}
