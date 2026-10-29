// File: scripts/lib/rest.mjs · Node 22 ESM
// Minimal Parse REST client (fetch) shared by scripts and tests — same pattern as game-backend-starter.
// Handles Back4app's throttle: HTTP 400 with Parse code 155 ("request limit exceeded") is retried with
// backoff when `retry` is enabled. Never prints keys or tokens.
export const THROTTLE_CODE = 155;

export function makeClient(env, options = {}) {
  const base = env.SERVER_URL.replace(/\/+$/, '');
  const defaultRetry = options.retry ?? false;
  const maxAttempts = options.maxAttempts ?? 8;

  function headers({ session, master, useJsKey } = {}) {
    const h = { 'Content-Type': 'application/json', 'X-Parse-Application-Id': env.APP_ID };
    if (master) {
      if (!env.MASTER_KEY) throw new Error('MASTER_KEY is required for this call');
      h['X-Parse-Master-Key'] = env.MASTER_KEY;
    } else if (useJsKey && env.JS_KEY) {
      h['X-Parse-Javascript-Key'] = env.JS_KEY;
    } else if (env.REST_KEY) {
      h['X-Parse-REST-API-Key'] = env.REST_KEY;
    } else if (env.JS_KEY) {
      h['X-Parse-Javascript-Key'] = env.JS_KEY;
    }
    if (session) h['X-Parse-Session-Token'] = session;
    return h;
  }

  /**
   * request('POST', '/functions/x', { body, session, master, retry }) → { status, json, ms }
   * Never throws on HTTP errors; throws only on network failure after retries.
   */
  async function request(method, path, opts = {}) {
    const retry = opts.retry ?? defaultRetry;
    let attempt = 0;
    for (;;) {
      attempt++;
      const t0 = performance.now();
      let res;
      try {
        res = await fetch(base + path, {
          method,
          headers: headers(opts),
          body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        });
      } catch (err) {
        if (!retry || attempt >= maxAttempts) throw err;
        await sleep(backoff(attempt));
        continue;
      }
      const text = await res.text();
      let json = null;
      try { json = text ? JSON.parse(text) : null; } catch { json = { raw: text }; }
      const ms = performance.now() - t0;
      const throttled = res.status === 400 && json && json.code === THROTTLE_CODE;
      const transient = res.status === 429 || res.status >= 500;
      if (retry && (throttled || transient) && attempt < maxAttempts) {
        await sleep(backoff(attempt));
        continue;
      }
      return { status: res.status, json, ms, attempts: attempt };
    }
  }

  /** Cloud function call. Returns { ok, status, result, error: {parseCode, code, message, …envelope}, ms } */
  async function call(name, params = {}, opts = {}) {
    const r = await request('POST', `/functions/${name}`, { ...opts, body: params });
    if (r.status === 200 && r.json && 'result' in r.json) return { ok: true, status: r.status, result: r.json.result, ms: r.ms };
    return { ok: false, status: r.status, error: parseCloudError(r.json), ms: r.ms };
  }

  return { request, call, headers, base };
}

/** Unwrap the {"code":"…","message":"…"} envelope that cloud/main.js puts in Parse.Error messages. */
export function parseCloudError(json) {
  if (!json) return { parseCode: null, code: 'NO_RESPONSE', message: 'empty response' };
  const parseCode = json.code ?? null;
  const raw = json.error ?? json.message ?? '';
  if (typeof raw === 'string' && raw.startsWith('{')) {
    try {
      const env = JSON.parse(raw);
      return { parseCode, ...env };
    } catch { /* not an envelope */ }
  }
  return { parseCode, code: 'PARSE_' + parseCode, message: String(raw) };
}

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function backoff(attempt) {
  return Math.min(30000, 500 * 2 ** (attempt - 1)) + Math.floor(Math.random() * 250);
}

/** Token bucket: `await bucket.take()` before each request to stay under `ratePerSecond`. */
export function tokenBucket(ratePerSecond) {
  const interval = 1000 / ratePerSecond;
  let next = performance.now();
  return {
    async take() {
      const now = performance.now();
      if (next < now) next = now;
      const wait = next - now;
      next += interval;
      if (wait > 0) await sleep(wait);
    },
  };
}

/** Deterministic PRNG (mulberry32) so seeds are reproducible. */
export function rng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (min, maxInclusive) => min + Math.floor(next() * (maxInclusive - min + 1));
  const hex = (n) => Array.from({ length: n }, () => int(0, 15).toString(16)).join('');
  return { next, int, hex };
}

export const where = (obj) => encodeURIComponent(JSON.stringify(obj));
