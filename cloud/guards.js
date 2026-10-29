// File: cloud/guards.js · CommonJS · no Parse dependency (so the test suite can load it directly).
//
// A shared membership helper reduces mistakes but cannot guarantee a developer calls it (brief review, point
// 3). This registry is the mechanical backstop: every Cloud function registered in main.js must be listed in
// the GUARDS table there, stating which guard wraps it, and the server REFUSES TO START (throws while loading
// cloud/main.js) if a function is registered without an entry, with an entry naming an unknown guard, twice,
// or if an entry in the table never gets registered. A forgotten guard therefore fails the deploy, not the
// tenant. (The one unguarded function, demoTaskById, must name the guard 'demo-unguarded' and only registers
// when config.DEMO_UNGUARDED is true — see cloud/config.js.)
'use strict';

// Guard names the registry accepts. What each one means is enforced in cloud/main.js, where `define` wraps
// the handler with the corresponding check before Parse ever sees it:
//   'authenticated'  requireUser: any signed-in user.
//   'member'         requireUser + requireMembership(user, tenant of the target): active member of the tenant.
//   'admin'          requireUser + requireMembership(…, 'admin'): active member with role admin.
//   'setup'          requireSetupEnabled (cloud/config.js SETUP_ENABLED), unauthenticated by design.
//   'demo-unguarded' NO guard. Only demoTaskById; only registered when config.DEMO_UNGUARDED is true.
const GUARD_NAMES = ['authenticated', 'member', 'admin', 'setup', 'demo-unguarded'];

/**
 * createRegistry(guards, { demoEnabled }) → { define, assertAllRegistered }
 *   guards: { functionName: guardName } — the GUARDS table from main.js.
 *   define(name, register): refuses unlisted names, unknown guards and double registration, skips
 *     'demo-unguarded' entries while demoEnabled is false, and otherwise calls register(guardName).
 *   assertAllRegistered(): throws if any table entry was never registered (e.g. a typo in a define call).
 */
function createRegistry(guards, options) {
  const demoEnabled = !!(options && options.demoEnabled);
  const registered = {};
  Object.keys(guards).forEach(function (name) {
    if (GUARD_NAMES.indexOf(guards[name]) === -1) {
      throw new Error('GUARDS["' + name + '"] names unknown guard "' + guards[name] + '" (known: ' + GUARD_NAMES.join(', ') + ')');
    }
  });
  return {
    define: function (name, register) {
      const guard = guards[name];
      if (!guard) {
        throw new Error('Cloud function "' + name + '" is not listed in the GUARDS table (cloud/main.js). ' +
          'Every function must declare its guard; the server does not start without it.');
      }
      if (registered[name]) throw new Error('Cloud function "' + name + '" registered twice.');
      if (guard === 'demo-unguarded' && !demoEnabled) {
        registered[name] = 'skipped';
        return; // not registered at all: calling it answers Parse 141 "Invalid function"
      }
      registered[name] = guard;
      register(guard);
    },
    assertAllRegistered: function () {
      const missing = Object.keys(guards).filter(function (name) { return !registered[name]; });
      if (missing.length) {
        throw new Error('GUARDS lists function(s) that were never registered: ' + missing.join(', ') +
          ' — remove the stale entries or add the define() calls.');
      }
    },
  };
}

module.exports = { createRegistry: createRegistry, GUARD_NAMES: GUARD_NAMES };
