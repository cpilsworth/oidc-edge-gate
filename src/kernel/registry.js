// Plugin registry (W1.1). Built once per execution from the static plugin list
// (plugins/index.js). It answers "which plugins exist" and "which cookies and
// header prefixes are reserved", and resolves the per-options parts of a
// manifest (routes, egress) that can depend on the policy.
//
// Everything here fails at load time (PluginDefinitionError), never at
// request time. Contracts: docs/architecture/plugins.md §3, §8, §12 (5);
// shapes: src/kernel/types.js (Registry).

import {
  CORE_HEADER_PREFIX, PLUGIN_KINDS, PluginDefinitionError, validateEgress, validateRoutes,
} from "../sdk/index.js";

/**
 * @param {unknown} m
 * @returns {boolean} true for a value shaped like a definePlugin() result
 */
function isDefinedPlugin(m) {
  return m !== null
    && typeof m === "object"
    && Object.isFrozen(m)
    && typeof m.name === "string"
    && PLUGIN_KINDS.includes(m.kind)
    // definePlugin() always normalizes these to frozen arrays; a hand-rolled
    // frozen object almost never has all of them.
    && Array.isArray(m.phases) && Object.isFrozen(m.phases)
    && Array.isArray(m.trustedHeaderPrefixes) && Object.isFrozen(m.trustedHeaderPrefixes)
    && Array.isArray(m.cookies) && Object.isFrozen(m.cookies)
    && Array.isArray(m.secrets) && Object.isFrozen(m.secrets)
    && Number.isInteger(m.maxFetches);
}

/**
 * Build the registry. Throws PluginDefinitionError when an entry is not a
 * definePlugin() result, when two plugins share a name, when two plugins
 * declare the same cookie, or when two plugins declare the same (or an
 * overlapping) trusted header prefix.
 *
 * @param {ReadonlyArray<import("./types.js").PluginManifest>} manifests
 * @returns {import("./types.js").Registry}
 */
export function createRegistry(manifests) {
  if (!Array.isArray(manifests)) throw new PluginDefinitionError("?", "registry expects an array of plugins");

  const byName = new Map();
  const cookieOwner = new Map(); // cookie name -> plugin name
  const prefixOwner = new Map(); // header prefix -> plugin name

  for (const m of manifests) {
    if (!isDefinedPlugin(m)) {
      const name = m && typeof m.name === "string" ? m.name : "?";
      throw new PluginDefinitionError(name, "is not a definePlugin() result");
    }
    if (byName.has(m.name)) throw new PluginDefinitionError(m.name, "is registered twice (duplicate plugin name)");

    for (const c of m.cookies) {
      const owner = cookieOwner.get(c);
      if (owner !== undefined && owner !== m.name) {
        throw new PluginDefinitionError(m.name, `cookie ${JSON.stringify(c)} is already declared by plugin ${JSON.stringify(owner)}`);
      }
      cookieOwner.set(c, m.name);
    }

    for (const p of m.trustedHeaderPrefixes) {
      const lower = p.toLowerCase();
      // definePlugin already rejects x-auth-; re-checked here so the registry
      // never trusts a manifest it did not validate itself.
      if (lower.startsWith(CORE_HEADER_PREFIX)) throw new PluginDefinitionError(m.name, `"${CORE_HEADER_PREFIX}" headers are kernel-owned`);
      for (const [other, owner] of prefixOwner) {
        // Overlap in either direction (x-foo- vs x-foo-bar-) would let one plugin
        // write headers the other one owns, so it is treated as a collision too.
        if (owner !== m.name && (other.startsWith(lower) || lower.startsWith(other))) {
          throw new PluginDefinitionError(m.name, `header prefix ${JSON.stringify(p)} collides with ${JSON.stringify(other)} declared by plugin ${JSON.stringify(owner)}`);
        }
      }
      prefixOwner.set(lower, m.name);
    }

    byName.set(m.name, m);
  }

  const ordered = Object.freeze([...byName.values()]);
  const reserved = Object.freeze([CORE_HEADER_PREFIX, ...prefixOwner.keys()]);
  const owned = Object.freeze([...cookieOwner.keys()]);

  return Object.freeze({
    get: (name) => byName.get(name),
    has: (name) => byName.has(name),
    list: () => [...ordered],
    reservedHeaderPrefixes: () => [...reserved],
    ownedCookies: () => [...owned],
    /** Extension (not in types.js): which plugin declared a cookie, or undefined. */
    cookieOwner: (cookie) => cookieOwner.get(cookie),
  });
}

/**
 * Iterate a CompiledPolicy.enabled value (a Map, or a plain object in tests).
 * @param {ReadonlyMap<string, object>|Object<string, object>|undefined|null} enabled
 * @returns {Array<[string, object]>}
 */
export function enabledEntries(enabled) {
  if (!enabled) return [];
  if (enabled instanceof Map) return [...enabled.entries()];
  if (typeof enabled === "object") return Object.entries(enabled);
  throw new TypeError("policy.enabled must be a Map");
}

/**
 * Resolve the routes of every ENABLED plugin. A `routes(options)` function is
 * called with the plugin's base options and its result re-validated. Two
 * plugins claiming the same path fail loading (kernel invariant 5).
 *
 * @param {import("./types.js").Registry} registry
 * @param {ReadonlyMap<string, Readonly<Object>>} enabled  plugin name -> validated base options
 * @returns {Map<string, {plugin: import("./types.js").PluginManifest, handler: Function, options: Readonly<Object>}>}
 */
export function resolveRoutes(registry, enabled) {
  const enabledMap = new Map(enabledEntries(enabled));
  for (const name of enabledMap.keys()) {
    if (!registry.has(name)) throw new PluginDefinitionError(name, "is enabled by the policy but not registered");
  }

  const out = new Map();
  // Registry order, so resolution (and any error message) is deterministic.
  for (const plugin of registry.list()) {
    if (!enabledMap.has(plugin.name) || plugin.routes === undefined) continue;
    const options = enabledMap.get(plugin.name) ?? {};
    const fail = (msg) => { throw new PluginDefinitionError(plugin.name, msg); };

    const routes = typeof plugin.routes === "function" ? plugin.routes(options) : plugin.routes;
    if (routes === null || typeof routes !== "object" || Array.isArray(routes)) fail("routes(options) must return an object { \"/.auth/x\": handler }");
    validateRoutes(routes, fail);

    for (const [path, handler] of Object.entries(routes)) {
      const prior = out.get(path);
      if (prior) fail(`route ${JSON.stringify(path)} is already claimed by plugin ${JSON.stringify(prior.plugin.name)}`);
      out.set(path, { plugin, handler, options });
    }
  }
  return out;
}

/**
 * Resolve a plugin's egress allow-list for the given options into a Set of
 * URL origins (e.g. "https://api.example.com").
 *
 * @param {import("./types.js").PluginManifest} manifest
 * @param {Readonly<Object>} options
 * @returns {Set<string>}
 */
export function resolveEgress(manifest, options) {
  const fail = (msg) => { throw new PluginDefinitionError(manifest.name, msg); };
  const raw = manifest.egress === undefined ? [] : manifest.egress;
  const list = typeof raw === "function" ? raw(options ?? {}) : raw;
  if (!Array.isArray(list)) fail("egress(options) must return an array of https origins");
  validateEgress(list, fail);
  return new Set(list.map((e) => new URL(e).origin));
}
