// Option validation for the user-info plugin (docs/architecture/plugins.md §14.3).
// validate() runs once per distinct merged options object at policy load; any
// problem is a PluginConfigError, which fails the config load (fail closed).
// The returned object has every default filled in, so the hooks never need
// their own fallbacks.

import { PluginConfigError, validateEgress } from "../../../src/sdk/index.js";

export const OPTION_DEFAULTS = Object.freeze({
  groups_path: "groups",
  on_login_error: "fail",
  degrade_ttl_seconds: 300,
  profile_fields: Object.freeze([]),
  expose: "none",
  cache_ttl_seconds: 300,
});

const OPTION_KEYS = new Set([
  "endpoint", "groups_path", "on_login_error", "degrade_ttl_seconds",
  "profile_endpoint", "profile_fields", "expose", "cache_ttl_seconds",
]);

/**
 * The only template variable: the verified `sub`. `{email}` is deliberately
 * NOT supported (W2.R R1): an IdP may assert an email it has not verified, and
 * selecting the backend record (groups, profile) by it would let a user who
 * registers someone else's address inherit that person's record.
 */
export const TEMPLATE_VARIABLES = Object.freeze(["sub"]);

const ON_LOGIN_ERROR = new Set(["fail", "degrade"]);
const EXPOSE = new Set(["none", "headers"]);
// Dot path of plain JSON keys, e.g. "groups" or "data.memberships".
const GROUPS_PATH_RE = /^[A-Za-z0-9_$-]+(?:\.[A-Za-z0-9_$-]+)*$/;
// Profile fields become `x-user-<field>` headers (lowercased, "_" -> "-").
export const PROFILE_FIELD_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const MAX_TEMPLATE_LENGTH = 2048;
const MAX_PROFILE_FIELDS = 64;

/**
 * Split a URL template into its (placeholder-free) origin part and the rest,
 * and check its variables. Throws PluginConfigError.
 * @param {unknown} template
 * @param {string} name  option name for messages
 * @returns {{origin: string, variables: string[]}}
 */
export function parseTemplate(template, name) {
  if (typeof template !== "string" || template.length === 0) throw new PluginConfigError(`${name} must be a non-empty URL template string`);
  if (template.length > MAX_TEMPLATE_LENGTH) throw new PluginConfigError(`${name} is longer than ${MAX_TEMPLATE_LENGTH} characters`);
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0020\u007f]/.test(template)) throw new PluginConfigError(`${name} must not contain whitespace or control characters`);

  const variables = [];
  const stripped = template.replace(/\{([^{}]*)\}/g, (_, v) => {
    if (v === "email") {
      throw new PluginConfigError(`${name}: the {email} template variable is not supported; user-info lookups are by the verified {sub} only`);
    }
    if (!TEMPLATE_VARIABLES.includes(v)) {
      throw new PluginConfigError(`${name}: unknown template variable {${v}} (only {sub}; lookups are by the verified sub)`);
    }
    variables.push(v);
    return "x";
  });
  if (/[{}]/.test(stripped)) throw new PluginConfigError(`${name}: unbalanced "{" or "}" in the URL template`);

  // Variables are allowed only after the authority, so a substituted value can
  // never change the host the credentials are sent to.
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([/?][^#]*)?$/.exec(template);
  if (!m) throw new PluginConfigError(`${name} must be an absolute https:// URL with a path (no fragment)`);
  if (/[{}]/.test(m[2])) throw new PluginConfigError(`${name}: template variables are not allowed in the host`);
  if (m[2].includes("@")) throw new PluginConfigError(`${name} must not embed credentials`);

  let url;
  try { url = new URL(stripped); } catch { throw new PluginConfigError(`${name} is not a valid URL`); }
  if (!isCanonicalPath(stripped, url)) {
    throw new PluginConfigError(`${name}: the path must be in canonical form (no "." / ".." segments or characters the URL parser re-encodes)`);
  }
  const origin = url.origin;
  validateEgress([origin], (msg) => { throw new PluginConfigError(`${name}: ${msg}`); });
  return { origin, variables: [...new Set(variables)] };
}

/**
 * True when the URL parser kept the path exactly as written: no dot segments
 * were resolved and nothing was re-encoded. Used at validate time for the
 * template and at request time for the expanded URL, where it catches a
 * substituted value of "." or ".." (encodeURIComponent leaves dots alone).
 * @param {string} raw  the absolute URL as written
 * @param {URL} url     new URL(raw)
 */
export function isCanonicalPath(raw, url) {
  const m = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*([^?#]*)/.exec(raw);
  const path = m ? m[1] : "";
  return url.pathname === (path === "" ? "/" : path);
}

/** Origin of a template, or null if it does not parse (egress() must not throw on bad input). */
export function templateOrigin(template) {
  try { return parseTemplate(template, "template").origin; } catch { return null; }
}

const positiveInt = (options, key) => {
  const v = options[key];
  if (v === undefined) return OPTION_DEFAULTS[key];
  if (!Number.isSafeInteger(v) || v <= 0) throw new PluginConfigError(`${key} must be a positive integer (seconds)`);
  return v;
};

const oneOf = (options, key, allowed) => {
  const v = options[key];
  if (v === undefined) return OPTION_DEFAULTS[key];
  if (!allowed.has(v)) throw new PluginConfigError(`${key} must be one of ${[...allowed].map((a) => JSON.stringify(a)).join(", ")}`);
  return v;
};

/** Header name for a profile field: x-user-<field>, lowercased, "_" -> "-". */
export function headerNameFor(field) {
  return `x-user-${field.toLowerCase().replace(/_/g, "-")}`;
}

/**
 * The plugin's validate(options): returns the normalized options with every
 * default filled in, or throws PluginConfigError.
 * @param {Object} options
 * @returns {Readonly<Object>}
 */
export function validateOptions(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) throw new PluginConfigError("options must be an object");
  for (const k of Object.keys(options)) {
    if (!OPTION_KEYS.has(k)) throw new PluginConfigError(`unknown option ${JSON.stringify(k)}`);
  }
  if (options.endpoint === undefined) throw new PluginConfigError("endpoint is required (set it in plugins[\"user-info\"])");
  parseTemplate(options.endpoint, "endpoint");
  const profileEndpoint = options.profile_endpoint === undefined ? options.endpoint : options.profile_endpoint;
  if (options.profile_endpoint !== undefined) parseTemplate(profileEndpoint, "profile_endpoint");

  let groupsPath = OPTION_DEFAULTS.groups_path;
  if (options.groups_path !== undefined) {
    const g = options.groups_path;
    if (typeof g !== "string" || !GROUPS_PATH_RE.test(g) || g.split(".").some((s) => FORBIDDEN_KEYS.has(s))) {
      throw new PluginConfigError("groups_path must be a dot path of JSON keys, e.g. \"groups\" or \"data.groups\"");
    }
    groupsPath = g;
  }

  let fields = OPTION_DEFAULTS.profile_fields;
  if (options.profile_fields !== undefined) {
    const f = options.profile_fields;
    if (!Array.isArray(f) || f.length > MAX_PROFILE_FIELDS) {
      throw new PluginConfigError(`profile_fields must be an array of at most ${MAX_PROFILE_FIELDS} field names`);
    }
    const headers = new Set();
    for (const name of f) {
      if (typeof name !== "string" || !PROFILE_FIELD_RE.test(name) || FORBIDDEN_KEYS.has(name)) {
        throw new PluginConfigError(`profile_fields entry ${JSON.stringify(name)} must be an identifier (letters, digits, "_")`);
      }
      const h = headerNameFor(name);
      if (headers.has(h)) throw new PluginConfigError(`profile_fields entry ${JSON.stringify(name)} duplicates another field (header ${h})`);
      headers.add(h);
    }
    fields = Object.freeze([...f]);
  }

  return Object.freeze({
    endpoint: options.endpoint,
    groups_path: groupsPath,
    on_login_error: oneOf(options, "on_login_error", ON_LOGIN_ERROR),
    degrade_ttl_seconds: positiveInt(options, "degrade_ttl_seconds"),
    profile_endpoint: profileEndpoint,
    profile_fields: fields,
    expose: oneOf(options, "expose", EXPOSE),
    cache_ttl_seconds: positiveInt(options, "cache_ttl_seconds"),
  });
}

/**
 * egress(options): the origins of endpoint and profile_endpoint. Never throws;
 * a bad template (already rejected by validate) contributes nothing.
 * @param {Object} options
 * @returns {string[]}
 */
export function egressFor(options) {
  const out = new Set();
  for (const t of [options && options.endpoint, options && options.profile_endpoint]) {
    if (t === undefined) continue;
    const o = templateOrigin(t);
    if (o) out.add(o);
  }
  return [...out];
}
