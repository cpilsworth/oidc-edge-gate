// user-info middleware plugin (W4.1; docs/architecture/plugins.md §14.3).
//
// Groups (and an optional profile) come from an HTTP user-info backend that
// is called with HTTP Basic service credentials:
//
//   onLogin        at login, GET `endpoint` and add the array at `groups_path`
//                  to the identity draft. A failure either aborts the login
//                  (on_login_error "fail": PluginError 503) or mints a short,
//                  group-less session ("degrade": draft.limitLifetime).
//   beforeForward  with expose "headers", forward the allowlisted
//                  `profile_fields` to the origin as x-user-<field>.
//   handle         a rule handler (e.g. /api/me) returning
//                  {sub, email, name, groups, profile} as JSON.
//
// URL templates take only {sub}/{email}, from the verified draft/identity,
// URL-encoded. Logs carry fixed reason codes only: never the URL, the
// response body or the credentials. See README.md.

import { definePlugin, PluginError } from "../../src/sdk/index.js";
import { NO_STORE_HEADERS, errorResponse } from "../../src/sdk/http.js";
import {
  expandTemplate, failureFields, getJson, LookupFailure, readPath, requireAuthorization,
} from "./lib/backend.js";
import { cacheProfile, loadProfile, pickProfile, profileHeaders } from "./lib/profile.js";
import { egressFor, validateOptions } from "./lib/options.js";

const unavailable = (reason) => new PluginError(503, "user_info_unavailable", `user-info backend unavailable: ${reason}`);

export default definePlugin({
  name: "user-info",
  kind: "middleware",
  description: "Groups at login and an allowlisted profile from an HTTP user-info backend (Basic service credentials).",
  phases: ["beforeForward"],
  trustedHeaderPrefixes: ["x-user-"],
  egress: (options) => egressFor(options),
  secrets: ["user_info_username", "user_info_password"],
  maxFetches: 1,
  defaults: { when: { authenticated: true } },
  // `on_error: "skip"` on a ref only skips UNEXPECTED errors (kernel §5): a
  // backend outage is a PluginError(503), which the kernel never skips.
  allowSkipOnError: true,

  validate(options) {
    return validateOptions(options);
  },

  async onLogin(ctx, draft, options) {
    // Misconfiguration (missing credentials) is a 500 whatever on_login_error says.
    const authorization = requireAuthorization(ctx);
    let body;
    try {
      const url = expandTemplate(options.endpoint, draft);
      body = await getJson(ctx, url, authorization, "user-info-groups");
      const groups = readPath(body, options.groups_path);
      if (groups === undefined) throw new LookupFailure("groups_missing");
      if (!Array.isArray(groups)) throw new LookupFailure("groups_not_array");
      draft.addGroups(groups); // normalizeGroups: strings only, no "," or control characters
    } catch (err) {
      if (!(err instanceof LookupFailure)) throw err;
      if (options.on_login_error === "degrade") {
        ctx.log.warn("user-info lookup failed at login; degraded session without groups",
          { ...failureFields(err, "user-info-groups"), lifetime: options.degrade_ttl_seconds });
        draft.limitLifetime(options.degrade_ttl_seconds);
        return;
      }
      ctx.log.warn("user-info lookup failed at login; login aborted", failureFields(err, "user-info-groups"));
      throw unavailable(err.reason);
    }
    // Same document for groups and profile: warm the profile cache (provisioned only).
    if (options.profile_endpoint === options.endpoint && options.profile_fields.length > 0) {
      let profile = null;
      try { profile = pickProfile(body, options.profile_fields); } catch { /* not an object: nothing to cache */ }
      if (profile) await cacheProfile(ctx, options, draft.sub, profile);
    }
  },

  async beforeForward(ctx, options) {
    if (options.expose !== "headers" || !ctx.identity || options.profile_fields.length === 0) return;
    let profile;
    try {
      profile = await loadProfile(ctx, options, ctx.identity);
    } catch (err) {
      if (!(err instanceof LookupFailure)) throw err;
      ctx.log.warn("user-info profile lookup failed", failureFields(err, "user-info-profile"));
      throw unavailable(err.reason);
    }
    for (const [name, value] of profileHeaders(profile, options.profile_fields)) ctx.forwardHeaders.set(name, value);
  },

  async handle(ctx, options) {
    const id = ctx.identity;
    // The kernel already enforces auth on secured/protected rules; defence in depth.
    if (!id) return errorResponse(401, { error: "unauthorized" }, { headers: { "www-authenticate": "Bearer" } });
    let profile;
    try {
      profile = await loadProfile(ctx, options, id);
    } catch (err) {
      if (!(err instanceof LookupFailure)) throw err;
      ctx.log.warn("user-info profile lookup failed", failureFields(err, "user-info-profile"));
      throw unavailable(err.reason);
    }
    const body = {
      sub: id.sub,
      email: id.email ?? null,
      name: id.name ?? null,
      groups: [...id.groups],
      profile,
    };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8", ...NO_STORE_HEADERS },
    });
  },
});
