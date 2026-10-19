// Server-side revocation check, run inside authenticate() on every request
// that carries a verified session (docs/architecture/plugins.md §15).
//
// OWNER: W3.2. Order of the check (§15.3): the global cutoff session_min_iat
// (config, every mode), then the effective mode, then the two KV records (sid
// and per-user epoch) read in parallel through ./revocation-store.js. A read
// that proves a revocation wins over a failed one; only "can't tell" is
// decided by the mode. Logs carry the reason or an error class only: never a
// sid, sub, cookie or KV key.

import { PluginError } from "../../../src/sdk/index.js";
import { isSessionRevoked, subjectRevokedAt } from "./revocation-store.js";

/** Values of the `revocation_mode` config key. */
export const REVOCATION_MODES = Object.freeze(["auto", "required", "optional", "disabled"]);

/**
 * The effective mode for this request (§15.1): `auto` is `required` on the
 * provisioned profile and `optional` on sandbox; anything else is used as-is.
 * A missing ctx.config.revocationMode (plugin unit tests) means `auto`.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @returns {"required"|"optional"|"disabled"}
 */
export function effectiveRevocationMode(ctx) {
  const mode = ctx.config.revocationMode ?? "auto";
  if (mode === "auto") return ctx.platform.profile === "provisioned" ? "required" : "optional";
  if (mode === "required" || mode === "optional" || mode === "disabled") return mode;
  throw new Error(`oidc-auth: invalid revocation_mode ${JSON.stringify(String(mode))}`);
}

/**
 * @typedef {Object} RevocationVerdict
 * @property {boolean} revoked
 * @property {"min_iat"|"sid"|"sub"} [reason]  set when revoked
 */

/**
 * Decide whether a verified session has been revoked (§15.3).
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {{sid: string, sub: string, iat: number, exp: number}} session  a verified session (session.js)
 * @returns {Promise<RevocationVerdict>}
 * @throws {import("../../../src/sdk/index.js").PluginError} 503 revocation_unavailable (mode required, KV missing or failing)
 */
export async function checkRevocation(ctx, session) {
  // 1. Global cutoff: config, not KV, so it holds in every mode and profile.
  const minIat = ctx.config.sessionMinIat;
  if (typeof minIat === "number" && session.iat < minIat) return revoked(ctx, "min_iat");

  // 2. Mode (throws on an unknown mode: config validation should have caught it).
  const mode = effectiveRevocationMode(ctx);
  if (mode === "disabled") return NOT_REVOKED;

  // 3. No KV bound.
  const kv = ctx.kv;
  if (!kv) {
    if (mode === "required") {
      throw new PluginError(503, "revocation_unavailable", "oidc-auth: revocation_mode required but no KV store is bound");
    }
    return NOT_REVOKED;
  }

  // 4. Exactly two KV reads, in parallel. allSettled so neither rejection is
  // left unhandled. A key-building TypeError (malformed sid or empty sub,
  // impossible for a verified session) rejects the same way and is treated as
  // a failure.
  const [sidResult, subResult] = await Promise.allSettled([
    isSessionRevoked(kv, session.sid),
    subjectRevokedAt(kv, session.sub),
  ]);

  // 5. Verdict from the reads that succeeded: a proven revocation wins in every
  // mode, even when the other read failed (W3.R R3-1).
  if (sidResult.status === "fulfilled" && sidResult.value === true) return revoked(ctx, "sid");
  if (subResult.status === "fulfilled") {
    const revokedAt = subResult.value;
    if (revokedAt !== null && session.iat <= revokedAt) return revoked(ctx, "sub");
  }

  // 6. Nothing proved a revocation. A failed read means "can't tell": the mode
  // decides (required: fail closed; optional: log and accept).
  const failed = [sidResult, subResult].find((r) => r.status === "rejected");
  if (failed) {
    const errorClass = errorClassOf(failed.reason);
    if (mode === "required") {
      throw new PluginError(503, "revocation_unavailable", `oidc-auth: revocation check failed (${errorClass})`);
    }
    ctx.log.warn("revocation check failed; session accepted (revocation_mode optional)", { error: errorClass });
  }
  return NOT_REVOKED;
}

const NOT_REVOKED = Object.freeze({ revoked: false });

/** 7. Log the reason only and return the verdict. */
function revoked(ctx, reason) {
  ctx.log.info("session revoked", { reason });
  return { revoked: true, reason };
}

/**
 * The error's class name, safe to log: never its message (a KV error message
 * may contain the key). Anything unusual collapses to "Error".
 */
function errorClassOf(err) {
  const name = err !== null && typeof err === "object" ? err.name : undefined;
  return typeof name === "string" && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(name) ? name : "Error";
}
