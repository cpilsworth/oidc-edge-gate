// IdP revocation webhook: adapter skeleton (docs/architecture/plugins.md §15.6).
//
// OWNER: W3.3. This file is a W3.0 stub: the route is only claimed when the
// `webhook_path` option is set, and it answers 501 until an adapter exists.

import { errorResponse } from "../../../src/sdk/http.js";

/** Adapter names accepted by the `webhook_adapter` option. */
export const WEBHOOK_ADAPTERS = Object.freeze(["janrain"]);

/**
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {import("./settings.js").OidcSettings} s
 * @returns {Promise<Response>}
 */
// eslint-disable-next-line no-unused-vars
export async function handleWebhook(ctx, s) {
  return errorResponse(501, { error: "not_implemented" }, { headers: { "x-auth-request-id": ctx.requestId } });
}
