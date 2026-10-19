// POST /.auth/admin/revoke: signed, provisioned-only revocation API
// (docs/architecture/plugins.md §15.5).
//
// OWNER: W3.3. This file is a W3.0 stub: the route is claimed but always
// answers 404, exactly what it must answer wherever the feature is unavailable.

import { errorResponse } from "../../../src/sdk/http.js";

/**
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {import("./settings.js").OidcSettings} s
 * @returns {Promise<Response>}
 */
// eslint-disable-next-line no-unused-vars
export async function handleAdminRevoke(ctx, s) {
  return errorResponse(404, { error: "not_found" }, { headers: { "x-auth-request-id": ctx.requestId } });
}
