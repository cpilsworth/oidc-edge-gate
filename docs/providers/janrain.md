# Provider profile: Janrain / Akamai Identity Cloud (Hosted Login, OIDC)

Status: **desk research only** (2026-10-18). No tenant, discovery URL or client is
available yet, so **nothing here is verified-live**. Every row is either
*documented* (with a source link) or *unverified*. Source IDs like `[S2]` refer to §7.

Synthetic discovery fixture: [`test/fixtures/janrain-discovery.json`](../../test/fixtures/janrain-discovery.json)
(built from the documented example in [S2]; fake all-zero customer id).

---

## 1. Summary

- **What it is.** Janrain was acquired by Akamai and renamed **Akamai Identity Cloud
  (AIC)**, a CIAM service. **Hosted Login** is AIC's OpenID Connect provider:
  an Akamai-hosted sign-in and registration UI, with standard `/authorize`,
  `/token`, `/jwk`, `/userinfo` and `/end_session` endpoints under
  `https://v1.api.{region}.janrain.com/{customerId}/login` [S2][S24]. It is
  OpenID-certified (Basic, Implicit and Hybrid OP) [S25]. User profiles live in the
  Identity Cloud ("Capture") store. The `sub` claim is the user's Identity Cloud UUID [S2][S3].
- **Lifecycle: end of life.** The official Akamai "End of Life & FAQ" page [S1] gives these dates:
  - **2024-03-07:** End of Sale.
  - **2024-10-31:** End of Life formally announced. No new features after 2024.
  - **2026-03-31:** Social Login Dashboard decommissioned. Changes to social apps now need a support ticket.
  - **2027-12-31:** **The service is decommissioned.** Every customer must have migrated by then. Akamai's suggested path is PingOne (Ping Identity).
- **Gate implication.** The Janrain profile should stay a *thin* configuration over
  the generic OIDC path. It has a hard sunset (≤ 14 months from this writing),
  so don't add Janrain-only machinery that can't be removed cleanly.
  The migration target (for example, PingOne) should fit the same generic path.

---

## 2. Capability matrix

Legend: **documented** = stated in official Akamai TechDocs (link). **unverified** = not
documented, ambiguous, or contradicted between pages. Needs a tenant check (§5/§6).
**verified-live** = none yet.

| # | Capability | What the gate needs | What Janrain provides | Status | Impact on gate |
|---|---|---|---|---|---|
| 1 | Issuer URL format | Stable issuer string; `iss` must equal it | Default: `https://v1.api.{us\|eu\|…}.janrain.com/{customerId}/login` (no trailing slash). A **custom issuer domain** (for example `https://login.example.com/login`) is possible through the Akamai rep. | documented [S2][S11] | Config value only. `trimSlash()` is a no-op here. If a custom domain is enabled later, the issuer changes, so update the config *and* re-login all sessions. |
| 2 | Discovery location and fields | `{issuer}/.well-known/openid-configuration` with `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri` (https) | Same location. Fields as in the fixture, plus `introspection_endpoint`, `revocation_endpoint`, `userinfo_endpoint` (`…/{customerId}/profiles/oidc/userinfo`, **not** under `/login`) and `end_session_endpoint`. All tenants get the same document apart from the URLs. | documented [S2] | None. `validateDiscovery()` works unchanged. |
| 3 | `response_types` | `code` | `code`, `id_token`, `token`, `none` and the hybrid combinations. The **login policy** has `allowedResponseTypes` and must include `code`. | documented [S2][S23] | Admin must allow `code` on the login policy (open question 4). |
| 4 | `grant_types` | `authorization_code` | `authorization_code`, `client_credentials`, `implicit`, `password`, `refresh_token`, token-exchange. The **token policy** has `allowedGrantTypes`. | documented [S2][S23] | Token policy must allow `authorization_code`. |
| 5 | `response_modes`: is `query` supported? Is `form_post` the default? | `query` (state cookie is `SameSite=Lax`; a cross-site `form_post` POST would not carry it) | `query`, `fragment`, `form_post`. **The default for `response_type=code` is `query`.** `form_post` is *not* the default (it is only described as "most secure"). `query` is only allowed with `response_type=code`. | documented [S7][S2] | None. Don't send `response_mode` (or send `query` explicitly). The Lax state cookie is fine. |
| 6 | PKCE with a confidential client; `code_challenge_methods_supported` | S256 PKCE **and** client secret on the token call | Discovery: `["S256"]` only (`plain` rejected). PKCE is documented **for public clients** (token call without client authentication). The confidential-client guide doesn't mention PKCE. **Neither guide says whether PKCE + secret together is accepted.** Akamai "strongly recommends" public clients + PKCE for all authorization requests. | S256: documented [S2][S8]. PKCE+confidential: **unverified** | Keep S256 (`pkce.js` already does). Confirm on the tenant (open question 3). Fallback: a public-client mode (`token_endpoint_auth_method: "none"`) in the profile. |
| 7 | Token endpoint auth method | One method, chosen per provider | Discovery advertises `client_secret_basic` **and** `client_secret_post`, but the confidential-client guide says **"Basic authentication is required"**. Its example sends `Authorization: Basic` plus `client_id` in the body. Public clients send `client_id` + `code_verifier` with no auth. | documented, but pages conflict [S2][S9][S8] | **Code change:** the gate sends `client_secret_post` today (`oidc.js` puts the secret in the body). Add `token_endpoint_auth_method` with `client_secret_basic` as the Janrain default. Build the header from `base64(urlencode(id):urlencode(secret))` (RFC 6749 §2.3.1). |
| 8 | "Client secret in the authorization request" | Secret must **never** go on the front channel | Two pages say confidential clients "must include the client secret in the authorization request" [S9][S20]. The worked example puts the secret only on the token call. Probably loose wording, but unconfirmed. | **unverified** | The gate will not put a secret in the `/authorize` URL. If the tenant really requires it, switch to public-client + PKCE (open question 2). |
| 9 | ID token signing alg | RS256 via WebCrypto RSASSA-PKCS1-v1_5 | `id_token_signing_alg_values_supported: ["RS256"]` only. JWKs are `kty: RSA`, `use: sig`, `alg: RS256`, `e: AQAB`. | documented [S2][S4] | None. |
| 10 | `kid` behaviour | `jwt.js` requires a header `kid` that matches a JWKS key | The JWKS normally holds **several** keys with `kid`s, and the token-verification walkthrough matches by `kid` [S4]. But the token reference says header `kid` "is optional… typically present only if you use more than one signing key" [S3]. `kid` need not be unique across `use`/`kty` [S4]. A real sample header includes `kid` [S3]. | **unverified** (docs conflict) | **Small code change (recommended):** if the header has no `kid` *and* exactly one RS256/sig key is in the JWKS, use it. Otherwise fail. The existing `use`/`alg` filter already copes with duplicate `kid`s. |
| 11 | Key rotation and JWKS caching | Refetch on `kid` miss; bounded cache | Akamai rotates keys "from time to time", **usually unannounced**. Clients must not hard-code or cache keys forever. No rotation interval or overlap period is published. | documented (no interval) [S4] | None. The current behaviour (1 h KV cache plus one forced refetch on `kid` miss) matches. On sandbox (no KV) every callback fetches live. |
| 12 | ID token lifetime | Only checked at callback (`exp` + 60 s skew) | Default **1 hour**. Token policies only expose access/refresh lifetimes (60–3600 s / ≤ 1 yr). No documented ID token lifetime setting. | documented default [S3][S17] | None. Gate session TTL is independent. |
| 13 | `iss` / `aud` / `azp` | `iss` == issuer; `aud` contains `client_id`; if `aud` has several values, `azp` == `client_id` | `iss` = issuer URL. **`aud` may be an array.** The text says it "will always" include the client ID **and the redirect URI** [S3]. A real sample shows `aud: [clientId]` [S16]. **`azp` is "always the OIDC client ID"** [S3]. | documented, examples inconsistent [S3][S16] | None needed. `audienceMatches()` handles arrays, and the multi-`aud` → `azp` check passes because `azp` is the client id. Add a test with `aud: [clientId, redirectUri]` + `azp`. One legacy sample shows `iss: "accounts.janrain.com"`, so check `iss` live (§6). |
| 14 | `nonce` | Echoed in ID token | Supported, "optional but recommended". Echoed in the ID token. | documented [S9][S10] | None (gate always sends `nonce`). |
| 15 | `at_hash` / `c_hash` | Verified when present | `at_hash` documented and present in samples [S3][S16]. `c_hash` not documented for the code flow. | `at_hash` documented, `c_hash` unverified | None. The gate checks each only when present. |
| 16 | Other ID token claims | Ignored safely | `sid` (Hosted Login session id), `global_sub` (Capture path), `acr`, `amr`, `auth_time`, `jti` [S16][S3] | documented [S16] | None. Optionally store `sid` in the session for global logout (row 22). |
| 17 | `sub` format | Non-empty string | Identity Cloud **UUID** (for example `3c388dd9-…`). `subject_types_supported: ["public"]` (same `sub` across clients). | documented [S2][S3] | None. The UUID is also the likely join key for the user-info/groups backend (open question 11). |
| 18 | `email`, `email_verified`, `name` in the **ID token** | `sub` required; `email`/`name` nice-to-have, read from the ID token (no extra call) | **Scopes only populate userinfo, never the ID token**: "scope information is *only* accessible from the userinfo endpoint". To put claims in the ID token, use the OIDC **`claims` parameter** (`{"id_token":{"email":null,…}}`, `claims_parameter_supported: true`) **or** admin-side **push claims** (login policy `customClaims` + `pushClaims=true`). **When push claims are on, the `scope`/`claims` request parameters are ignored.** `email_verified` is boolean in [S5] and the samples but "date and time" in [S2]. `name` has **no mapped profile attribute** and is missing from `claims_supported` [S5][S2]; `given_name`/`family_name` map to `givenName`/`familyName`. Scopes outside the token policy's `allowedScopes` are silently dropped. | documented [S5][S6][S18][S2]; `name` population and `email_verified` type **unverified** | **Code change:** the provider profile needs `authorize_params` (send `claims`). Map `name` with a fallback (`name` → `given_name family_name` → `preferred_username`). Treat `email_verified` as truthy/boolean-or-timestamp if it is ever used. |
| 19 | `claims` request parameter | JSON-encoded authorize param | Supported, both `userinfo` and `id_token` targets, standard and custom claims | documented [S6][S2] | See row 18. |
| 20 | Required scopes | `openid` | `openid` is mandatory. `profile`, `email`, `address`, `phone`, `offline_access` are supported. **No custom scopes.** | documented [S2][S5] | `scopes: "openid email profile"` (harmless if dropped). |
| 21 | Userinfo endpoint | **Not used** (one callback-time call at most, never per request) | `GET {base}/{customerId}/profiles/oidc/userinfo` with `Authorization: Bearer <access_token>`. Returns `sub`, `global_sub` and the claims allowed by scope/claims/token policy. | documented [S13][S2] | None. Optional fallback: one call at the callback if the ID token lacks `email`. Not needed if row 18 works. |
| 22 | `end_session_endpoint` / RP-initiated logout | Front-channel 302 that ends the IdP session and returns to the site | `{issuer}/end_session`, **called in the browser**. Parameters: `client_id` (functionally required), `post_logout_redirect_uri` (functionally required; must be in the client's **`postLogoutRedirectURIs`**), `state` (functionally required), optional `logout_hint=<sid>` for **global** logout (all devices). The default is local logout (this device only). **`id_token_hint` is not documented.** Legacy alternative: `/{customerId}/auth-ui/logout?client_id&redirect_uri&state` (`redirect_uri` must be in `redirectURIs`). | documented [S11][S12]; `id_token_hint` **unverified** | **Code change:** add a random `state` to the logout URL (the gate currently sends only `client_id` + `post_logout_redirect_uri`). Make the post-logout path configurable. `id_token_hint` is not needed (the gate doesn't keep the ID token). |
| 23 | Token revocation endpoint | Not needed (the gate keeps no access/refresh token) | `{issuer}/token/revoke`. Revokes access/refresh tokens, not ID tokens. Confidential clients use Basic auth. IdP logout does **not** revoke tokens. | documented [S2][S22][S12] | None. Tokens are discarded after the callback. |
| 24 | Access token format | Not needed | **Opaque** by default. JWT access tokens via token policy `useAccessJWT: true` (RS256, `jku`/`kid`). Max lifetime 3600 s. Introspection only for confidential clients. | documented [S3][S17] | None. Keep opaque. The gate doesn't use the AT (except to check `at_hash`). |
| 25 | Redirect URI rules | One exact callback per environment host, plus local dev | **Exact match** against the client's `redirectURIs` array. **Multiple URIs per client** are allowed. **No wildcards** (`*.akamai.com` rejected). Query params allowed except `code`/`state`. **HTTPS only**, with one exception: guide says only `http://127.0.0.1`, API reference says only `localhost`. `https://localhost:3001/…` appears in examples. PUTting a client replaces *all* fields (omitted optional fields are nulled). | documented [S14][S15][S20]; http-loopback exception and port handling **unverified** | Register `https://<each env host>/.auth/callback` exactly, plus the local URI. **Local dev:** `fastly compute serve` uses `http://localhost:7676`, which may be rejected. Plan to use `http://127.0.0.1:7676/.auth/callback` (`effectiveRedirectUri()` already derives from the request origin) or an https tunnel. Per-environment custom domains: one login client listing every env callback, or one client per env (open question 6). |
| 26 | Client configuration objects | One confidential OIDC client with the redirect/post-logout URIs and a token policy | **OIDC login client** (`type: public\|confidential`, **immutable**; `redirectURIs`, `postLogoutRedirectURIs`, `loginPolicy` (required), `tokenPolicy` (required)). **Login policy:** allowed response types, custom/push claims, application/flow binding. **Token policy:** `allowedScopes`, `allowedGrantTypes`, AT/RT lifetimes, `useAccessJWT`. **Configuration client:** a confidential client *without* a login policy, used only for admin config-API tokens, **not usable for login**. Plus the Capture **application/API client** linked to the login client (flow, emails). | documented [S14][S23][S20] | Ask the admin for a *login* client (not a configuration client), with the settings in §5. The gate needs only the login client's `client_id` + secret. |
| 27 | Client secret rotation | Rotate without downtime | `POST /config/clients/{id}/secret` **resets** the secret and returns the new one. No dual-secret or overlap window is documented. | documented [S21]; overlap **unverified** | Rotation = reset → update the secret store/CI secret → redeploy. Expect a brief login outage unless the tenant supports overlap (open question 9). Existing gate sessions are unaffected (HMAC key is separate). |
| 28 | Rate limits / quotas | ≤ 32 backend requests per execution; no per-request IdP calls | **No published rate limits** for the Hosted Login OIDC endpoints. The gate makes ≤ 1 discovery fetch at login start and ≤ 5 at the callback (discovery ×2, token, JWKS, +1 JWKS on `kid` miss) when KV is absent. | **unverified** | None expected. Confirm limits and whether edge egress IPs could trip Akamai bot/rate protection (open question 10). |
| 29 | CORS / third-party cookies | Top-level redirects only; no iframes or XHR to the IdP | Hosted Login sets its own first-party cookies (session `{customerId}`/`aic_authui_{customerId}`: HttpOnly, Secure, SameSite=Lax; plus `_csrf_token` and bot-manager cookies) on the IdP host during top-level navigation. Cookies must be enabled. `prompt=none` SSO depends on those cookies. | documented [S19][S16] | None. The token exchange is server-side (no CORS). Avoid hidden-iframe `prompt=none` checks (third-party cookie blocking). |
| 30 | Anything needing a per-request backend call | None | Nothing in this design. Introspection/userinfo exist but aren't needed, because the gate trusts its own HMAC session after verifying the ID token once. | documented [S2][S3] | None. **No per-request IdP calls.** |

---

## 3. Required gate configuration: `janrain` provider profile

Proposed shape. Field names are suggestions for the provider-profile work package.
Secrets stay in the secret store or embedded fallback and are never written here.

```jsonc
{
  "provider": "janrain",
  "options": {
    // Exact issuer from the tenant's discovery doc (no trailing slash).
    // Default pattern: https://v1.api.<region>.janrain.com/<customerId>/login
    "issuer": "https://v1.api.us.janrain.com/00000000-0000-0000-0000-000000000000/login",
    "client_id": "<OIDC login client id (UUID)>",          // confidential login client
    // client_secret: from secrets (OIDC_CLIENT_SECRET), never in config
    "scopes": "openid email profile",                        // scopes alone only feed userinfo (§2 row 18)
    "token_endpoint_auth_method": "client_secret_basic",     // guide says Basic is required (§2 row 7)
    "pkce": "S256",                                          // only method supported
    "response_mode": null,                                   // omit → default "query" for response_type=code
    "authorize_params": {
      // Put identity claims in the ID token so no userinfo call is needed.
      // Ignored by the IdP if the login policy uses push claims.
      "claims": "{\"id_token\":{\"email\":null,\"email_verified\":null,\"given_name\":null,\"family_name\":null,\"name\":null}}"
      // optional: "prompt": "login" (force re-auth), "ui_locales": "en-GB", "max_age": "<seconds>"
    },
    "id_token": {
      "algs": ["RS256"],
      "allow_missing_kid_single_key": true,                  // §2 row 10
      "require_azp_when_multi_aud": true                     // already enforced in jwt.js
    },
    "claim_map": {
      "name": ["name", "given_name family_name", "preferred_username"],
      "email": "email"
    },
    "groups_source": "userinfo_backend",                     // NOT an ID token claim for Janrain
    "end_session": {
      "enabled": true,                                       // use discovery end_session_endpoint
      "params": ["client_id", "post_logout_redirect_uri", "state"],
      "id_token_hint": false,                                // not documented; gate doesn't keep the ID token
      "global_logout_via_sid": false,                        // true → store `sid` in session, send logout_hint
      "post_logout_redirect_path": "/"                       // must be listed in postLogoutRedirectURIs per host
    }
  }
}
```

Defaults and rationale:

- **`token_endpoint_auth_method: client_secret_basic`.** The confidential-client guide says Basic
  is required [S9]. Discovery also lists `client_secret_post` [S2], so `post` is
  the fallback if Basic fails. The generic code path must support both (Auth0 uses `post`).
- **`scopes: openid email profile` + `claims`.** Janrain's scopes never put claims in the ID token [S5].
  The `claims` parameter does [S6]. Requesting the scopes as well costs nothing and keeps the
  userinfo fallback working. Scopes not in the token policy's `allowedScopes` are silently dropped.
- **No `response_mode`.** The default `query` matches the `SameSite=Lax` state cookie [S7].
- **`prompt`/`ui_locales`/`max_age`** are optional and off by default. `ui_locales` is
  ignored unless the locale exists in the tenant's flow [S10].
- **End session.** Send `state` because Akamai lists it as "functionally required" [S11].
  Default to local (this-device) logout. Global logout needs `sid` in the session cookie.

Code changes this profile needs (to be scheduled by the orchestrator, not done here):
1. `oidc.js` `handleCallback`: switchable token endpoint auth (`client_secret_basic` | `client_secret_post` | `none`).
2. `oidc.js` `startLogin`: append `authorize_params`.
3. `jwt.js` `importSigningKey`: single-key fallback when the header has no `kid`.
4. `oidc.js` `handleLogout`: add `state`, use a configurable param set and post-logout path.
5. `session.js`: claim mapping for `name` (and tolerant `email_verified`). Groups come from the backend (separate work package).

---

## 4. Differences from Auth0 that the profile must encode

| Auth0 (current gate configuration) | Janrain / Akamai Hosted Login |
|---|---|
| Issuer `https://<tenant>.auth0.com/` (trailing slash, trimmed by the gate) | Issuer `https://v1.api.<region>.janrain.com/<customerId>/login` (path-based, no trailing slash). Custom issuer domain is optional [S2]. |
| Groups from a namespaced ID token claim set by a post-login Action (`groups_claim`) | **No groups in tokens.** Groups come from the separate user-info backend. `groups_claim` is unused. |
| `email`/`name` appear in the ID token when the `email`/`profile` scopes are requested | Scopes only feed **userinfo**. ID token claims need the **`claims` parameter** or push claims [S5][S6]. `name` may be empty (no mapped attribute). |
| Gate sends `client_secret_post` (secret in the form body) | Guide says **HTTP Basic is required** for confidential clients (`client_secret_basic`). Discovery also lists `post` [S9][S2]. |
| ID token `aud` is the client id (single value) | `aud` may be an **array** (client id, possibly the redirect URI) with `azp` = client id [S3][S16] |
| Header `kid` always present | `kid` documented as optional when there is a single key [S3]. Keys rotate unannounced [S4]. |
| Logout: discovery `end_session_endpoint` with `client_id` + `post_logout_redirect_uri` (Allowed Logout URLs) | `end_session` needs `client_id` + `post_logout_redirect_uri` (in `postLogoutRedirectURIs`) **+ `state`**. Optional `logout_hint=sid` for global logout. No `id_token_hint` documented [S11]. |
| `http://localhost:<port>` callback works for local dev | HTTPS only, except **`http://127.0.0.1`** (guide) / `localhost` (API reference). Port handling unverified. Exact match, no wildcards [S14][S20]. |
| PKCE with a confidential client: in use today | PKCE documented for **public** clients. Akamai recommends public + PKCE. Confidential + PKCE is **unverified** [S8][S14]. |
| `email_verified` is boolean | Boolean in the claims table and samples, but "date and time" in the discovery article. Parse tolerantly [S5][S2]. |
| Actively developed product | **End of life**: no new features since 2024, decommissioned **2027-12-31** [S1] |

---

## 5. Open questions for the Janrain / Akamai administrator

1. What is the **exact issuer / discovery URL** (region host `v1.api.us|eu|….janrain.com` + customer id, or a custom issuer domain)? Will a custom domain be enabled, and when?
2. Is the gate's OIDC client a **confidential login client** (with a login policy), not a configuration client? Does the tenant ever require `client_secret` on the **`/authorize`** request (docs suggest it)? If so, can we use a **public client + PKCE** instead?
3. With a confidential client, does `/token` **accept PKCE** (`code_verifier`) together with client authentication? Is PKCE **enforced**?
4. Does the **login policy**'s `allowedResponseTypes` include `code`, and does the **token policy**'s `allowedGrantTypes` include `authorization_code`?
5. Which **token endpoint auth method** does the client accept: `client_secret_basic`, `client_secret_post`, or both?
6. Can the client hold **all per-environment callbacks** (`https://<host>/.auth/callback` for each env/custom domain), or is one client per environment preferred? Is an **http loopback** URI allowed for local dev (`http://127.0.0.1:7676/.auth/callback` or `http://localhost:7676/...`)? Are **ports** matched exactly?
7. Is **RP-initiated logout** (`end_session`) enabled? Can `postLogoutRedirectURIs` be set to each env's `https://<host>/`? Is `id_token_hint` accepted or required? Is local or global logout wanted?
8. What is in the **token policy** `allowedScopes` (need at least `openid`, ideally `email profile`)? Are **push claims** enabled on the login policy (they override our `claims` parameter)? Will `email`, `email_verified`, `given_name`/`family_name` (and `name`) be populated in the **ID token**?
9. What is the **client secret rotation** procedure? Is there any overlap window, or does `POST …/secret` invalidate the old secret immediately?
10. Are there **rate limits** / bot-manager rules on `/login/authorize`, `/login/token` and `/login/jwk` that could affect requests from Fastly/AEM edge egress IPs?
11. Is the Identity Cloud **UUID (`sub`) the key** the separate user-info/groups backend uses? Is that backend part of Identity Cloud (for example a Capture API client) or external?
12. Does the ID token header always carry a **`kid`**? Does the JWKS contain more than one key? Is there a published **rotation cadence**?
13. Given **EOL on 2027-12-31**, what is the planned **successor IdP** (for example PingOne) and timeline? This decides how much Janrain-specific work is justified.

---

## 6. Verification checklist (once a tenant URL exists)

**Discovery document.** Replace the placeholder. This only reads public metadata.

```bash
ISSUER='https://<host>/<customerId>/login'     # placeholder: do not commit a real one here
curl -fsS "$ISSUER/.well-known/openid-configuration" -o /tmp/janrain-discovery.live.json
jq '{issuer, authorization_endpoint, token_endpoint, jwks_uri, userinfo_endpoint, end_session_endpoint,
     response_modes_supported, response_types_supported, grant_types_supported,
     token_endpoint_auth_methods_supported, code_challenge_methods_supported,
     id_token_signing_alg_values_supported, claims_parameter_supported, scopes_supported, claims_supported}' \
   /tmp/janrain-discovery.live.json
# Structural diff against the synthetic fixture (ignoring URLs):
diff <(jq -S 'del(._comment) | with_entries(select(.key | test("_endpoint$|^issuer$|^jwks_uri$") | not))' test/fixtures/janrain-discovery.json) \
     <(jq -S 'with_entries(select(.key | test("_endpoint$|^issuer$|^jwks_uri$") | not))' /tmp/janrain-discovery.live.json)
# JWKS shape (kid count, alg, use):
curl -fsS "$(jq -r .jwks_uri /tmp/janrain-discovery.live.json)" | jq '.keys[] | {kid, kty, alg, use}'
```

Check:
- [ ] `issuer` exactly equals the configured issuer (no trailing slash). Every endpoint is https.
- [ ] `response_modes_supported` contains `query`. `code_challenge_methods_supported` contains `S256`.
- [ ] `token_endpoint_auth_methods_supported` contains the method the profile uses.
- [ ] `id_token_signing_alg_values_supported` is `["RS256"]`. JWKS keys are `RSA`/`sig`/`RS256`, and you've noted how many.
- [ ] `end_session_endpoint` is present.
- [ ] Replace the synthetic fixture with the live document (customer id anonymised) and remove "synthetic" from `_comment`.

**One test login** (test user, non-production; inspect claims in gate debug logs, never commit tokens):
- [ ] The callback arrives as a `GET` with `?code&state` (query mode). The state cookie is present.
- [ ] Token exchange succeeds with `client_secret_basic` + `code_verifier`. Also try `client_secret_post` and record the result.
- [ ] ID token header: `alg=RS256`, `kid` present or absent?
- [ ] ID token payload: `iss` == issuer, `aud` shape (string or array, includes redirect URI?), `azp` == client id, `nonce` matches, `at_hash` present, `exp - iat` ≈ 3600.
- [ ] `sub` is a UUID. `email`, `email_verified` (type?), `name` / `given_name` / `family_name` present when the `claims` param is sent.
- [ ] Logout: the 302 to `end_session` with `client_id`, `post_logout_redirect_uri` and `state` returns to the site. A later login prompts for credentials.
- [ ] Local dev: the loopback callback is accepted (record which form works).
- [ ] Update the matrix statuses to **verified-live** where confirmed.

---

## 7. Sources

Official Akamai TechDocs (current; Identity Cloud / Hosted Login), retrieved 2026-10-18:

- [S1] End of Life & FAQ: https://techdocs.akamai.com/identity-cloud/docs/product-status
- [S2] Discovery document: https://techdocs.akamai.com/identity-cloud/docs/the-discovery-document
- [S3] Token reference (access, refresh, identity tokens; JWT access tokens): https://techdocs.akamai.com/identity-cloud/docs/token-reference
- [S4] JSON web keys (incl. rotation): https://techdocs.akamai.com/identity-cloud/docs/json-web-keys-1
- [S5] Scopes and claims: https://techdocs.akamai.com/identity-cloud/docs/scopes-and-claims
- [S6] Return standard and custom claims (`claims` parameter): https://techdocs.akamai.com/identity-cloud/docs/return-standard-and-custom-claims
- [S7] Supported response modes: https://techdocs.akamai.com/identity-cloud/docs/supported-response-modes-1
- [S8] Authorization code + PKCE grant type: https://techdocs.akamai.com/identity-cloud/docs/the-authorization-code-pkce-grant-type
- [S9] Authorization code for web apps (confidential client) grant type: https://techdocs.akamai.com/identity-cloud/docs/the-authorization-code-for-web-apps-grant-type
- [S10] Optional authorization request parameters (prompt, ui_locales, max_age, nonce): https://techdocs.akamai.com/identity-cloud/docs/optional-authorization-request-parameters
- [S11] OIDC end_session_endpoint: https://techdocs.akamai.com/identity-cloud/docs/oidc-end_session_endpoint
- [S12] Logout from Hosted Login (`/auth-ui/logout`): https://techdocs.akamai.com/identity-cloud/docs/logout-from-hosted-login
- [S13] View userinfo information: https://techdocs.akamai.com/identity-cloud/docs/view-userinfo-information
- [S14] Create an OIDC login client (client types, redirectURIs rules): https://techdocs.akamai.com/identity-cloud/docs/create-an-oidc-login-client
- [S15] Add a redirect URI to a login client: https://techdocs.akamai.com/identity-cloud/docs/add-a-redirect-uri-to-a-login-client
- [S16] Hosted Login session checking (real ID token sample with `sid`, `azp`, `at_hash`): https://techdocs.akamai.com/identity-cloud/docs/hosted-login-session-checking
- [S17] Modify token lifetimes: https://techdocs.akamai.com/identity-cloud/docs/modify-token-lifetimes
- [S18] Push claims: https://techdocs.akamai.com/identity-cloud/docs/push-claims-1
- [S19] Cookies and local storage: https://techdocs.akamai.com/identity-cloud/docs/hosted-login-cookies-and-local-storage-1
- [S20] Hosted Login API, Create an OIDC client: https://techdocs.akamai.com/identity-cloud-hosted-login/reference/post-oidc-clients
- [S21] Hosted Login API, Reset a client secret: https://techdocs.akamai.com/identity-cloud-hosted-login/reference/post-reset-client-secret
- [S22] Hosted Login API, Revoke a token: https://techdocs.akamai.com/identity-cloud-hosted-login/reference/post-revoke-token
- [S23] Hosted Login API, allowed response types / grant types: https://techdocs.akamai.com/identity-cloud-hosted-login/reference/get-allowed-response-types , https://techdocs.akamai.com/identity-cloud-hosted-login/reference/get-allowed-grant-types
- [S24] Introduction to Hosted Login: https://techdocs.akamai.com/identity-cloud/docs/an-introduction-to-hosted-login-1
- [S25] OpenID Connect certification: https://techdocs.akamai.com/identity-cloud/docs/openid-connect-certification
- Also consulted: session logout semantics, https://techdocs.akamai.com/identity-cloud/docs/session-logout-in-hosted-login ; Akamai discontinued-products list (Identity Cloud not listed there as of 2026-08), https://techdocs.akamai.com/home/page/akamai-discontinued-products

Third-party (corroboration only, not relied on): several CIAM vendor and consultancy
blogs (for example Next Reason, SSOJet) repeat the 2027-12-31 shutdown date from [S1].

No legacy Janrain (pre-Akamai) documentation was needed. All rows above cite current Akamai TechDocs.
