# user-info

Middleware plugin that takes a user's **groups at login** and, optionally, an
**allowlisted profile** from an HTTP user-info backend. The backend is called
with HTTP Basic service credentials. Spec: `docs/architecture/plugins.md` §14.3.

| | |
|---|---|
| Kind | `middleware`, phase `beforeForward`, plus `onLogin`, `onLogout` and `handle()` |
| Trusted header prefix | `x-user-` (stripped from every inbound request by the kernel, `x_user_*` lookalikes too) |
| `identityHeaders` | `true`: `x-user-*` carry profile PII, so a rule's third-party `upstream` gets them only with `forward_identity: true` (the EDS origin always does) |
| Egress | the origin(s) of `endpoint` and `profile_endpoint`; `maxFetches: 2` per request |
| Secrets | `user_info_username`, `user_info_password` |
| Defaults | `when: { authenticated: true }`, `on_error: "fail"` |
| `allowSkipOnError` | `true` (see "Errors" for what `on_error: "skip"` does and does not cover) |

## What it does

- **`onLogin(ctx, draft, options)`** runs during the OIDC callback, after the
  ID token is verified and before the session exists. It GETs `endpoint`,
  reads the JSON array at `groups_path`, and adds it to the draft with
  `draft.addGroups()`. A response with more than **256** entries (counted
  before normalizing) is a failed lookup (`too_many_groups`), so
  `on_login_error` applies. The SDK normalizes the groups: only strings of
  1–128 printable ASCII characters (0x20–0x7E), no `,`, no leading or
  trailing space; de-duplicated, order kept; anything else is dropped. The
  session then carries those groups, so policy `audience` rules use them.
  The login also refreshes the KV profile cache (see "Profile data at rest").
- **`onLogout(ctx, identity)`** deletes the subject's cached profile from KV.
- **`beforeForward`** with `expose: "headers"` sends the allowlisted
  `profile_fields` to the origin as `x-user-<field>` headers. Field names are
  lowercased and `_` becomes `-`, so `given_name` becomes `x-user-given-name`.
  With `expose: "none"` (the default) it does nothing. On a rule with an
  `upstream`, the headers are sent only when the rule also sets
  `forward_identity: true`, the same rule as `x-auth-*`.
- **`handle(ctx, options)`** is a rule handler, for example `/api/me`. It
  returns `200` JSON
  `{"sub", "email", "name", "groups", "profile": {…allowlisted}}`.
  `email` and `name` are `null` when the identity has none. Without an
  identity it returns `401 {"error":"unauthorized"}`. The kernel already
  enforces authentication on secured rules, so this is defence in depth.

## Options

Set the options under `plugins["user-info"]`. A middleware ref (`{"use": "user-info"}`)
and the rule handler both start from these base options, and `endpoint` must
be there. A ref's own `options` are merged over them.

| Option | Default | Meaning |
|---|---|---|
| `endpoint` | required | URL template for the groups lookup at login, e.g. `https://users.example.com/v1/users/{sub}`; the only variable is `{sub}` |
| `groups_path` | `"groups"` | dot path to the groups array in the response, e.g. `"data.groups"` |
| `on_login_error` | `"fail"` | `"fail"` aborts the login. `"degrade"` mints a short session without the backend's groups (a `"claim"` provider's groups are kept) |
| `degrade_ttl_seconds` | `300` | session lifetime cap when degraded (positive integer) |
| `profile_endpoint` | `endpoint` | URL template for profile lookups |
| `profile_fields` | `[]` | allowlist of top-level profile fields: identifiers (`[A-Za-z_][A-Za-z0-9_]*`, at most 64 characters), at most 64 fields, which must map to distinct headers |
| `expose` | `"none"` | `"none"` or `"headers"` (`x-user-<field>` to the origin) |
| `cache_ttl_seconds` | `300` | profile cache lifetime in KV (provisioned only; positive integer) |

`validate()` rejects any unknown key and any invalid value, and that fails the
config load (fail closed). It checks the following:

- **URL templates:** an absolute `https://` URL with no credentials and no
  fragment. `http://` is allowed only for `localhost` and `127.0.0.1`, for
  local development. The only variable is `{sub}`, and it may appear only
  after the host. **`{email}` is rejected** ("lookups are by the verified
  `{sub}` only"): an IdP can assert an email it has not verified, and
  selecting the backend record by it would hand one user another user's
  groups and profile. The path must already be in canonical form,
  with no `.` or `..` segments and no characters the URL parser would
  re-encode.
- **`groups_path`:** a dot path of JSON keys.
- **Enums and integers:** `on_login_error` and `expose` must be one of their
  listed values. `degrade_ttl_seconds` and `cache_ttl_seconds` must be
  positive integers.

## Secrets

| Key | Use |
|---|---|
| `user_info_username` | HTTP Basic username of the service account |
| `user_info_password` | HTTP Basic password |

Requests carry `Authorization: Basic base64(username:password)`. The header is
built from UTF-8 bytes, so non-ASCII credentials work. The header and the
credentials are never logged.

If either secret is missing, the plugin treats it as a misconfiguration. It
logs `reason: "missing_credentials"` with the key names only and fails with
`500 {"error":"internal_error"}`. A username containing `:` is a
misconfiguration too (HTTP Basic splits at the first `:`, so the backend would
see a different user): `reason: "username_contains_colon"`, no values logged,
the same 500. Both apply even with `on_login_error: "degrade"`.

**Provisioned:** put both keys in the SecretStore `secrets` JSON bundle, or
store them as individual SecretStore keys (the per-key fallback reads every
secret a registered plugin declares).

**Sandbox:** the keys come from the embedded secrets in
`src/embedded-config.js`.

## Policy example

```jsonc
{
  "version": 2,
  "default_tier": "protected",
  "authentication": { "use": "oidc-auth" },
  "plugins": {
    "user-info": {
      "endpoint": "https://users.example.com/v1/users/{sub}",
      "groups_path": "data.groups",
      "on_login_error": "fail",
      "profile_fields": ["given_name", "department"],
      "expose": "headers"
    }
  },
  "rules": [
    { "path": "/api/me", "tier": "secured", "handler": "user-info" },
    { "path": "/protected/medical/*", "tier": "protected", "audience": ["medical"],
      "middleware": [ { "use": "user-info" } ] }
  ]
}
```

- **Enabling `onLogin`:** listing the plugin under `plugins` is enough. Its
  `onLogin` then runs at every login, whether or not any rule uses it.
- **The `x-user-*` headers:** these are sent only where a middleware ref uses
  the plugin.
- **A ref's own `when`:** a `when` on a ref *replaces* the default
  `{authenticated: true}`. The hook still does nothing without an identity.

## Errors

| Situation | Result |
|---|---|
| Login lookup fails, `on_login_error: "fail"` | `PluginError(503, "user_info_unavailable")`. The login is aborted and no session is set. The callback (W2.3) answers 503. |
| Login lookup fails, `on_login_error: "degrade"` | A `warn` log, then `draft.limitLifetime(degrade_ttl_seconds)`. Only the **backend's** groups are lost. With a `groupsSource: "claim"` provider (Auth0, generic) the ID-token claim groups are already on the draft and are **kept**, so audience pages they grant stay open for the short session; with Janrain (`"user-info"`) the draft is empty, so the session has no groups. The session's `exp` and `Max-Age` come from `identity.expiresAt`. |
| Profile lookup fails (`beforeForward` or `handle`) | `503 {"error":"user_info_unavailable"}` |
| Credentials missing, or a username containing `:` | `500 {"error":"internal_error"}` |
| Egress or budget violation | The kernel answers `500 egress_denied` or `503 budget_exceeded`. These are never degraded. |

A lookup fails on any of the following:

- a network error
- a non-2xx status, including redirects, which are never followed
- a body larger than 256 KiB
- a body that is not JSON
- a `groups_path` that is missing or is not an array
- more than 256 groups
- a profile document that is not a JSON object

`on_error: "skip"` on a ref is allowed because `allowSkipOnError` is `true`.
It skips only **unexpected** errors, such as a bug. A backend outage is a
`PluginError`, and the kernel never skips those (ADR §5), so it still answers
503.

Every log line carries a fixed `reason` code, plus the HTTP `status` where
there is one. The codes are `missing_variable`, `bad_url`, `network_error`,
`http_status`, `too_large`, `bad_json`, `groups_missing`, `groups_not_array`,
`too_many_groups`, `not_an_object`, `kv_read_error`, `kv_write_error`,
`kv_delete_error`, `missing_credentials` and `username_contains_colon`.
Log lines never contain the URL (which carries the sub), a response body or
the credentials.

## Security notes

- **URL templates:** the only value is the **verified** `sub` of the draft or
  identity, never anything from the request, and never the email (which an
  IdP may not have verified). It is encoded with `encodeURIComponent`. The expanded URL must keep the configured origin and
  its path must still be canonical. A `sub` of `.` or `..` would otherwise
  collapse a path segment, so it fails the lookup.
- **Profile fields:** only allowlisted top-level scalars are kept: strings,
  finite numbers and booleans. Objects, arrays and `null` are dropped, and so
  is every other field.
- **Header values:** control characters, including CR and LF, are removed.
  A value that contains non-ASCII characters or `%` is percent-encoded with
  `encodeURIComponent`, so `decodeURIComponent(value)` at the origin always
  gives back the original. The value is then truncated at a character
  boundary to 1024 characters, and an empty value is not sent.
- **Inbound headers:** the kernel strips `x-user-*` from every inbound
  request. If one of these headers reaches the origin, the gate set it.
- **Third-party upstreams:** the manifest sets `identityHeaders: true`, so the
  kernel withholds `x-user-*` from a rule's `upstream` unless that rule sets
  `forward_identity: true`.
- **Fetches:** they go through `ctx.fetch`, which is budgeted and
  egress-checked. The cache mode stays `pass`; the function's fetch cache is
  never used.

## Platform profiles

| | provisioned | sandbox |
|---|---|---|
| Profile cache | KV key `profile:` + hex SHA-256(`sub`), with TTL `cache_ttl_seconds` and namespace `plugin:user-info:` | none: every profile lookup fetches |
| KV read error | logged as `kv_read_error`, then a live fetch | n/a |
| KV write error | logged as `kv_write_error`, not fatal | n/a |
| Login cache warm-up | when `profile_endpoint` equals `endpoint`, the login response also fills the profile cache | none |
| Secrets | SecretStore `secrets` bundle | embedded |

On sandbox the plugin never uses KV, even when local development binds a KV
store.

### Profile data at rest

The cached profile is PII stored in KV. It lives at most
`cache_ttl_seconds` (default 300 s) after it was written, and less in these
cases:

- **Logout** (`onLogout`) deletes the subject's entry.
- **Login** re-writes it from the login response when `profile_endpoint`
  equals `endpoint` (and `profile_fields` is non-empty); otherwise, including a
  degraded login, it deletes any entry left by an earlier session, so a fresh
  login never serves an old profile.

A session that simply expires (no logout) leaves its entry until the KV TTL
runs out. Keep `cache_ttl_seconds` short. Delete errors are logged
(`kv_delete_error`) and never fail a login or logout.

Each cache entry records a fingerprint of `profile_endpoint` and
`profile_fields`. An entry written for different options is treated as a
miss.

Within one request, each distinct profile lookup (same `profile_endpoint`
and `profile_fields`) is fetched at most once; `beforeForward` and `handle`
share it. `maxFetches` is 2, so a global ref and a rule ref with *different*
profile options can each fetch once on the same request. There is still one
KV entry per subject: the second lookup sees a fingerprint mismatch, treats
it as a miss and overwrites the entry. A third distinct lookup on one request
fails with `503 budget_exceeded`.

## Files

- `index.js`: the manifest and its hooks (`onLogin`, `onLogout`, `beforeForward`, `handle`).
- `lib/options.js`: `validate()`, template parsing and `egress(options)`.
- `lib/backend.js`: template expansion, the Basic header, the bounded JSON
  GET and the dot-path reader.
- `lib/profile.js`: the allowlist, the KV cache (write, read, delete), the
  per-request memo and the header sanitizer.
- `test/`: unit tests on `src/sdk/testing.js`. The end-to-end tests through
  the kernel are in `test/user-info-gate.test.js`.
