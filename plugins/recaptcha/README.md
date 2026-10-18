# recaptcha

Middleware plugin that requires a verified Google reCAPTCHA token on matching
requests (by default **POST only**) before they are forwarded.

| | |
|---|---|
| Kind | `middleware`, phase `beforeForward` (after authentication — decision D6) |
| Trusted header prefix | `x-recaptcha-` (stripped from every inbound request by the kernel) |
| Egress | `https://www.google.com` (siteverify), `maxFetches: 1` |
| Secrets | `recaptcha_secret` |
| Defaults | `when: { methods: ["POST"] }`, `on_error: "fail"` |

## Behaviour

1. No `recaptcha_secret` provisioned → logged as a misconfiguration and the
   request ends with **500** `{"error":"internal_error"}` (fail closed).
2. The body is buffered as bytes; the `g-recaptcha-response` field is read
   from an `application/x-www-form-urlencoded` or `multipart/form-data` body.
3. The token is verified with Google's siteverify through `ctx.fetch`
   (budgeted, egress-checked, cache `pass`). A missing token is rejected
   without calling Google.
4. It passes when `success` is true and, for v3 keys, `score >= min_score`.
   v2 responses carry no score, so the threshold is a no-op for them.
5. Failure → **400** `{"error":"recaptcha_failed"}`. Success → the buffered
   body is re-attached with `ctx.replaceRequest` and Google's result is
   forwarded as `x-recaptcha-score`, `x-recaptcha-hostname` and
   `x-recaptcha-challenge-ts` (only the fields Google returned).

Because it runs after authentication, an anonymous POST to a **protected**
rule is sent to log in (302) first and never costs a siteverify call; a
session never exempts a request from the check. On a **public** rule there is
no authentication, so it behaves exactly as before.

## Options

| Option | Type | Default |
|---|---|---|
| `min_score` | number `0..1` | the gate-wide `recaptcha_min_score` config key (`ctx.config.recaptchaMinScore`, built-in default `0.5`; an explicit empty value means no threshold) |

## Policy

```jsonc
// v2
{ "path": "/form/*", "tier": "public",
  "middleware": [ { "use": "recaptcha", "options": { "min_score": 0.7 } } ] }

// legacy shape (upgraded by the policy compiler with a warning)
{ "path": "/form/*", "tier": "public", "recaptcha": true }
```

## Files

- `index.js` — the manifest and the `beforeForward` hook.
- `lib/siteverify.js` — token extraction, siteverify call, pass/fail rule and
  result headers (pure functions; the fetch is passed in).
- `test/` — unit tests built on `src/sdk/testing.js`.
