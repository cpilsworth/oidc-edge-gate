// Request-path normalization, run before classification (src/index.js).
//
// The WHATWG URL parser preserves percent-encoding and duplicate slashes, so a
// raw `url.pathname` like `//protected/secret` or `/%70rotected/secret` would not
// match a `/protected/*` policy rule — yet the EDS origin may collapse `//`→`/`
// or decode `%70`→`p` and serve the protected content. We close that gap by
// classifying *and forwarding* a single normalized path, so the gate and the
// origin always agree on what was requested.

const ENCODED_SEPARATOR = /%2f|%5c/i; // encoded "/" or "\"

/**
 * Normalize a raw URL pathname: reject smuggled separators, percent-decode, and
 * collapse repeated slashes. Throws on a malformed escape or an encoded `/`/`\`
 * (the caller turns the throw into a 400) so an attacker can't reintroduce a
 * structural separator after classification.
 * @param {string} rawPathname  e.g. url.pathname
 * @returns {string} the normalized pathname
 */
export function normalizePathname(rawPathname) {
  // Must check BEFORE decoding: once decoded, an encoded separator is
  // indistinguishable from a structural one.
  if (ENCODED_SEPARATOR.test(rawPathname)) {
    throw new Error("encoded path separator");
  }
  const decoded = decodeURIComponent(rawPathname); // throws on malformed escape
  return decoded.replace(/\/{2,}/g, "/");
}
