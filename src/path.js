// Request-path normalization, run before classification (src/index.js).
//
// The WHATWG URL parser preserves percent-encoding, duplicate slashes and `..`
// segments, so a raw `url.pathname` like `//protected/secret`,
// `/%70rotected/secret` or `/public/../protected/secret` would not match a
// `/protected/*` policy rule — yet the EDS origin may collapse `//`→`/`,
// decode `%70`→`p` or resolve `..`→`/protected` and serve the protected
// content. We close that gap by classifying *and forwarding* a single
// normalized path, so the gate and the origin always agree on what was
// requested.

const ENCODED_SEPARATOR = /%2f|%5c/i; // encoded "/" or "\"

/**
 * Normalize a raw URL pathname: reject smuggled separators, percent-decode,
 * collapse repeated slashes, and resolve `.` / `..` segments (rejecting any
 * `..` that would escape above the root). Throws on a malformed escape, an
 * encoded `/`/`\`, or an escaping `..` (the caller turns the throw into a 400)
 * so an attacker can't reintroduce a structural separator after classification
 * or traverse into a path the gate never classified.
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
  const collapsed = decoded.replace(/\/{2,}/g, "/");
  return resolveSegments(collapsed);
}

// Walk the decoded, slash-collapsed path segment-by-segment, dropping `.` and
// popping on `..`. A `..` that would pop above the root escapes the classified
// namespace, so reject it. A trailing slash on a non-root path is preserved so
// the origin still sees the same shape it would have.
function resolveSegments(path) {
  const segments = path.split("/");
  const out = [];
  for (const seg of segments) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (out.length === 0) throw new Error("path escapes root");
      out.pop();
      continue;
    }
    out.push(seg);
  }
  const trailing = path.endsWith("/") && path !== "/" ? "/" : "";
  const joined = out.join("/");
  if (joined === "") return "/";
  return "/" + joined + trailing;
}
