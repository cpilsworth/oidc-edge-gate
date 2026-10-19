// Build-time probe access token.
//
// COMMITTED AS A PLACEHOLDER. Inject the real value at build time from an env
// var (see README "Inject the token"), build, then restore this file with
// `git checkout -- tools/platform-probe/src/token.js`. Never commit a real token.
// While the placeholder is in place every /__probe/ route answers 404.
export const PROBE_TOKEN = "REPLACE_WITH_PROBE_TOKEN";
