// Stand-in for `fastly:cache-override`. The real class controls Fastly's own
// cache behaviour for a backend fetch; under node there is no such cache, and
// node's fetch ignores the unknown `cacheOverride` option.
//
// It models BOTH constructor forms of @fastly/js-compute (>= 3.30), so tests can
// tell them apart:
//   new CacheOverride("pass")                 -> mode "pass"
//   new CacheOverride("override", { ttl })    -> mode "override", ttl
//   new CacheOverride({ ttl, ... })           -> mode "override" (an init object
//                                                as the first argument ALWAYS
//                                                means "override"; a `mode` key
//                                                inside it is ignored)
// so `new CacheOverride({ mode: "pass" })` is NOT a pass. Unknown mode strings
// throw, like the runtime.
const MODES = new Set(["none", "pass", "override"]);
const INIT_KEYS = ["ttl", "swr", "surrogateKey", "pci", "beforeSend", "afterSend"];

export class CacheOverride {
  constructor(modeOrInit, init) {
    let mode;
    let opts;
    if (modeOrInit !== null && typeof modeOrInit === "object") {
      mode = "override";
      opts = modeOrInit;
    } else {
      if (!MODES.has(modeOrInit)) throw new TypeError(`CacheOverride: invalid mode ${JSON.stringify(modeOrInit)}`);
      mode = modeOrInit;
      opts = init || {};
    }
    this.mode = mode;
    for (const key of INIT_KEYS) {
      if (opts[key] !== undefined) this[key] = opts[key];
    }
  }
}
