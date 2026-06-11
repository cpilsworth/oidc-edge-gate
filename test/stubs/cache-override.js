// No-op stand-in for `fastly:cache-override`. The real class controls Fastly's
// own cache behaviour for an origin fetch; under node there is no such cache, so
// constructing it is harmless. src/origin.js only passes the instance through to
// fetch(), and node's fetch ignores the unknown `cacheOverride` option.
export class CacheOverride {
  constructor(mode) {
    this.mode = mode;
  }
}
