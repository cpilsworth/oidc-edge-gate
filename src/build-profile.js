// Build-time platform pin (W1.F, F5). Spec: docs/architecture/plugins.md §11.
//
// detectPlatform() picks the profile from whether ConfigStore("config_default")
// opens. Without a pin, a provisioned build whose ConfigStore fails to open
// would silently DOWNGRADE to the sandbox profile and run on the embedded
// (sandbox) config and secrets. A pinned build fails closed instead: when the
// detected profile differs from this constant, config load throws and every
// request gets a generic 500.
//
//   null           no pin (today's sandbox POC builds; detection decides)
//   "provisioned"  a provisioned build SETS this, so a missing ConfigStore is
//                  an error rather than a fallback to embedded values
//   "sandbox"      a sandbox build MAY set this, so unexpectedly present stores
//                  are an error too
//
// Runs on the Fastly Compute runtime: no Node-only APIs.

/** @type {null | "provisioned" | "sandbox"} */
export const EXPECTED_PLATFORM_PROFILE = null;
