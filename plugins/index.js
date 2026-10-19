// The static plugin list (docs/architecture/plugins.md §3). The Wasm bundle
// cannot load code dynamically, so every plugin is registered here at build
// time; the policy decides which ones are active. Registry order is the order
// lifecycle hooks (onLogin/onLogout) run in.
//
// Every folder in plugins/ except _template must be listed here
// (enforced by test/plugin-boundaries.test.js).

import oidcAuth from "./oidc-auth/index.js";
import recaptcha from "./recaptcha/index.js";
import userInfo from "./user-info/index.js";

export default [oidcAuth, recaptcha, userInfo];
