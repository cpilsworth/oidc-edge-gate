import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Layer 1 of the test strategy (worker-gate-parity-plan.md §5): plain node-vitest.
// The edge-gate source imports Fastly platform modules; we cannot run them under
// node, so the four `fastly:*` specifiers are aliased to in-memory stubs. Web
// Crypto, fetch, TextEncoder etc. come from Node 18+ natively. Layers 2 (Viceroy
// `fastly compute serve`) and 3 (hosted OIDF) are out of scope here.
const stub = (p) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.js"],
  },
  resolve: {
    alias: {
      "fastly:config-store": stub("./test/stubs/config-store.js"),
      "fastly:secret-store": stub("./test/stubs/secret-store.js"),
      "fastly:kv-store": stub("./test/stubs/kv-store.js"),
      "fastly:cache-override": stub("./test/stubs/cache-override.js"),
    },
  },
});
