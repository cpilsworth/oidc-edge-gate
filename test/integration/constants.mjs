// Shared constants for the Viceroy integration smoke (plan §5 Layer 2).
// These MUST stay in sync with test/integration/oidc_config.json and
// fastly.integration.toml (ports + issuer + client_id + redirect_uri + hmac).

export const OP_PORT = 7681;
export const ORIGIN_PORT = 7682;
export const GATE_PORT = 7676;

export const OP_BASE = `http://127.0.0.1:${OP_PORT}`;
export const GATE_BASE = `http://127.0.0.1:${GATE_PORT}`;

export const ISSUER = OP_BASE;
export const CLIENT_ID = "integration-client";
export const CLIENT_SECRET = "integration-secret";
export const REDIRECT_URI = `${GATE_BASE}/.auth/callback`;
export const HMAC_KEY = "integration-hmac-key-at-least-32-bytes-long!!";

// Identity the mock OP mints into every id_token.
export const SUB = "user-123";
export const EMAIL = "user@example.com";
export const NAME = "Integration User";
export const GROUPS = ["medical"]; // matches the /protected/medical/* audience rule
