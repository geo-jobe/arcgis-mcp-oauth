import assert from "node:assert/strict";
import test from "node:test";

import { extractBearer, resolveSession, resourceUri, settingsFromEnvironment } from "./server.js";

test("extractBearer accepts a case-insensitive Bearer scheme", () => {
  assert.equal(extractBearer("bEaReR mcp-token-example"), "mcp-token-example");
});

test("extractBearer rejects missing and malformed authorization", () => {
  assert.equal(extractBearer(undefined), undefined);
  assert.equal(extractBearer("Basic credentials"), undefined);
  assert.equal(extractBearer("Bearer"), undefined);
});

test("settingsFromEnvironment requires the internal API key", () => {
  assert.throws(() => settingsFromEnvironment({}), /INTERNAL_API_KEY must be set/);
});

test("resourceUri derives the exact protected MCP endpoint", () => {
  assert.equal(
    resourceUri({
      authServiceUrl: "https://auth.example.com",
      internalApiKey: "secret",
      publicBaseUrl: "https://mcp.example.com",
    }),
    "https://mcp.example.com/mcp",
  );
});

test("resolveSession sends and verifies the resource audience", async () => {
  const settings = {
    authServiceUrl: "https://auth.example.com",
    internalApiKey: "secret",
    publicBaseUrl: "https://mcp.example.com",
  };
  const originalFetch = globalThis.fetch;
  let requestedResource: string | null = null;
  globalThis.fetch = async (_input, init) => {
    requestedResource = new Headers(init?.headers).get("X-MCP-Resource");
    return Response.json({
      active: true,
      resource: "https://other.example.com/mcp",
      arcgis_token: { access_token: "arcgis-token" },
      portal: { portal_url: "https://portal.example.com", api_root: "https://portal.example.com/sharing/rest" },
    });
  };

  try {
    assert.equal(await resolveSession(settings, "mcp-token"), undefined);
    assert.equal(requestedResource, "https://mcp.example.com/mcp");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
