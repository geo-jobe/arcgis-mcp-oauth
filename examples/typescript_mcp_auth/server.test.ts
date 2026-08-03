import assert from "node:assert/strict";
import test from "node:test";

import { extractBearer, settingsFromEnvironment } from "./server.js";

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
