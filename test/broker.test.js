const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { createCapabilityBroker } = require("../demo/broker.js");

const policy = JSON.parse(readFileSync(path.join(__dirname, "..", "demo", "scriptsentinel.json"), "utf8"));
const frame = {};
const auditEvents = [];
const broker = createCapabilityBroker(policy, event => auditEvents.push(event));

function message(type, payload = null, id = "test-request") {
  return { source: frame, origin: "null", data: { id, type, payload } };
}

test("returns only the configured cookie mock", () => {
  const response = broker.handleMessage(message("READ_COOKIE"), frame);
  assert.deepEqual(response, {
    id: "test-request",
    success: true,
    value: "session_id=REDACTED_BY_SCRIPTSENTINEL"
  });
  assert.match(auditEvents.at(-1).detail, /host cookies were not accessed/);
});

test("simulates allowlisted HTTPS requests without making a network request", () => {
  const response = broker.handleMessage(message("NETWORK_FETCH", {
    url: "https://trusted-analytics.example/collect",
    method: "GET"
  }), frame);
  assert.equal(response.success, true);
  assert.equal(response.value.simulated, true);
  assert.match(auditEvents.at(-1).detail, /no outbound request was made/);
});

test("denies untrusted origins, non-HTTPS URLs, and non-GET methods", () => {
  const untrusted = broker.handleMessage(message("NETWORK_FETCH", {
    url: "https://attacker.example/exfiltrate",
    method: "GET"
  }), frame);
  const insecure = broker.handleMessage(message("NETWORK_FETCH", {
    url: "http://trusted-analytics.example/collect",
    method: "GET"
  }), frame);
  const post = broker.handleMessage(message("NETWORK_FETCH", {
    url: "https://trusted-analytics.example/collect",
    method: "POST"
  }), frame);

  assert.equal(untrusted.success, false);
  assert.equal(insecure.success, false);
  assert.equal(post.success, false);
});

test("ignores messages from other frames and non-opaque origins", () => {
  assert.equal(broker.handleMessage({ ...message("READ_COOKIE"), source: {} }, frame), null);
  assert.equal(broker.handleMessage({ ...message("READ_COOKIE"), origin: "https://example.com" }, frame), null);
});

test("rejects malformed or oversized request identifiers", () => {
  assert.equal(broker.handleMessage({ source: frame, origin: "null", data: [] }, frame), null);
  assert.equal(broker.handleMessage(message("READ_COOKIE", null, "x".repeat(101)), frame), null);
  assert.ok(auditEvents.some(event => event.action === "PROTOCOL" && event.status === "DENIED"));
});

test("fails closed when policy grants host cookie access", () => {
  const unsafePolicy = structuredClone(policy);
  unsafePolicy.scripts[0].permissions.document.cookie.allow = true;
  assert.throws(() => createCapabilityBroker(unsafePolicy, () => {}), /must deny cookie access/);
});

test("sandbox configuration omits same-origin and denies direct egress", () => {
  const index = readFileSync(path.join(__dirname, "..", "demo", "index.html"), "utf8");
  const sandbox = readFileSync(path.join(__dirname, "..", "demo", "sandbox.html"), "utf8");
  assert.match(index, /sandbox="allow-scripts"/);
  assert.doesNotMatch(index, /sandbox="[^"]*allow-same-origin/);
  assert.match(sandbox, /connect-src 'none'/);
  assert.match(sandbox, /default-src 'none'/);
});
