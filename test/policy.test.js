const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { validatePolicy } = require("../out/src/policy.js");

const validPolicy = {
  applicationId: "checkout",
  version: "1.0.0",
  globalSettings: {
    antiPrototypePollution: true,
    iframeBypassProtection: true
  },
  scripts: [
    {
      identifier: "analytics",
      sourceMatch: "https://analytics.example",
      permissions: {
        document: {
          cookie: {
            allow: false,
            fallbackMode: "mock",
            mockValue: "session_id=REDACTED"
          }
        },
        network: {
          allowedOrigins: ["https://trusted.example"],
          fallbackMode: "drop-with-403"
        }
      }
    }
  ]
};

test("accepts a least-privilege policy without findings", () => {
  assert.deepEqual(validatePolicy(JSON.stringify(validPolicy)), []);
});

test("reports invalid JSON as an error", () => {
  const [finding] = validatePolicy("{");
  assert.equal(finding.severity, "error");
  assert.match(finding.message, /^Invalid JSON:/);
});

test("rejects wildcard network origins and warns on sensitive access", () => {
  const policy = structuredClone(validPolicy);
  policy.scripts[0].permissions.network.allowedOrigins = ["*"];
  policy.scripts[0].permissions.document.cookie = { allow: true };

  const findings = validatePolicy(JSON.stringify(policy));
  assert.ok(findings.some(finding => finding.severity === "error" && finding.message.includes("wildcards")));
  assert.ok(findings.some(finding => finding.severity === "warning" && finding.message.includes("document.cookie")));
});

test("flags duplicate script identifiers", () => {
  const policy = structuredClone(validPolicy);
  policy.scripts.push(structuredClone(policy.scripts[0]));

  const findings = validatePolicy(JSON.stringify(policy));
  assert.ok(findings.some(finding => finding.message.includes("Duplicate script identifier")));
});

test("keeps the schema parseable JSON", () => {
  const schemaPath = path.join(__dirname, "..", "resources", "scriptsentinel.schema.json");
  assert.equal(typeof JSON.parse(readFileSync(schemaPath, "utf8")), "object");
});

test("points the extension manifest at the compiled entry point", () => {
  const packagePath = path.join(__dirname, "..", "package.json");
  const packageJson = JSON.parse(readFileSync(packagePath, "utf8"));
  assert.equal(require("node:fs").existsSync(path.join(__dirname, "..", packageJson.main)), true);
});
