# ScriptSentinel for VS Code

ScriptSentinel helps author and review a JSON policy describing the capabilities
intended for third-party JavaScript integrations.

## Features

- **Policy Explorer** lists each configured script and summarizes its access rules.
- **Create Policy** scaffolds a `scriptsentinel.json` file in the first workspace folder.
- **Audit Policy** reports malformed rules, broad network access, and selected sensitive grants.
- The contributed JSON Schema provides editor validation and completion for the policy format.

Open the ScriptSentinel view in the Explorer, or run **ScriptSentinel: Create Policy**
from the Command Palette. Add script rules, then run **ScriptSentinel: Audit Policy**.

The initial extension is a policy authoring and review tool. It does **not** isolate,
intercept, or enforce third-party JavaScript at runtime, and its audit is not a PCI DSS
compliance certification. Runtime enforcement requires a separately designed and
security-reviewed browser-side capability boundary.

## Runtime boundary demo

The [`demo/`](./demo/) folder contains a local, browser-based prototype of an opaque-origin
`sandbox="allow-scripts"` iframe and a narrow `postMessage` capability broker. Start a
static server from the repository root, for example:

```sh
npx --yes http-server . -p 8080
```

Then open `http://localhost:8080/demo/`. Try the mock cookie capability, trusted and
untrusted network requests, direct iframe egress, parent DOM access, and iframe reload.
The host broker only simulates the allowlisted network response; it does not fetch the
requested URL or read host cookies. The iframe CSP separately blocks direct connections.
Lifecycle events and heartbeat timeouts are logged as possible reload/unresponsive signals,
not as definitive evidence of a browser-process crash.

This prototype demonstrates a boundary for a cooperating, purpose-built widget; it does
not transparently sandbox arbitrary existing third-party scripts or replace browser-level
security testing.

## Development

```sh
npm install
npm test
```

Press `F5` in VS Code to launch an Extension Development Host.

## Policy shape

See `resources/scriptsentinel.schema.json` for the supported fields. For example:

```json
{
  "applicationId": "enterprise-checkout-service",
  "version": "1.0.0",
  "globalSettings": {
    "antiPrototypePollution": true,
    "iframeBypassProtection": true
  },
  "scripts": [
    {
      "identifier": "third-party-analytics",
      "sourceMatch": "https://analytics-provider.com",
      "permissions": {
        "document": {
          "cookie": {
            "allow": false,
            "fallbackMode": "mock",
            "mockValue": "session_id=REDACTED_BY_SCRIPTSENTINEL"
          }
        },
        "network": {
          "allowedOrigins": [
            "https://trusted-analytics.com"
          ],
          "fallbackMode": "drop-with-403"
        }
      }
    }
  ]
}
```

## Upstream references

- [LavaMoat](https://github.com/LavaMoat/LavaMoat) focuses on sandboxing dependency graphs.
- [Harden-Runner](https://github.com/step-security/harden-runner) instruments GitHub Actions runners.
- [js-eyes](https://github.com/imjszhang/js-eyes) is a local-first browser automation stack with a consent gateway for sensitive AI-agent tool actions; its [security notes](https://github.com/imjszhang/js-eyes/blob/main/SECURITY.md) describe that trust boundary.
- [Human Security's MCP server](https://github.com/HumanSecurity/human-mcp-server) is a reference for exposing security information through MCP.

These are reference projects, not imported runtime dependencies. Their security
boundaries differ from ScriptSentinel's proposed per-script browser enforcement;
the VS Code extension currently authors and reviews policy only.
