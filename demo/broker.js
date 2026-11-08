(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.ScriptSentinelBroker = api;
  }
})(globalThis, function () {
  "use strict";

  const MAX_ID_LENGTH = 100;
  const MAX_TEXT_LENGTH = 200;

  function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
  }

  function createCapabilityBroker(policy, onAudit) {
    if (!isRecord(policy) || !Array.isArray(policy.scripts) || policy.scripts.length !== 1) {
      throw new TypeError("Demo policy must define exactly one script.");
    }

    const script = policy.scripts[0];
    const permissions = script && script.permissions;
    const cookie = permissions && permissions.document && permissions.document.cookie;
    const network = permissions && permissions.network;
    if (!isRecord(cookie) || cookie.allow !== false ||
        cookie.fallbackMode !== "mock" || typeof cookie.mockValue !== "string") {
      throw new TypeError("Demo policy must deny cookie access and define a string mock value.");
    }
    if (!isRecord(network) || !Array.isArray(network.allowedOrigins) ||
        network.fallbackMode !== "drop-with-403" ||
        network.allowedOrigins.some(origin => typeof origin !== "string" || !isHttpsOrigin(origin))) {
      throw new TypeError("Demo policy must define explicit HTTPS network origins.");
    }

    const scriptId = typeof script.identifier === "string" ? script.identifier : "unknown-script";

    function audit(action, target, status, detail) {
      onAudit({
        timestamp: new Date().toISOString(),
        script: scriptId,
        action,
        target,
        status,
        detail: String(detail).slice(0, MAX_TEXT_LENGTH)
      });
    }

    function handleMessage(event, expectedSource) {
      if (!event || event.source !== expectedSource || event.origin !== "null") {
        return null;
      }

      const message = event.data;
      if (!isRecord(message) || typeof message.type !== "string" ||
          typeof message.id !== "string" || message.id.length === 0 ||
          message.id.length > MAX_ID_LENGTH) {
        audit("PROTOCOL", "message", "DENIED", "Malformed broker request.");
        return null;
      }

      switch (message.type) {
        case "READ_COOKIE":
          audit("COOKIE_READ", "document.cookie", "DENIED", "Returned policy mock; host cookies were not accessed.");
          return { id: message.id, success: true, value: cookie.mockValue };

        case "NETWORK_FETCH":
          return handleNetworkRequest(message, network, audit);

        case "FRAME_READY":
          audit("FRAME_READY", "sandbox.html", "ALLOWED", "Sandbox frame initialized.");
          return { id: message.id, success: true, value: "ready" };

        case "FRAME_HEARTBEAT":
          return { id: message.id, success: true, value: "alive" };

        case "FRAME_PAGEHIDE":
          audit("FRAME_PAGEHIDE", "sandbox.html", "ALLOWED", "Sandbox document is unloading or entering the back-forward cache.");
          return null;

        case "FRAME_ERROR":
          audit("FRAME_ERROR", "sandbox.html", "DENIED", safeText(message.payload && message.payload.message, "Uncaught frame error."));
          return null;

        case "FRAME_UNHANDLED_REJECTION":
          audit("FRAME_UNHANDLED_REJECTION", "sandbox.html", "DENIED", safeText(message.payload && message.payload.message, "Unhandled frame promise rejection."));
          return null;

        case "CSP_VIOLATION":
          audit(
            "CSP_VIOLATION",
            safeText(message.payload && message.payload.directive, "unknown-directive"),
            "DENIED",
            safeText(message.payload && message.payload.blockedURI, "Blocked by the sandbox content policy.")
          );
          return null;

        default:
          audit("PROTOCOL", message.type.slice(0, MAX_TEXT_LENGTH), "DENIED", "Unsupported broker message.");
          return { id: message.id, success: false, error: "Unsupported broker request." };
      }
    }

    return { handleMessage };
  }

  function handleNetworkRequest(message, network, audit) {
    const payload = message.payload;
    if (!isRecord(payload) || typeof payload.url !== "string" ||
        typeof payload.method !== "string" || payload.method.toUpperCase() !== "GET") {
      audit("NETWORK_FETCH", "invalid-request", "DENIED", "Only a well-formed GET request is accepted.");
      return { id: message.id, success: false, error: "Only GET requests are supported by this demo." };
    }

    let url;
    try {
      url = new URL(payload.url);
    } catch {
      audit("NETWORK_FETCH", "invalid-url", "DENIED", "Request URL must be absolute.");
      return { id: message.id, success: false, error: "Request URL must be absolute." };
    }

    if (url.protocol !== "https:" || !network.allowedOrigins.includes(url.origin)) {
      audit("NETWORK_FETCH", url.origin, "DENIED", "Origin is not in the policy allowlist.");
      return { id: message.id, success: false, error: "403 Forbidden by ScriptSentinel policy." };
    }

    audit("NETWORK_FETCH", url.origin, "ALLOWED", "Returned a simulated response; no outbound request was made.");
    return {
      id: message.id,
      success: true,
      value: {
        status: 200,
        simulated: true,
        origin: url.origin,
        message: "This demo response was generated by the broker. No network request was sent."
      }
    };
  }

  function isHttpsOrigin(value) {
    try {
      const url = new URL(value);
      return url.protocol === "https:" && url.origin === value;
    } catch {
      return false;
    }
  }

  function safeText(value, fallback) {
    return typeof value === "string" ? value.slice(0, MAX_TEXT_LENGTH) : fallback;
  }

  return { createCapabilityBroker };
});
