"use strict";

(() => {
  const frame = document.getElementById("sandbox");
  const log = document.getElementById("audit-log");
  const frameState = document.getElementById("frame-state");
  const policyState = document.getElementById("policy-state");
  const heartbeatTimeoutMs = 5000;
  let broker;
  let heartbeatTimer;
  let frameLoads = 0;
  let lastHeartbeat = 0;

  function appendAudit(event) {
    const item = document.createElement("li");
    item.className = `audit-${event.status.toLowerCase()}`;
    const time = new Date(event.timestamp).toLocaleTimeString();
    item.textContent = `${time}  ${event.status}  ${event.action} → ${event.target} — ${event.detail}`;
    log.prepend(item);
    while (log.children.length > 60) {
      log.lastElementChild.remove();
    }
    console.info("[ScriptSentinel demo]", event);
  }

  function audit(action, target, status, detail) {
    appendAudit({
      timestamp: new Date().toISOString(),
      script: "untrusted-demo-widget",
      action,
      target,
      status,
      detail
    });
  }

  function sendResponse(source, response) {
    if (source && response) {
      source.postMessage(response, "*");
    }
  }

  function updateFrameState(state, description) {
    frameState.textContent = state;
    frameState.title = description;
    frameState.className = `pill ${state === "Running" ? "pill-good" : "pill-warn"}`;
  }

  function onMessage(event) {
    if (!broker || !frame.contentWindow) {
      return;
    }
    if (event.source !== frame.contentWindow || event.origin !== "null") {
      return;
    }
    const response = broker.handleMessage(event, frame.contentWindow);
    if (event.data && event.data.type === "FRAME_HEARTBEAT" && response && response.success) {
      lastHeartbeat = Date.now();
      updateFrameState("Running", "Sandbox heartbeat received.");
    } else if (event.data && event.data.type === "FRAME_READY") {
      lastHeartbeat = Date.now();
      updateFrameState("Running", "Sandbox ready message received.");
    }
    sendResponse(event.source, response);
  }

  function checkHeartbeat() {
    if (!broker || !lastHeartbeat || Date.now() - lastHeartbeat <= heartbeatTimeoutMs) {
      return;
    }
    lastHeartbeat = 0;
    updateFrameState("Unresponsive", "No heartbeat received. This may indicate a reload, navigation, or unresponsive frame; it is not proof of a crash.");
    audit("FRAME_HEARTBEAT_TIMEOUT", "sandbox.html", "DENIED", "No heartbeat; possible reload, navigation, or unresponsive frame, not confirmed crash.");
  }

  window.addEventListener("message", onMessage);
  frame.addEventListener("load", () => {
    frameLoads += 1;
    if (frameLoads > 1) {
      audit("FRAME_LOAD", "sandbox.html", "DENIED", `Frame loaded again (load ${frameLoads}); reload/navigation detected, not necessarily a crash.`);
    } else {
      audit("FRAME_LOAD", "sandbox.html", "ALLOWED", "Initial sandbox document loaded.");
    }
    lastHeartbeat = 0;
    updateFrameState("Loading", "Waiting for a sandbox ready message.");
  });
  frame.addEventListener("error", () => {
    updateFrameState("Error", "The browser reported an iframe load error.");
    audit("FRAME_LOAD_ERROR", "sandbox.html", "DENIED", "Browser reported an iframe load error.");
  });
  window.addEventListener("beforeunload", () => clearInterval(heartbeatTimer));

  fetch("./scriptsentinel.json", { cache: "no-store" })
    .then(response => {
      if (!response.ok) {
        throw new Error(`Policy request failed with HTTP ${response.status}.`);
      }
      return response.json();
    })
    .then(policy => {
      broker = ScriptSentinelBroker.createCapabilityBroker(policy, appendAudit);
      policyState.textContent = "Policy loaded";
      policyState.className = "pill pill-good";
      heartbeatTimer = setInterval(checkHeartbeat, 1000);
    })
    .catch(error => {
      policyState.textContent = "Policy error";
      policyState.className = "pill pill-warn";
      updateFrameState("Unavailable", "The policy could not be loaded or is invalid.");
      audit("POLICY_ERROR", "scriptsentinel.json", "DENIED", error.message);
    });
})();
