export type FindingSeverity = "error" | "warning";

export interface PolicyFinding {
  severity: FindingSeverity;
  message: string;
  path: string[];
}

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function addFinding(
  findings: PolicyFinding[],
  severity: FindingSeverity,
  message: string,
  path: string[]
): void {
  findings.push({ severity, message, path });
}

function validateAccessRule(
  rule: unknown,
  path: string[],
  findings: PolicyFinding[]
): void {
  if (!isRecord(rule) || typeof rule.allow !== "boolean") {
    addFinding(findings, "error", "Expected an access rule with a boolean allow field.", path);
    return;
  }

  if (!rule.allow && typeof rule.fallbackMode !== "string") {
    addFinding(findings, "error", "Denied access must define a fallbackMode.", [...path, "fallbackMode"]);
  }

  if (rule.fallbackMode === "mock" && typeof rule.mockValue !== "string") {
    addFinding(findings, "error", "Mock fallback must define a string mockValue.", [...path, "mockValue"]);
  }
}

export function validatePolicy(text: string): PolicyFinding[] {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Unknown JSON parse error.";
    return [{ severity: "error", message: `Invalid JSON: ${detail}`, path: [] }];
  }

  const findings: PolicyFinding[] = [];
  if (!isRecord(value)) {
    return [{ severity: "error", message: "Policy must be a JSON object.", path: [] }];
  }

  if (typeof value.applicationId !== "string" || value.applicationId.trim() === "") {
    addFinding(findings, "error", "applicationId must be a non-empty string.", ["applicationId"]);
  }
  if (typeof value.version !== "string" || !/^\d+\.\d+\.\d+$/.test(value.version)) {
    addFinding(findings, "error", "version must use the numeric x.y.z format.", ["version"]);
  }

  if (!isRecord(value.globalSettings)) {
    addFinding(findings, "error", "globalSettings must be an object.", ["globalSettings"]);
  } else {
    for (const setting of ["antiPrototypePollution", "iframeBypassProtection"]) {
      if (typeof value.globalSettings[setting] !== "boolean") {
        addFinding(findings, "error", `${setting} must be a boolean.`, ["globalSettings", setting]);
      } else if (value.globalSettings[setting] === false) {
        addFinding(findings, "warning", `${setting} is disabled.`, ["globalSettings", setting]);
      }
    }
  }

  if (!Array.isArray(value.scripts)) {
    addFinding(findings, "error", "scripts must be an array.", ["scripts"]);
    return findings;
  }

  const identifiers = new Set<string>();
  value.scripts.forEach((script: unknown, index: number) => {
    const path = ["scripts", String(index)];
    if (!isRecord(script)) {
      addFinding(findings, "error", "Each script entry must be an object.", path);
      return;
    }

    if (typeof script.identifier !== "string" || script.identifier.trim() === "") {
      addFinding(findings, "error", "identifier must be a non-empty string.", [...path, "identifier"]);
    } else if (identifiers.has(script.identifier)) {
      addFinding(findings, "error", `Duplicate script identifier "${script.identifier}".`, [...path, "identifier"]);
    } else {
      identifiers.add(script.identifier);
    }

    if (typeof script.sourceMatch !== "string" || script.sourceMatch.trim() === "") {
      addFinding(findings, "error", "sourceMatch must be a non-empty string.", [...path, "sourceMatch"]);
    }

    if (!isRecord(script.permissions)) {
      addFinding(findings, "error", "permissions must be an object.", [...path, "permissions"]);
      return;
    }

    const permissions = script.permissions;
    if (isRecord(permissions.document)) {
      for (const resource of ["cookie", "innerHTML"]) {
        const rule = permissions.document[resource];
        if (rule === undefined) {
          continue;
        }
        const rulePath = [...path, "permissions", "document", resource];
        validateAccessRule(rule, rulePath, findings);
        if (isRecord(rule) && rule.allow === true) {
          addFinding(findings, "warning", `Third-party access to document.${resource} is allowed.`, [...rulePath, "allow"]);
        }
      }
    } else if (permissions.document !== undefined) {
      addFinding(findings, "error", "document permissions must be an object.", [...path, "permissions", "document"]);
    }

    if (isRecord(permissions.network)) {
      const origins = permissions.network.allowedOrigins;
      if (!Array.isArray(origins)) {
        addFinding(findings, "error", "allowedOrigins must be an array.", [...path, "permissions", "network", "allowedOrigins"]);
      } else {
        origins.forEach((origin: unknown, originIndex: number) => {
          const originPath = [...path, "permissions", "network", "allowedOrigins", String(originIndex)];
          if (typeof origin !== "string" || origin === "*") {
            addFinding(findings, "error", "Network origins must be explicit URLs; wildcards are not allowed.", originPath);
            return;
          }
          try {
            const parsed = new URL(origin);
            if (parsed.protocol !== "https:" && parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1") {
              addFinding(findings, "warning", "Network origin does not use HTTPS.", originPath);
            }
          } catch {
            addFinding(findings, "error", "Network origin must be a valid absolute URL.", originPath);
          }
        });
      }
      if (permissions.network.fallbackMode !== "drop-with-403") {
        addFinding(findings, "error", 'Network fallbackMode must be "drop-with-403".', [...path, "permissions", "network", "fallbackMode"]);
      }
    } else if (permissions.network !== undefined) {
      addFinding(findings, "error", "network permissions must be an object.", [...path, "permissions", "network"]);
    }

    if (isRecord(permissions.storage) && isRecord(permissions.storage.localStorage)) {
      if (permissions.storage.localStorage.allow === true) {
        addFinding(findings, "warning", "Third-party access to localStorage is allowed.", [...path, "permissions", "storage", "localStorage", "allow"]);
      } else if (typeof permissions.storage.localStorage.allow !== "boolean") {
        addFinding(findings, "error", "localStorage.allow must be a boolean.", [...path, "permissions", "storage", "localStorage", "allow"]);
      }
    } else if (permissions.storage !== undefined && !isRecord(permissions.storage)) {
      addFinding(findings, "error", "storage permissions must be an object.", [...path, "permissions", "storage"]);
    }
  });

  return findings;
}

export function isPolicyShape(value: unknown): value is { scripts: unknown[] } {
  return isRecord(value) && Array.isArray(value.scripts);
}
