import * as path from "node:path";
import * as vscode from "vscode";
import { isPolicyShape, PolicyFinding, validatePolicy } from "./policy";

const POLICY_FILENAME = "scriptsentinel.json";
const output = vscode.window.createOutputChannel("ScriptSentinel");
const diagnostics = vscode.languages.createDiagnosticCollection("ScriptSentinel");

interface TreeNode {
  kind: "script" | "message";
  label: string;
  description?: string;
  script?: Record<string, unknown>;
}

class PolicyExplorer implements vscode.TreeDataProvider<TreeNode> {
  private readonly changeEmitter = new vscode.EventEmitter<TreeNode | undefined>();
  readonly onDidChangeTreeData = this.changeEmitter.event;

  refresh(): void {
    this.changeEmitter.fire(undefined);
  }

  getTreeItem(node: TreeNode): vscode.TreeItem {
    const item = new vscode.TreeItem(
      node.label,
      node.kind === "script" ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None
    );
    item.description = node.description;
    if (node.kind === "script") {
      item.iconPath = new vscode.ThemeIcon("shield");
      item.contextValue = "scriptsentinelScript";
    } else {
      item.iconPath = new vscode.ThemeIcon("info");
      item.command = node.label === "Create a policy"
        ? { command: "scriptsentinel.createPolicy", title: "Create a policy" }
        : undefined;
    }
    return item;
  }

  async getChildren(node?: TreeNode): Promise<TreeNode[]> {
    if (node?.kind === "script") {
      return permissionNodes(node.script?.permissions);
    }

    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      return [{ kind: "message", label: "Open a workspace to manage a policy" }];
    }
    const policyUri = vscode.Uri.joinPath(folder.uri, POLICY_FILENAME);
    const matches = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, POLICY_FILENAME),
      "**/node_modules/**",
      1
    );
    if (matches.length === 0) {
      return [{ kind: "message", label: "Create a policy" }];
    }

    try {
      const text = Buffer.from(await vscode.workspace.fs.readFile(policyUri)).toString("utf8");
      const value: unknown = JSON.parse(text);
      if (!isPolicyShape(value)) {
        return [{ kind: "message", label: "Policy must contain a scripts array" }];
      }
      if (value.scripts.length === 0) {
        return [{ kind: "message", label: "No scripts defined in scriptsentinel.json" }];
      }
      return value.scripts.map((script: unknown, index: number) => {
        if (typeof script !== "object" || script === null || Array.isArray(script)) {
          return { kind: "message", label: `Invalid script entry at index ${index}` };
        }
        const item = script as Record<string, unknown>;
        return {
          kind: "script",
          label: typeof item.identifier === "string" ? item.identifier : `Script ${index + 1}`,
          description: typeof item.sourceMatch === "string" ? item.sourceMatch : undefined,
          script: item
        };
      });
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      output.appendLine(`Unable to read ${policyUri.fsPath}: ${detail}`);
      return [{ kind: "message", label: "Unable to read scriptsentinel.json; see Output" }];
    }
  }

  dispose(): void {
    this.changeEmitter.dispose();
  }
}

function permissionNodes(value: unknown): TreeNode[] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return [{ kind: "message", label: "No permissions configured" }];
  }
  const permissions = value as Record<string, unknown>;
  const result: TreeNode[] = [];
  const documentPermissions = permissions.document;
  if (typeof documentPermissions === "object" && documentPermissions !== null && !Array.isArray(documentPermissions)) {
    for (const [resource, rule] of Object.entries(documentPermissions)) {
      const allowed = typeof rule === "object" && rule !== null && "allow" in rule && rule.allow === true;
      result.push({ kind: "message", label: `document.${resource}: ${allowed ? "allowed" : "blocked"}` });
    }
  }
  const network = permissions.network;
  if (typeof network === "object" && network !== null && !Array.isArray(network)) {
    const origins = "allowedOrigins" in network && Array.isArray(network.allowedOrigins) ? network.allowedOrigins.length : 0;
    result.push({ kind: "message", label: `network: ${origins} allowed origin(s)` });
  }
  const storage = permissions.storage;
  if (typeof storage === "object" && storage !== null && !Array.isArray(storage)) {
    const localStorage = "localStorage" in storage ? storage.localStorage : undefined;
    if (typeof localStorage === "object" && localStorage !== null && "allow" in localStorage) {
      result.push({ kind: "message", label: `storage.localStorage: ${localStorage.allow === true ? "allowed" : "blocked"}` });
    }
  }
  return result.length > 0 ? result : [{ kind: "message", label: "No permissions configured" }];
}

function isPolicyDocument(document: vscode.TextDocument): boolean {
  return path.basename(document.uri.fsPath).toLowerCase() === POLICY_FILENAME;
}

function updateDiagnostics(document: vscode.TextDocument): void {
  if (!isPolicyDocument(document)) {
    return;
  }
  const findings = validatePolicy(document.getText());
  diagnostics.set(document.uri, findings.map(finding => toDiagnostic(document, finding)));
}

function toDiagnostic(document: vscode.TextDocument, finding: PolicyFinding): vscode.Diagnostic {
  const target = finding.path.length > 0 ? JSON.stringify(finding.path[finding.path.length - 1]) : "";
  const text = document.getText();
  const index = target ? text.indexOf(target) : -1;
  const start = index >= 0 ? document.positionAt(index) : new vscode.Position(0, 0);
  const end = index >= 0 ? document.positionAt(index + target.length) : new vscode.Position(0, 1);
  const diagnostic = new vscode.Diagnostic(
    new vscode.Range(start, end),
    finding.message,
    finding.severity === "error" ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning
  );
  diagnostic.source = "ScriptSentinel";
  return diagnostic;
}

async function getPolicyDocument(): Promise<vscode.TextDocument | undefined> {
  const active = vscode.window.activeTextEditor?.document;
  if (active && isPolicyDocument(active)) {
    return active;
  }
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    void vscode.window.showErrorMessage("ScriptSentinel requires an open workspace.");
    return undefined;
  }
  const uri = vscode.Uri.joinPath(folder.uri, POLICY_FILENAME);
  try {
    await vscode.workspace.fs.stat(uri);
    return await vscode.workspace.openTextDocument(uri);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    void vscode.window.showErrorMessage(`Unable to open ${POLICY_FILENAME}: ${detail}`);
    return undefined;
  }
}

async function createPolicy(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    void vscode.window.showErrorMessage("Open a workspace before creating a ScriptSentinel policy.");
    return;
  }

  const uri = vscode.Uri.joinPath(folder.uri, POLICY_FILENAME);
  try {
    await vscode.workspace.fs.stat(uri);
    await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(uri));
    void vscode.window.showInformationMessage(`${POLICY_FILENAME} already exists.`);
    return;
  } catch (error) {
    if (!(error instanceof vscode.FileSystemError) || error.code !== "FileNotFound") {
      const detail = error instanceof Error ? error.message : String(error);
      void vscode.window.showErrorMessage(`Unable to check for an existing policy: ${detail}`);
      return;
    }
  }

  const applicationId = folder.name.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-|-$/g, "") || "application";
  const contents = {
    applicationId,
    version: "1.0.0",
    globalSettings: {
      antiPrototypePollution: true,
      iframeBypassProtection: true
    },
    scripts: []
  };
  try {
    await vscode.workspace.fs.writeFile(uri, Buffer.from(`${JSON.stringify(contents, null, 2)}\n`, "utf8"));
    await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(uri));
    void vscode.window.showInformationMessage(`Created ${POLICY_FILENAME}.`);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    void vscode.window.showErrorMessage(`Unable to create ${POLICY_FILENAME}: ${detail}`);
  }
}

async function auditPolicy(): Promise<void> {
  const document = await getPolicyDocument();
  if (!document) {
    return;
  }
  const findings = validatePolicy(document.getText());
  diagnostics.set(document.uri, findings.map(finding => toDiagnostic(document, finding)));
  output.clear();
  output.appendLine(`Policy audit: ${document.uri.fsPath}`);
  for (const finding of findings) {
    output.appendLine(`${finding.severity.toUpperCase()}: ${finding.path.join(".") || "(root)"}: ${finding.message}`);
  }
  output.show(true);

  const errors = findings.filter(finding => finding.severity === "error").length;
  const warnings = findings.length - errors;
  const message = `ScriptSentinel audit: ${errors} error(s), ${warnings} warning(s).`;
  if (errors > 0) {
    void vscode.window.showWarningMessage(message);
  } else {
    void vscode.window.showInformationMessage(message);
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const explorer = new PolicyExplorer();
  const policyWatcher = vscode.workspace.createFileSystemWatcher("**/scriptsentinel.json");
  const refreshExplorer = (): void => explorer.refresh();
  context.subscriptions.push(
    output,
    diagnostics,
    explorer,
    policyWatcher,
    vscode.window.registerTreeDataProvider("scriptsentinel.policyExplorer", explorer),
    vscode.commands.registerCommand("scriptsentinel.createPolicy", createPolicy),
    vscode.commands.registerCommand("scriptsentinel.validatePolicy", auditPolicy),
    vscode.commands.registerCommand("scriptsentinel.refreshPolicyExplorer", () => explorer.refresh()),
    policyWatcher.onDidCreate(refreshExplorer),
    policyWatcher.onDidChange(refreshExplorer),
    policyWatcher.onDidDelete(refreshExplorer),
    vscode.workspace.onDidOpenTextDocument(document => {
      updateDiagnostics(document);
      if (isPolicyDocument(document)) {
        refreshExplorer();
      }
    }),
    vscode.workspace.onDidChangeTextDocument(event => {
      updateDiagnostics(event.document);
      if (isPolicyDocument(event.document)) {
        refreshExplorer();
      }
    }),
    vscode.workspace.onDidSaveTextDocument(document => {
      updateDiagnostics(document);
      if (isPolicyDocument(document)) {
        refreshExplorer();
      }
    }),
    vscode.workspace.onDidCloseTextDocument(document => diagnostics.delete(document.uri))
  );

  for (const document of vscode.workspace.textDocuments) {
    updateDiagnostics(document);
  }
}

export function deactivate(): void {}
