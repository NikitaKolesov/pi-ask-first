import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

type Decision = "allow" | "ask" | "deny";
type Risk = "low" | "medium" | "high";

type Policy = {
  defaultPolicy: Decision;
  tools: Record<string, Decision>;
  bash: { safeCommands: string[]; dangerousPatterns: string[] };
  paths: { outsideProject: Decision; homeDirectory: Decision; systemDirectories: Decision };
  remembered: Record<string, Decision>;
};

const DEFAULT_POLICY: Policy = {
  defaultPolicy: "ask",
  tools: {
    read: "allow",
    ls: "allow",
    grep: "allow",
    bash: "ask",
    write: "ask",
    edit: "ask",
    mcp: "ask",
  },
  bash: {
    safeCommands: ["pwd", "ls", "cat", "grep", "rg", "find"],
    dangerousPatterns: ["rm -rf", "sudo", "chmod -R", "curl | sh", "curl|sh", "wget | sh", "wget|sh", "dd "],
  },
  paths: { outsideProject: "ask", homeDirectory: "ask", systemDirectories: "deny" },
  remembered: {},
};

const GLOBAL_POLICY = path.join(os.homedir(), ".pi/agent/pi-permissions.jsonc");
const PROJECT_POLICY = ".pi/permissions.jsonc";

function stripJsonComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

function readJsonc(file: string): Partial<Policy> {
  if (!fs.existsSync(file)) return {};
  try {
    return JSON.parse(stripJsonComments(fs.readFileSync(file, "utf8")));
  } catch (error) {
    console.warn(`[ask-first] Failed to parse ${file}:`, error);
    return {};
  }
}

function mergePolicy(base: Policy, overlay: Partial<Policy>): Policy {
  return {
    ...base,
    ...overlay,
    tools: { ...base.tools, ...(overlay.tools ?? {}) },
    bash: { ...base.bash, ...(overlay.bash ?? {}) },
    paths: { ...base.paths, ...(overlay.paths ?? {}) },
    remembered: { ...base.remembered, ...(overlay.remembered ?? {}) },
  };
}

function loadPolicy(cwd: string): Policy {
  return mergePolicy(mergePolicy(DEFAULT_POLICY, readJsonc(GLOBAL_POLICY)), readJsonc(path.join(cwd, PROJECT_POLICY)));
}

function saveProjectPolicy(cwd: string, policy: Policy) {
  const file = path.join(cwd, PROJECT_POLICY);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const existing = readJsonc(file);
  const next = { ...existing, remembered: policy.remembered, defaultPolicy: policy.defaultPolicy };
  fs.writeFileSync(file, JSON.stringify(next, null, 2) + "\n");
}

function firstWord(command: string): string {
  return command.trim().split(/\s+/)[0] ?? "";
}

function truncate(value: string, max = 900): string {
  return value.length <= max ? value : `${value.slice(0, max)}\n… truncated (${value.length - max} more chars)`;
}

function stable(value: unknown): string {
  return JSON.stringify(value, Object.keys(value as object).sort());
}

function patternFor(toolName: string, input: any): string {
  if (toolName === "bash") return `bash:${input.command ?? ""}`;
  const target = input.path ?? input.file ?? input.url ?? input.uri ?? input.command ?? stable(input);
  return `${toolName}:${target}`;
}

function classifyPath(raw: string | undefined, cwd: string, policy: Policy): { decision?: Decision; risk: Risk; note?: string } {
  if (!raw) return { risk: "medium" };
  const full = path.resolve(cwd, raw.replace(/^~(?=$|\/)/, os.homedir()));
  const home = os.homedir();
  const systemDirs = ["/etc", "/bin", "/sbin", "/usr", "/var", "/System", "/Library"];
  const sensitive = [path.join(home, ".ssh"), path.join(home, ".gnupg"), path.join(home, ".aws"), path.join(home, ".config"), path.join(home, ".bashrc"), path.join(home, ".zshrc")];
  if (systemDirs.some((d) => full === d || full.startsWith(d + path.sep))) return { decision: policy.paths.systemDirectories, risk: "high", note: "system directory" };
  if (sensitive.some((d) => full === d || full.startsWith(d + path.sep))) return { decision: policy.paths.homeDirectory, risk: "high", note: "sensitive home path" };
  if (!full.startsWith(path.resolve(cwd) + path.sep) && full !== path.resolve(cwd)) return { decision: policy.paths.outsideProject, risk: "medium", note: "outside project" };
  return { risk: "medium" };
}

function summarize(toolName: string, input: any, cwd: string, policy: Policy) {
  if (toolName === "bash") {
    const command = String(input.command ?? "");
    const safe = policy.bash.safeCommands.includes(firstWord(command));
    const dangerous = policy.bash.dangerousPatterns.some((p) => command.toLowerCase().includes(p.toLowerCase()));
    return { action: "Run shell command", target: command, preview: command, risk: dangerous ? "high" as Risk : safe ? "low" as Risk : "medium" as Risk };
  }
  const filePath = input.path ?? input.file;
  const p = classifyPath(filePath, cwd, policy);
  if (["write", "edit"].includes(toolName)) {
    const content = input.content ?? input.newText ?? input.edits;
    return { action: toolName === "write" ? "Write file" : "Modify file", target: filePath ?? "unknown", preview: truncate(typeof content === "string" ? content : JSON.stringify(content, null, 2)), risk: p.risk, note: p.note, pathDecision: p.decision };
  }
  if (toolName.startsWith("mcp") || input.url || input.uri) return { action: "Call external/MCP tool", target: input.url ?? input.uri ?? toolName, preview: truncate(JSON.stringify(input, null, 2)), risk: "medium" as Risk };
  return { action: "Use tool", target: filePath ?? toolName, preview: truncate(JSON.stringify(input, null, 2)), risk: p.risk, note: p.note, pathDecision: p.decision };
}

export default function (pi: ExtensionAPI) {
  const sessionMemo = new Map<string, Decision>();
  let policy: Policy | undefined;

  function getPolicy(ctx: ExtensionContext) {
    policy ??= loadPolicy(ctx.cwd);
    return policy;
  }

  pi.on("tool_call", async (event, ctx) => {
    const current = getPolicy(ctx);
    const key = patternFor(event.toolName, event.input);
    const saved = sessionMemo.get(key) ?? current.remembered[key];
    if (saved === "allow") return undefined;
    if (saved === "deny") return { block: true, reason: `Blocked by ask-first remembered deny for ${key}` };

    const info = summarize(event.toolName, event.input, ctx.cwd, current);
    let decision: Decision = info.pathDecision ?? current.tools[event.toolName] ?? (event.toolName.startsWith("mcp") ? current.tools.mcp : current.defaultPolicy);
    if (info.risk === "high" && decision === "allow") decision = "ask";
    if (decision === "allow") return undefined;
    if (decision === "deny") return { block: true, reason: `Blocked by ask-first policy (${info.note ?? "policy deny"})` };

    if (!ctx.hasUI) return { block: true, reason: "Ask-first approval required, but no UI is available" };

    const prompt = [
      `${info.risk === "high" ? "⚠️ " : ""}${info.action}`,
      `Tool: ${event.toolName}`,
      `Target: ${info.target}`,
      `Risk: ${info.risk}${info.note ? ` (${info.note})` : ""}`,
      "",
      truncate(String(info.preview)),
    ].join("\n");
    const choice = await ctx.ui.select(prompt, ["Allow once", "Deny once", "Always allow this exact action", "Always deny this exact action"]);
    if (choice === "Allow once") { sessionMemo.set(key, "allow"); return undefined; }
    if (choice === "Always allow this exact action") { current.remembered[key] = "allow"; saveProjectPolicy(ctx.cwd, current); return undefined; }
    if (choice === "Always deny this exact action") { current.remembered[key] = "deny"; saveProjectPolicy(ctx.cwd, current); }
    return { block: true, reason: "Blocked by user" };
  });

  pi.registerCommand("permissions", {
    description: "Show or modify ask-first permissions: reset | mode ask-first|strict|permissive",
    handler: async (args, ctx) => {
      policy = loadPolicy(ctx.cwd);
      const [cmd, value] = args.trim().split(/\s+/);
      if (cmd === "reset") {
        policy.remembered = {};
        sessionMemo.clear();
        saveProjectPolicy(ctx.cwd, policy);
        ctx.ui.notify("Ask-first remembered decisions reset", "info");
        return;
      }
      if (cmd === "mode") {
        if (value === "ask-first") policy.defaultPolicy = "ask";
        else if (value === "strict") { policy.defaultPolicy = "ask"; policy.tools.read = "ask"; }
        else if (value === "permissive") { policy.defaultPolicy = "allow"; policy.tools.bash = "ask"; policy.tools.write = "ask"; policy.tools.edit = "ask"; }
        else { ctx.ui.notify("Usage: /permissions mode ask-first|strict|permissive", "error"); return; }
        saveProjectPolicy(ctx.cwd, policy);
        ctx.ui.notify(`Ask-first mode set to ${value}`, "info");
        return;
      }
      ctx.ui.notify(`Ask-first policy: default=${policy.defaultPolicy}, remembered=${Object.keys(policy.remembered).length}. Config: ${PROJECT_POLICY}`, "info");
    },
  });
}
