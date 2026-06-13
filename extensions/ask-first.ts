import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DEFAULT_POLICY as RAW_DEFAULT_POLICY, mergePolicy, patternFor, readJsonc, summarize } from "./policy.js";

type Decision = "allow" | "ask" | "deny";

type Policy = {
  defaultPolicy: Decision;
  tools: Record<string, Decision>;
  bash: { safeCommands: string[]; dangerousPatterns: string[] };
  paths: { outsideProject: Decision; homeDirectory: Decision; systemDirectories: Decision };
  remembered: Record<string, Decision>;
};

const DEFAULT_POLICY = RAW_DEFAULT_POLICY as Policy;
const GLOBAL_POLICY = path.join(os.homedir(), ".pi/agent/pi-permissions.jsonc");
const PROJECT_POLICY = ".pi/permissions.jsonc";

function loadPolicy(cwd: string): Policy {
  return mergePolicy(mergePolicy(DEFAULT_POLICY, readJsonc(GLOBAL_POLICY)), readJsonc(path.join(cwd, PROJECT_POLICY))) as Policy;
}

function saveProjectPolicy(cwd: string, policy: Policy) {
  const file = path.join(cwd, PROJECT_POLICY);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const existing = readJsonc(file);
  const next = { ...existing, defaultPolicy: policy.defaultPolicy, tools: policy.tools, bash: policy.bash, paths: policy.paths, remembered: policy.remembered };
  fs.writeFileSync(file, JSON.stringify(next, null, 2) + "\n");
}

export default function (pi: ExtensionAPI) {
  const sessionMemo = new Map<string, Decision>();
  const policies = new Map<string, Policy>();

  function getPolicy(ctx: ExtensionContext) {
    const cwd = path.resolve(ctx.cwd);
    let policy = policies.get(cwd);
    if (!policy) {
      policy = loadPolicy(cwd);
      policies.set(cwd, policy);
    }
    return policy;
  }

  pi.on("tool_call", async (event, ctx) => {
    const current = getPolicy(ctx);
    const key = patternFor(event.toolName, event.input);
    const saved = sessionMemo.get(key) ?? current.remembered[key];
    if (saved === "allow") return undefined;
    if (saved === "deny") return { block: true, reason: `Blocked by ask-first remembered deny for ${key}` };

    const info = summarize(event.toolName, event.input, ctx.cwd, current as any);
    let decision: Decision = info.pathDecision ?? current.tools[event.toolName] ?? (event.toolName.startsWith("mcp") ? current.tools.mcp : current.defaultPolicy);
    if (event.toolName === "bash" && info.safeReadOnlyBash) decision = current.tools.read ?? "allow";
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
      String(info.preview).length <= 900 ? String(info.preview) : `${String(info.preview).slice(0, 900)}\n… truncated (${String(info.preview).length - 900} more chars)`,
    ].join("\n");
    const choice = await ctx.ui.select(prompt, ["Allow for this session", "Deny once", "Always allow this exact action", "Always deny this exact action"]);
    if (choice === "Allow for this session") { sessionMemo.set(key, "allow"); return undefined; }
    if (choice === "Always allow this exact action") { current.remembered[key] = "allow"; saveProjectPolicy(ctx.cwd, current); return undefined; }
    if (choice === "Always deny this exact action") { current.remembered[key] = "deny"; saveProjectPolicy(ctx.cwd, current); }
    return { block: true, reason: "Blocked by user" };
  });

  pi.registerCommand("permissions", {
    description: "Show or modify ask-first permissions: reset | mode ask-first|strict|permissive",
    handler: async (args, ctx) => {
      const cwd = path.resolve(ctx.cwd);
      const policy = loadPolicy(cwd);
      policies.set(cwd, policy);
      const [cmd, value] = args.trim().split(/\s+/);
      if (cmd === "reset") {
        policy.remembered = {};
        sessionMemo.clear();
        saveProjectPolicy(ctx.cwd, policy);
        ctx.ui.notify("Ask-first remembered decisions reset", "info");
        return;
      }
      if (cmd === "mode") {
        if (value === "ask-first") { policy.defaultPolicy = "ask"; policy.tools = { ...DEFAULT_POLICY.tools }; }
        else if (value === "strict") { policy.defaultPolicy = "ask"; policy.tools = Object.fromEntries(Object.keys(policy.tools).map((tool) => [tool, "ask" as Decision])); }
        else if (value === "permissive") { policy.defaultPolicy = "allow"; policy.tools = { ...DEFAULT_POLICY.tools, bash: "ask", write: "ask", edit: "ask", mcp: "ask" }; }
        else { ctx.ui.notify("Usage: /permissions mode ask-first|strict|permissive", "error"); return; }
        saveProjectPolicy(ctx.cwd, policy);
        ctx.ui.notify(`Ask-first mode set to ${value}`, "info");
        return;
      }
      ctx.ui.notify(`Ask-first policy: default=${policy.defaultPolicy}, remembered=${Object.keys(policy.remembered).length}. Config: ${PROJECT_POLICY}`, "info");
    },
  });
}
