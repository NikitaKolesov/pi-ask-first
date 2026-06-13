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

type ActionSummary = {
  action: string;
  target: string;
  preview: string;
  risk: Risk;
  note?: string;
  pathDecision?: Decision;
  safeReadOnlyBash?: boolean;
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
  let out = "";
  let inString = false;
  let quote = "";
  let escaping = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];
    if (inString) {
      out += ch;
      if (escaping) escaping = false;
      else if (ch === "\\") escaping = true;
      else if (ch === quote) inString = false;
      continue;
    }
    if (ch === '"' || ch === "'") { inString = true; quote = ch; out += ch; continue; }
    if (ch === "/" && next === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++;
      continue;
    }
    out += ch;
  }
  return out;
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
  const next = { ...existing, defaultPolicy: policy.defaultPolicy, tools: policy.tools, bash: policy.bash, paths: policy.paths, remembered: policy.remembered };
  fs.writeFileSync(file, JSON.stringify(next, null, 2) + "\n");
}

function shellWords(command: string): string[] | undefined {
  const words: string[] = [];
  let current = "";
  let quote: "'" | "\"" | undefined;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote) {
      if (ch === quote) quote = undefined;
      else current += ch;
      continue;
    }
    if (ch === "'" || ch === "\"") { quote = ch; continue; }
    if (/\s/.test(ch)) {
      if (current) { words.push(current); current = ""; }
      continue;
    }
    current += ch;
  }
  if (quote) return undefined;
  if (current) words.push(current);
  return words;
}

function truncate(value: string, max = 900): string {
  return value.length <= max ? value : `${value.slice(0, max)}\n… truncated (${value.length - max} more chars)`;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, sortKeys(v)]));
}

function stable(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function patternFor(toolName: string, input: any): string {
  if (toolName === "bash") return `bash:${input.command ?? ""}`;
  const target = input.path ?? input.file ?? input.url ?? input.uri ?? input.command ?? stable(input);
  return `${toolName}:${target}`;
}

function classifyPath(raw: string | undefined, cwd: string, policy: Policy): { decision?: Decision; risk: Risk; note?: string } {
  if (!raw) return { risk: "medium" };
  const full = resolveThroughExistingParent(raw, cwd);
  const home = os.homedir();
  const systemDirs = ["/etc", "/bin", "/sbin", "/usr", "/var", "/System", "/Library"];
  const sensitive = [path.join(home, ".ssh"), path.join(home, ".gnupg"), path.join(home, ".aws"), path.join(home, ".config"), path.join(home, ".bashrc"), path.join(home, ".zshrc")];
  if (systemDirs.some((d) => full === d || full.startsWith(d + path.sep))) return { decision: policy.paths.systemDirectories, risk: "high", note: "system directory" };
  if (sensitive.some((d) => full === d || full.startsWith(d + path.sep))) return { decision: policy.paths.homeDirectory, risk: "high", note: "sensitive home path" };
  if (!full.startsWith(path.resolve(cwd) + path.sep) && full !== path.resolve(cwd)) return { decision: policy.paths.outsideProject, risk: "medium", note: "outside project" };
  return { risk: "medium" };
}

const BASH_CONTROL_CHARS = /[;&|`$<>\\]/;
const FIND_DANGEROUS_FLAGS = new Set(["-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls", "-fprint", "-fprint0", "-fprintf"]);
const DANGEROUS_BASH_REGEXES = [
  /(^|\s)rm\s+(?:-[^\s]*[rf][^\s]*\s+|(?:-[^\s]*[rf][^\s]*\s+){2,})/i,
  /(^|\s)sudo(\s|$)/i,
  /(^|\s)(dd|mkfs(?:\.[\w-]+)?|mount|umount|shutdown|reboot)(\s|$)/i,
  /(^|\s)(chmod|chown|chgrp)\s+.*\s-R(\s|$)|(^|\s)(chmod|chown|chgrp)\s+-[^\s]*R/i,
  /(^|\s)chmod\s+(?:777|666|[0-7]*7[0-7]*)(\s|$)/i,
  /(curl|wget)\b[^|;\n]*(\||>)\s*(sh|bash)\b/i,
  /:\s*\(\)\s*\{\s*:\s*\|\s*:\s*&\s*}\s*;\s*:/,
];

function isOption(word: string): boolean {
  return word.startsWith("-") && word !== "-";
}

function resolveThroughExistingParent(raw: string, cwd: string): string {
  const resolved = path.resolve(cwd, raw.replace(/^~(?=$|\/)/, os.homedir()));
  const parts = resolved.split(path.sep);
  for (let i = parts.length; i > 0; i--) {
    const prefix = parts.slice(0, i).join(path.sep) || path.sep;
    if (fs.existsSync(prefix)) return path.join(fs.realpathSync(prefix), ...parts.slice(i));
  }
  return resolved;
}

function isProjectLocalPath(raw: string, cwd: string): boolean {
  if (!raw || raw.startsWith("-")) return true;
  if (raw.includes("*") || raw.includes("?") || raw.includes("[")) return false;
  const full = resolveThroughExistingParent(raw, cwd);
  const root = fs.existsSync(cwd) ? fs.realpathSync(cwd) : path.resolve(cwd);
  return full === root || full.startsWith(root + path.sep);
}

function isDangerousBash(command: string, policy: Policy): boolean {
  return policy.bash.dangerousPatterns.some((p) => command.toLowerCase().includes(p.toLowerCase())) || DANGEROUS_BASH_REGEXES.some((r) => r.test(command));
}

function isSafeProjectLocalBash(command: string, cwd: string, policy: Policy): boolean {
  if (BASH_CONTROL_CHARS.test(command)) return false;
  const words = shellWords(command);
  if (!words?.length) return false;
  const cmd = words[0];
  if (!policy.bash.safeCommands.includes(cmd)) return false;
  if (isDangerousBash(command, policy)) return false;
  if (cmd === "pwd") return words.length === 1;
  if (cmd === "find") {
    if (words.some((w) => FIND_DANGEROUS_FLAGS.has(w))) return false;
    const firstPredicate = words.findIndex((w, index) => index > 0 && (isOption(w) || ["!", "(", ")"].includes(w)));
    const initialPaths = firstPredicate === 1 ? ["."] : words.slice(1, firstPredicate === -1 ? undefined : firstPredicate);
    return initialPaths.every((arg) => isProjectLocalPath(arg, cwd));
  }

  let pathArgs: string[] = [];
  if (["grep", "rg"].includes(cmd)) {
    const nonOptions = words.slice(1).filter((w) => !isOption(w));
    pathArgs = nonOptions.slice(1).filter((w) => w.includes(path.sep) || w === "." || w === ".." || w.startsWith("~"));
  } else {
    pathArgs = words.slice(1).filter((w) => !isOption(w));
  }
  return pathArgs.every((arg) => isProjectLocalPath(arg, cwd));
}

function summarize(toolName: string, input: any, cwd: string, policy: Policy): ActionSummary {
  if (toolName === "bash") {
    const command = String(input.command ?? "");
    const safe = isSafeProjectLocalBash(command, cwd, policy);
    const dangerous = isDangerousBash(command, policy);
    return { action: "Run shell command", target: command, preview: command, risk: dangerous ? "high" as Risk : safe ? "low" as Risk : "medium" as Risk, safeReadOnlyBash: safe };
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
      truncate(String(info.preview)),
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
