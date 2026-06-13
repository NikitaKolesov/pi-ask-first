import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const DEFAULT_POLICY = {
  defaultPolicy: "ask",
  tools: { read: "allow", ls: "allow", grep: "allow", bash: "ask", write: "ask", edit: "ask", mcp: "ask" },
  bash: { safeCommands: ["pwd", "ls", "cat", "grep", "rg", "find"], dangerousPatterns: ["rm -rf", "sudo", "chmod -R", "curl | sh", "curl|sh", "wget | sh", "wget|sh", "dd "] },
  paths: { outsideProject: "ask", homeDirectory: "ask", systemDirectories: "deny" },
  remembered: {},
};

export function stripJsonComments(text) {
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
    if (ch === "/" && next === "/") { while (i < text.length && text[i] !== "\n") i++; out += "\n"; continue; }
    if (ch === "/" && next === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i++; continue; }
    out += ch;
  }
  return out;
}

export function readJsonc(file) {
  if (!fs.existsSync(file)) return {};
  try { return JSON.parse(stripJsonComments(fs.readFileSync(file, "utf8"))); }
  catch (error) { console.warn(`[ask-first] Failed to parse ${file}:`, error); return {}; }
}

export function mergePolicy(base, overlay) {
  return { ...base, ...overlay, tools: { ...base.tools, ...(overlay.tools ?? {}) }, bash: { ...base.bash, ...(overlay.bash ?? {}) }, paths: { ...base.paths, ...(overlay.paths ?? {}) }, remembered: { ...base.remembered, ...(overlay.remembered ?? {}) } };
}

export function shellWords(command) {
  const words = [];
  let current = "";
  let quote;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote) { if (ch === quote) quote = undefined; else current += ch; continue; }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (/\s/.test(ch)) { if (current) { words.push(current); current = ""; } continue; }
    current += ch;
  }
  if (quote) return undefined;
  if (current) words.push(current);
  return words;
}

export function truncate(value, max = 900) { return value.length <= max ? value : `${value.slice(0, max)}\n… truncated (${value.length - max} more chars)`; }

export function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, sortKeys(v)]));
}

export function stable(value) { return JSON.stringify(sortKeys(value)); }

export function patternFor(toolName, input) {
  if (toolName === "bash") return `bash:${input.command ?? ""}`;
  const target = input.path ?? input.file ?? input.url ?? input.uri ?? input.command ?? stable(input);
  return `${toolName}:${target}`;
}

export function resolveThroughExistingParent(raw, cwd) {
  const resolved = path.resolve(cwd, raw.replace(/^~(?=$|\/)/, os.homedir()));
  const parts = resolved.split(path.sep);
  for (let i = parts.length; i > 0; i--) {
    const prefix = parts.slice(0, i).join(path.sep) || path.sep;
    if (fs.existsSync(prefix)) return path.join(fs.realpathSync(prefix), ...parts.slice(i));
  }
  return resolved;
}

export function classifyPath(raw, cwd, policy) {
  if (!raw) return { risk: "medium" };
  const full = resolveThroughExistingParent(raw, cwd);
  const home = os.homedir();
  const systemDirs = ["/etc", "/bin", "/sbin", "/usr", "/var", "/System", "/Library"];
  const sensitive = [path.join(home, ".ssh"), path.join(home, ".gnupg"), path.join(home, ".aws"), path.join(home, ".config"), path.join(home, ".bashrc"), path.join(home, ".zshrc")];
  if (systemDirs.some((d) => full === d || full.startsWith(d + path.sep))) return { decision: policy.paths.systemDirectories, risk: "high", note: "system directory" };
  if (sensitive.some((d) => full === d || full.startsWith(d + path.sep))) return { decision: policy.paths.homeDirectory, risk: "high", note: "sensitive home path" };
  const root = fs.existsSync(cwd) ? fs.realpathSync(cwd) : path.resolve(cwd);
  if (!full.startsWith(root + path.sep) && full !== root) return { decision: policy.paths.outsideProject, risk: "medium", note: "outside project" };
  return { risk: "medium" };
}

const BASH_CONTROL_CHARS = /[;&|`$<>\\]/;
const FIND_DANGEROUS_FLAGS = new Set(["-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls", "-fprint", "-fprint0", "-fprintf"]);
export const DANGEROUS_BASH_REGEXES = [/(^|\s)rm\s+(?:-[^\s]*[rf][^\s]*\s+|(?:-[^\s]*[rf][^\s]*\s+){2,})/i, /(^|\s)sudo(\s|$)/i, /(^|\s)(dd|mkfs(?:\.[\w-]+)?|mount|umount|shutdown|reboot)(\s|$)/i, /(^|\s)(chmod|chown|chgrp)\s+.*\s-R(\s|$)|(^|\s)(chmod|chown|chgrp)\s+-[^\s]*R/i, /(^|\s)chmod\s+(?:777|666|[0-7]*7[0-7]*)(\s|$)/i, /(curl|wget)\b[^|;\n]*(\||>)\s*(sh|bash)\b/i, /:\s*\(\)\s*\{\s*:\s*\|\s*:\s*&\s*}\s*;\s*:/];

function isOption(word) { return word.startsWith("-") && word !== "-"; }

export function isProjectLocalPath(raw, cwd) {
  if (!raw || raw.startsWith("-")) return true;
  if (raw.includes("*") || raw.includes("?") || raw.includes("[")) return false;
  const full = resolveThroughExistingParent(raw, cwd);
  const root = fs.existsSync(cwd) ? fs.realpathSync(cwd) : path.resolve(cwd);
  return full === root || full.startsWith(root + path.sep);
}

export function isDangerousBash(command, policy = DEFAULT_POLICY) {
  return policy.bash.dangerousPatterns.some((p) => command.toLowerCase().includes(p.toLowerCase())) || DANGEROUS_BASH_REGEXES.some((r) => r.test(command));
}

export function isSafeProjectLocalBash(command, cwd, policy = DEFAULT_POLICY) {
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
  let pathArgs = [];
  if (["grep", "rg"].includes(cmd)) {
    const nonOptions = words.slice(1).filter((w) => !isOption(w));
    pathArgs = nonOptions.slice(1).filter((w) => w.includes(path.sep) || w === "." || w === ".." || w.startsWith("~"));
  } else {
    pathArgs = words.slice(1).filter((w) => !isOption(w));
  }
  return pathArgs.every((arg) => isProjectLocalPath(arg, cwd));
}

export function summarize(toolName, input, cwd, policy = DEFAULT_POLICY) {
  if (toolName === "bash") {
    const command = String(input.command ?? "");
    const safe = isSafeProjectLocalBash(command, cwd, policy);
    const dangerous = isDangerousBash(command, policy);
    return { action: "Run shell command", target: command, preview: command, risk: dangerous ? "high" : safe ? "low" : "medium", safeReadOnlyBash: safe };
  }
  const filePath = input.path ?? input.file;
  const p = classifyPath(filePath, cwd, policy);
  if (["write", "edit"].includes(toolName)) {
    const content = input.content ?? input.newText ?? input.edits;
    return { action: toolName === "write" ? "Write file" : "Modify file", target: filePath ?? "unknown", preview: truncate(typeof content === "string" ? content : JSON.stringify(content, null, 2)), risk: p.risk, note: p.note, pathDecision: p.decision };
  }
  if (toolName.startsWith("mcp") || input.url || input.uri) return { action: "Call external/MCP tool", target: input.url ?? input.uri ?? toolName, preview: truncate(JSON.stringify(input, null, 2)), risk: "medium" };
  return { action: "Use tool", target: filePath ?? toolName, preview: truncate(JSON.stringify(input, null, 2)), risk: p.risk, note: p.note, pathDecision: p.decision };
}
