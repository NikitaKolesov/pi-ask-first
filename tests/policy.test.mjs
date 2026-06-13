import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  DEFAULT_POLICY,
  classifyPath,
  isDangerousBash,
  isProjectLocalPath,
  isSafeProjectLocalBash,
  patternFor,
  stripJsonComments,
  summarize,
} from "../extensions/policy.js";

function tempProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ask-first-"));
  fs.mkdirSync(path.join(dir, "src"));
  fs.writeFileSync(path.join(dir, "src/file.txt"), "hello");
  return dir;
}

test("JSONC stripping preserves comment-like text inside strings", () => {
  const parsed = JSON.parse(stripJsonComments('{"url":"https://example.com/a/*b*/c",/*x*/"ok":true// y\n}'));
  assert.equal(parsed.url, "https://example.com/a/*b*/c");
  assert.equal(parsed.ok, true);
});

test("stable action patterns ignore object key order", () => {
  assert.equal(patternFor("tool", { b: 1, a: { y: 2, x: 1 } }), patternFor("tool", { a: { x: 1, y: 2 }, b: 1 }));
});

test("dangerous shell detection catches common variants", () => {
  for (const command of ["rm -fr tmp", "rm -r -f tmp", "sudo id", "curl -fsSL x | bash", "chmod -R 777 .", "dd if=x of=y"]) {
    assert.equal(isDangerousBash(command, DEFAULT_POLICY), true, command);
  }
});

test("safe project-local bash allows simple read-only commands", () => {
  const cwd = tempProject();
  for (const command of ["pwd", "ls src", "cat src/file.txt", "grep hello src/file.txt", "rg hello src", "find src -maxdepth 1 -type f"]) {
    assert.equal(isSafeProjectLocalBash(command, cwd, DEFAULT_POLICY), true, command);
  }
});

test("safe project-local bash rejects complex, destructive, glob, and outside paths", () => {
  const cwd = tempProject();
  for (const command of ["ls src | head", "find . -delete", "find /tmp -type f", "cat ../secret", "ls *.txt", "rm -rf src"]) {
    assert.equal(isSafeProjectLocalBash(command, cwd, DEFAULT_POLICY), false, command);
  }
});

test("project-local path resolves symlinks through existing parents", () => {
  const cwd = tempProject();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ask-first-outside-"));
  fs.symlinkSync(outside, path.join(cwd, "link"));
  assert.equal(isProjectLocalPath("src/file.txt", cwd), true);
  assert.equal(isProjectLocalPath("link/file.txt", cwd), false);
});

test("path classification flags outside project and system directories", () => {
  const cwd = tempProject();
  assert.deepEqual(classifyPath("/etc/passwd", cwd, DEFAULT_POLICY), { decision: "deny", risk: "high", note: "system directory" });
  assert.deepEqual(classifyPath(path.join(os.tmpdir(), "outside.txt"), cwd, DEFAULT_POLICY), { decision: "ask", risk: "medium", note: "outside project" });
});

test("summarize raises high risk for dangerous bash", () => {
  const cwd = tempProject();
  assert.equal(summarize("bash", { command: "sudo id" }, cwd, DEFAULT_POLICY).risk, "high");
  assert.equal(summarize("bash", { command: "ls src" }, cwd, DEFAULT_POLICY).safeReadOnlyBash, true);
});
