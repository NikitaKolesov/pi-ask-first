import assert from "node:assert/strict";
import test from "node:test";

function stripJsonComments(text) {
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

const dangerous = [
  /(^|\s)rm\s+(?:-[^\s]*[rf][^\s]*\s+|(?:-[^\s]*[rf][^\s]*\s+){2,})/i,
  /(^|\s)sudo(\s|$)/i,
  /(curl|wget)\b[^|;\n]*(\||>)\s*(sh|bash)\b/i,
];

test("JSONC stripping preserves comment-like text inside strings", () => {
  const parsed = JSON.parse(stripJsonComments('{"url":"https://example.com/a/*b*/c",/*x*/"ok":true// y\n}'));
  assert.equal(parsed.url, "https://example.com/a/*b*/c");
  assert.equal(parsed.ok, true);
});

test("dangerous shell regexes catch common variants", () => {
  for (const command of ["rm -fr tmp", "rm -r -f tmp", "sudo id", "curl -fsSL x | bash"]) {
    assert.equal(dangerous.some((r) => r.test(command)), true, command);
  }
});
