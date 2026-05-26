# Ask-First Pi Extension

Claude Code–style permission gate for Pi tool calls. It intercepts `tool_call` before execution and applies `allow`, `ask`, or `deny` policy decisions.

## Install

This project already contains the extension at:

```text
.pi/extensions/ask-first/index.ts
```

Reload Pi with `/reload`, or start Pi in this project. For global use, copy the directory to:

```text
~/.pi/agent/extensions/ask-first/
```

## Behavior

- Read-only tools such as `read`, `ls`, and `grep` are allowed by default.
- Side-effectful tools such as `bash`, `write`, and `edit` ask first.
- Unknown tools use `defaultPolicy`, which defaults to `ask`.
- High-risk bash commands are highlighted.
- File operations outside the project or in sensitive locations raise risk.
- System directories are denied by default.
- “Always allow/deny this exact action” decisions are persisted in `.pi/permissions.jsonc`.

## Commands

```text
/permissions
/permissions reset
/permissions mode ask-first
/permissions mode strict
/permissions mode permissive
```

## Configuration

Global config:

```text
~/.pi/agent/pi-permissions.jsonc
```

Project config:

```text
.pi/permissions.jsonc
```

Project config overrides global config.

Example:

```jsonc
{
  "defaultPolicy": "ask",
  "tools": {
    "read": "allow",
    "write": "ask",
    "edit": "ask",
    "bash": "ask",
    "mcp": "ask"
  },
  "bash": {
    "safeCommands": ["pwd", "ls", "cat", "grep", "rg", "find"],
    "dangerousPatterns": ["rm -rf", "sudo", "chmod -R", "curl | sh", "dd "]
  },
  "paths": {
    "outsideProject": "ask",
    "homeDirectory": "ask",
    "systemDirectories": "deny"
  }
}
```

## Demo

Ask Pi to run a shell command or edit a file. For example:

```text
Run pwd using bash
```

The extension will show a prompt with the tool, target, risk level, and preview.

## Security caveats

This is a permission prompt, not a sandbox. Pi extensions run with your user privileges. Only install trusted extensions, and do not rely on this to contain malicious code or malicious extensions.
