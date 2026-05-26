# pi-ask-first

Ask-first permission gate extension for [Pi](https://github.com/earendil-works/pi-coding-agent). It adds a Claude Code–style confirmation flow before potentially impactful tool calls.

The extension intercepts Pi `tool_call` events before execution and applies `allow`, `ask`, or `deny` decisions from policy.

## Features

- Allows safe read-only tools by default.
- Asks before side-effectful tools such as `bash`, `write`, and `edit`.
- Prompts with tool name, action summary, target, risk level, and preview.
- Highlights high-risk shell commands such as `rm -rf`, `sudo`, `dd`, destructive chmods, and pipe-to-shell patterns.
- Raises risk for file operations outside the current project or in sensitive home paths.
- Denies system-directory operations by default.
- Supports remembered allow/deny decisions for exact action patterns.
- Supports global and project-local JSONC policy files.
- Provides a `/permissions` command for viewing/resetting remembered decisions and changing modes.

## Installation

### From npm

After this package is published to npm:

```bash
pi install npm:pi-ask-first
```

Or pin a version:

```bash
pi install npm:pi-ask-first@0.1.0
```

### From GitHub

```bash
pi install git:github.com/NikitaKolesov/pi-ask-first@v0.1.0
```


### From a local checkout

```bash
git clone https://github.com/NikitaKolesov/pi-ask-first.git
pi install ./pi-ask-first
```

### Manual install

Copy the extension into Pi's global extension directory:

```bash
mkdir -p ~/.pi/agent/extensions/ask-first
cp extensions/ask-first.ts ~/.pi/agent/extensions/ask-first/index.ts
```

Then restart Pi or run:

```text
/reload
```

## Usage

Once installed, ask Pi to perform a tool action, for example:

```text
Run pwd using bash
```

For actions that require approval, Pi will show a prompt with:

- tool name
- plain-language action summary
- target path/command/URL/tool
- risk level
- action preview

Choices:

- Allow once
- Deny once
- Always allow this exact action
- Always deny this exact action

Remembered decisions are stored in the project policy file at `.pi/permissions.jsonc`.

## Commands

```text
/permissions
```

Show the current default policy and number of remembered decisions.

```text
/permissions reset
```

Clear remembered allow/deny decisions.

```text
/permissions mode ask-first
```

Set the default policy to ask for unknown or side-effectful tools.

```text
/permissions mode strict
```

Ask for nearly everything, including `read`.

```text
/permissions mode permissive
```

Allow common actions by default, while still asking for `bash`, `write`, and `edit`.

## Configuration

Global policy file:

```text
~/.pi/agent/pi-permissions.jsonc
```

Project policy file:

```text
.pi/permissions.jsonc
```

Project policy overrides global policy.

Example:

```jsonc
{
  "defaultPolicy": "ask",
  "tools": {
    "read": "allow",
    "ls": "allow",
    "grep": "allow",
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

## Policy behavior

Default policy:

- `read`, `ls`, `grep`: allow
- `bash`, `write`, `edit`, `mcp`: ask
- unknown tools: ask
- outside-project paths: ask
- sensitive home paths: ask and high risk
- system directories: deny

High-risk actions are still prompted even if a broad policy would otherwise allow them.

## Development

Package layout:

```text
pi-ask-first/
  package.json
  README.md
  extensions/
    ask-first.ts
```

Test locally with:

```bash
pi -e ./extensions/ask-first.ts
```

Or install the local package:

```bash
pi install .
```

## Security caveats

This extension is a permission prompt, not a sandbox. Pi extensions run with your full user privileges and can execute arbitrary code. Only install extensions from sources you trust.

This extension also does not guarantee protection from malicious extensions or from all possible command encodings. Review high-risk prompts carefully.
