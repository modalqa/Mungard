# Claude Code example

- `.mcp.json`: connects Claude Code to the Mungard MCP server (copy to your project root, or run `claude mcp add --scope project mungard -- mungard mcp serve`).
- `settings.json`: enables Mungard Guard as a `PreToolUse` hook and adds deny rules that stop the agent from approving its own requests or touching `.mungard/`. Merge it into `.claude/settings.json`.

Example prompts:

- "Plan a security assessment for this project and run the static checks."
- "Inspect our MCP configuration and explain the risks."
- "Can a member read another member's invoices? Use the configured test accounts."
- "Propose a fix for MG-XXXXXXXXXX, then retest it after I apply it."
