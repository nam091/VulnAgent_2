import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


CURSOR_RULES_CONTENT = """# VulnAgent Security Guidelines for AI Coding

When writing or editing Python code:
1. After editing code that handles user input, database queries, file access, or system commands, call `scan_changes` via the VulnAgent MCP server.
2. For each candidate finding returned:
   - Call `get_finding_context(scan_id, finding_id)` to view AST scope and initial evidence.
   - If needed, call `read_evidence(scan_id, path, start_line, end_line)` to inspect upstream sanitizers or authenticators.
   - If safe: call `submit_assessment(scan_id, finding_id, verdict='refuted', mitigating_control='...', evidence_ids=[...])`.
   - If vulnerable: repair the defect using secure standard patterns (e.g. parameterized queries, path containment check, shlex.quote).
3. Call `check_fix(scan_id, finding_ids=[...])` to ensure the vulnerability is resolved and no regressions were introduced.
"""

CLAUDE_CODE_INSTRUCTIONS = """VulnAgent MCP Integration:
- Use `scan_changes` to identify security candidates in modified Python files.
- Inspect context with `get_finding_context` and `read_evidence`.
- Submit verified verdicts with `submit_assessment`.
- Verify repairs with `check_fix`.
"""


class HostAdapter:
    """
    Configures host environments (Cursor, Claude Code, CLI) to integrate
    VulnAgent seamlessly via MCP without requiring host API keys in the backend.
    """

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root).resolve() if root else Path.cwd().resolve()

    def detect_host(self) -> str:
        """
        Detect whether workspace is configured for Cursor or Claude Code.
        """
        if (self.root / ".cursor").exists() or (self.root / ".cursorrules").exists():
            return "cursor"
        if (self.root / ".claude").exists():
            return "claude"
        return "cursor"  # default target for MVP

    def configure_cursor(self) -> Dict[str, Any]:
        """
        Configure Cursor MCP server and security rules without overwriting existing settings.
        """
        cursor_dir = self.root / ".cursor"
        cursor_dir.mkdir(parents=True, exist_ok=True)
        mcp_config_path = cursor_dir / "mcp.json"

        config: Dict[str, Any] = {"mcpServers": {}}
        if mcp_config_path.is_file():
            try:
                config = json.loads(mcp_config_path.read_text(encoding="utf-8"))
            except Exception:
                config = {"mcpServers": {}}

        python_exec = sys.executable
        server_script = str((Path(__file__).resolve().parents[1] / "mcp_server.py").as_posix())

        config.setdefault("mcpServers", {})["vulnagent"] = {
            "command": python_exec,
            "args": [server_script],
            "env": {
                "PYTHONPATH": str(Path(__file__).resolve().parents[1].as_posix())
            }
        }

        # Backup existing if present
        if mcp_config_path.exists():
            shutil.copy2(mcp_config_path, mcp_config_path.with_suffix(".json.bak"))

        mcp_config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

        # Write .cursorrules if not present
        cursor_rules = self.root / ".cursorrules"
        if not cursor_rules.exists():
            cursor_rules.write_text(CURSOR_RULES_CONTENT, encoding="utf-8")

        return {
            "mcp_config": str(mcp_config_path),
            "rules_file": str(cursor_rules),
            "configured": True,
        }

    def configure_claude_code(self) -> Dict[str, Any]:
        """
        Configure Claude Code MCP settings.
        """
        claude_dir = self.root / ".claude"
        claude_dir.mkdir(parents=True, exist_ok=True)
        config_path = claude_dir / "mcp.json"

        config: Dict[str, Any] = {"mcpServers": {}}
        if config_path.is_file():
            try:
                config = json.loads(config_path.read_text(encoding="utf-8"))
            except Exception:
                config = {"mcpServers": {}}

        python_exec = sys.executable
        server_script = str((Path(__file__).resolve().parents[1] / "mcp_server.py").as_posix())

        config.setdefault("mcpServers", {})["vulnagent"] = {
            "command": python_exec,
            "args": [server_script],
            "env": {
                "PYTHONPATH": str(Path(__file__).resolve().parents[1].as_posix())
            }
        }

        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

        instructions_path = claude_dir / "CLAUDE.md"
        if not instructions_path.exists():
            instructions_path.write_text(CLAUDE_CODE_INSTRUCTIONS, encoding="utf-8")

        return {
            "mcp_config": str(config_path),
            "instructions": str(instructions_path),
            "configured": True,
        }
