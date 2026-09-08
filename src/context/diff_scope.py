import logging
import subprocess
from pathlib import Path
from typing import List, Optional, Set

from context.ast_context import ASTContextExtractor
from evidence.safe_reader import SafeReader


class DiffScopeAnalyzer:
    """
    Identifies changed files from git working tree, index or base branch,
    and expands the scope to closely related callers and dependencies.
    """

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root).resolve() if root else Path.cwd().resolve()
        self.reader = SafeReader(self.root)
        self.ast = ASTContextExtractor(self.root)

    def get_changed_files(
        self,
        base_ref: Optional[str] = None,
        include_untracked: bool = True
    ) -> List[str]:
        """
        Detect changed Python files relative to base_ref or working directory.
        """
        changed: Set[str] = set()

        try:
            import git
            repo = git.Repo(self.root, search_parent_directories=True)

            if base_ref:
                # Diff against base_ref
                diff_index = repo.commit(base_ref).diff(None)
                for d in diff_index:
                    if d.b_path and d.b_path.endswith(".py"):
                        changed.add(d.b_path.replace("\\", "/"))
                    elif d.a_path and d.a_path.endswith(".py"):
                        changed.add(d.a_path.replace("\\", "/"))
            else:
                # Working tree and staged changes against HEAD
                try:
                    head_commit = repo.head.commit
                    for d in head_commit.diff(None):
                        p = d.b_path or d.a_path
                        if p and p.endswith(".py"):
                            changed.add(p.replace("\\", "/"))
                    for d in repo.index.diff("HEAD"):
                        p = d.a_path or d.b_path
                        if p and p.endswith(".py"):
                            changed.add(p.replace("\\", "/"))
                except Exception:
                    # Initial repo with no commits yet
                    for item in repo.index.entries.keys():
                        path_str = item[0]
                        if path_str.endswith(".py"):
                            changed.add(path_str.replace("\\", "/"))

            if include_untracked:
                for untracked in repo.untracked_files:
                    if untracked.endswith(".py"):
                        changed.add(untracked.replace("\\", "/"))

        except Exception as e:
            logging.debug(f"Git diff failed, falling back to all python files: {e}")
            all_files = self.reader.list_python_files()
            return [self.reader.to_relative(p) for p in all_files]

        # Filter to files that actually exist and resolve inside root
        valid_changed = []
        for rel in sorted(changed):
            try:
                target = self.reader.resolve(rel)
                if target.is_file():
                    valid_changed.append(self.reader.to_relative(target))
            except Exception:
                continue

        return valid_changed

    def expand_scope(self, seed_files: List[str], max_extra_files: int = 5) -> List[str]:
        """
        Expand changed files by adding direct callers/importers within budget.
        """
        scope = set(seed_files)
        all_py = self.reader.list_python_files()

        # Build map of module names provided by seed files
        seed_modules = {
            Path(f).stem: f for f in seed_files
        }

        added = 0
        for py_file in all_py:
            rel = self.reader.to_relative(py_file)
            if rel in scope:
                continue
            try:
                ctx = self.ast.parse_file(rel)
                # Check if this file imports any seed module
                for imp in ctx.imports:
                    if imp.module in seed_modules or imp.name in seed_modules:
                        scope.add(rel)
                        added += 1
                        break
                if added >= max_extra_files:
                    break
            except Exception:
                continue

        return sorted(scope)
