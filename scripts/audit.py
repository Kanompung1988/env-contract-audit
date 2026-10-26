#!/usr/bin/env python3
"""Audit documented environment-variable names against local Python and JS/TS usage.

Safe by construction: reads example files and source only, never reads .env values.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", ".next", ".nuxt", "coverage", "__pycache__", ".turbo", "vendor", "target"}
BUILTINS = {"NODE_ENV", "MODE", "DEV", "PROD", "SSR", "BASE_URL", "CI", "HOME", "PATH", "PWD", "SHELL", "USER", "TMPDIR", "GITHUB_ACTIONS"}
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*=")
JS_REFS = re.compile(r"(?<!\w)(?:(process\.env\.([A-Za-z_][A-Za-z_0-9]*))|(process\.env\[['\"]([A-Za-z_][A-Za-z_0-9]*)['\"]\])|(import\.meta\.env\.([A-Za-z_][A-Za-z_0-9]*)))")
SENSITIVE_PUBLIC = re.compile(r"(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL|API_KEY)(?:_|$)", re.I)
LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3}
MAX_FILE_BYTES = 512_000
MAX_FILES = 5000


@dataclass(frozen=True)
class Use:
    name: str
    path: str
    line: int
    optional: bool
    channel: str


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    name: str
    path: str
    line: int
    message: str
    remediation: str


def python_uses(source: str, path: str) -> list[Use]:
    tree = ast.parse(source, filename=path)
    found: list[Use] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            is_lookup = (isinstance(f, ast.Attribute) and f.attr == "getenv" and isinstance(f.value, ast.Name) and f.value.id == "os")
            is_lookup |= (isinstance(f, ast.Attribute) and f.attr == "get" and isinstance(f.value, ast.Attribute) and f.value.attr == "environ" and isinstance(f.value.value, ast.Name) and f.value.value.id == "os")
            if is_lookup and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                name = node.args[0].value
                fallback = len(node.args) >= 2 and not (isinstance(node.args[1], ast.Constant) and node.args[1].value is None)
                found.append(Use(name, path, node.lineno, fallback, "python"))
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name) and node.value.value.id == "os" and node.value.attr == "environ":
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                found.append(Use(node.slice.value, path, node.lineno, False, "python"))
    return found


def js_uses(source: str, path: str) -> list[Use]:
    results: list[Use] = []
    for num, line in enumerate(source.splitlines(), 1):
        # Line-based static matching: does not parse JS syntax or string/comment context.
        for hit in JS_REFS.finditer(line):
            name = next((group for group in (hit.group(2), hit.group(4), hit.group(6)) if group), "")
            following = line[hit.end():]
            optional = bool(re.match(r"\s*(?:\?\?|\|\|)", following))
            results.append(Use(name, path, num, optional, "vite" if hit.group(6) else "node"))
    return results


def is_example(path: Path) -> bool:
    basename = path.name
    return basename in {".env.example", ".env.sample", ".env.template"} or basename.endswith((".env.example", ".env.sample", ".env.template")) or basename.startswith(".env.example.")


def walk_source(root: Path) -> tuple[list[Path], list[Path]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Input must be a directory, not a symlink")
    source_files: list[Path] = []
    examples: list[Path] = []
    n = 0
    for path in root.rglob("*"):
        if len(set(path.relative_to(root).parts) & IGNORED_DIRS) or path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() in SOURCE_EXTENSIONS:
            source_files.append(path)
            n += 1
        elif is_example(path):
            examples.append(path)
            n += 1
        if n > MAX_FILES:
            raise ValueError("Too many eligible files (limit 5000)")
    return sorted(source_files), sorted(examples)


def parse_example(source: str, path: str) -> tuple[dict[str, int], list[Finding]]:
    declared: dict[str, int] = {}
    duplicates: list[Finding] = []
    for lineno, line in enumerate(source.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        m = ENV_LINE.match(line)
        if m:
            name = m.group(1)
            if name in declared:
                duplicates.append(Finding("ENV004", "low", name, path, lineno, "Example defines the same key more than once", "Keep one documented definition per example file."))
            declared[name] = lineno
    return declared, duplicates


def analyze(root: Path, *, check_unused: bool = False) -> list[Finding]:
    sources, examples = walk_source(root)
    uses: list[Use] = []
    declarations: dict[str, tuple[str, int]] = {}
    findings: list[Finding] = []
    for path in sources:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"Oversized source file: {path.relative_to(root)}")
        rel = path.relative_to(root).as_posix()
        content = path.read_text(encoding="utf-8")
        try:
            uses.extend(python_uses(content, rel) if path.suffix.lower() == ".py" else js_uses(content, rel))
        except SyntaxError as exc:
            raise ValueError(f"Python source parsing failed: {rel}:{exc.lineno}: {exc.msg}") from exc
    for path in examples:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"Oversized env example: {path.relative_to(root)}")
        rel = path.relative_to(root).as_posix()
        found, duplicates = parse_example(path.read_text(encoding="utf-8"), rel)
        findings.extend(duplicates)
        for name, lineno in found.items():
            declarations.setdefault(name, (rel, lineno))
    ref_uses = {u.name for u in uses if u.name not in BUILTINS}
    if ref_uses and not examples:
        findings.append(Finding("ENV001", "medium", "", ".", 1, "Source references env keys but no .env.example / .env.sample / .env.template exists", "Create a placeholder-only example file; never commit live credentials."))
    seen_missing: set[str] = set()
    for use in sorted(uses, key=lambda x: (x.path, x.line, x.name)):
        if use.name in BUILTINS or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", use.name):
            continue
        if use.name not in declarations and use.name not in seen_missing:
            findings.append(Finding("ENV002", "low" if use.optional else "high", use.name, use.path, use.line, "Referenced key is absent from env examples", "Document this variable with a placeholder and whether it is required; do not copy real values."))
            seen_missing.add(use.name)
        if use.channel in ("vite", "node") and use.name.startswith(("VITE_", "NEXT_PUBLIC_", "PUBLIC_")) and SENSITIVE_PUBLIC.search(use.name):
            findings.append(Finding("ENV003", "high", use.name, use.path, use.line, "Publicly exposed variable name looks secret-like", "Check the bundler public prefix policy and move sensitive credentials server-side; name-only heuristic."))
    if check_unused:
        for name, (rel, line) in sorted(declarations.items()):
            if name not in ref_uses:
                findings.append(Finding("ENV005", "info", name, rel, line, "Documented key not found in supported static source patterns", "Confirm this is consumed in config, templates, scripts, or external services before deleting."))
    return sorted(findings, key=lambda x: (x.path, x.line, x.rule, x.name))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("repo", nargs="?", default=".", help="repository root")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--check-unused", action="store_true", help="also report unreferenced documented example keys")
    p.add_argument("--fail-on", choices=["none", "medium", "high"], default="high")
    args = p.parse_args(argv)
    try:
        result = analyze(Path(args.repo), check_unused=args.check_unused)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Env contract audit error: {exc}", file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps({"findings": [asdict(f) for f in result], "count": len(result), "note": "Key names only; dynamic references not supported."}, indent=2))
    else:
        print("# Environment contract audit\n")
        for f in result:
            print(f"- **{f.severity.upper()} {f.rule}** `{f.path}:{f.line}` ({f.name or 'docs'}): {f.message}. {f.remediation}")
        if not result:
            print("No supported drift patterns found (not proof of deployment correctness).")
        print(f"\nFindings: {len(result)}. No real .env files or secret values were read.")
    return 2 if args.fail_on != "none" and any(LEVELS[f.severity] >= LEVELS[args.fail_on] for f in result) else 0


if __name__ == "__main__":
    raise SystemExit(main())
