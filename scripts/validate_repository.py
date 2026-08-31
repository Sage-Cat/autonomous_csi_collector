#!/usr/bin/env python3
from __future__ import annotations
import sys
import tomllib
from pathlib import Path

from check_public_tree import validate_public_tree

REQUIRED = {"schema_version", "mean_id", "canonical_name", "implementation_surface", "practical_contract"}
def main() -> int:
    root = Path(__file__).resolve().parents[1]; errors = []
    try: metadata = tomllib.loads((root / "mean.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc: errors.append(f"invalid mean.toml: {exc}"); metadata = {}
    if set(metadata) != REQUIRED or metadata.get("schema_version") != 1: errors.append("mean.toml must use compact schema_version = 1")
    surface = metadata.get("implementation_surface")
    if not isinstance(surface, str) or not (root / surface).is_dir(): errors.append("implementation_surface must resolve to a directory")
    try:
        errors.extend(validate_public_tree(root))
    except ValueError as exc:
        errors.append(f"public-release check error: {exc}")
    if errors: print("\n".join(errors), file=sys.stderr); return 1
    print("repository validation passed"); return 0
if __name__ == "__main__": raise SystemExit(main())
