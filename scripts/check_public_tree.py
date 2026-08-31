#!/usr/bin/env python3
"""Check the configured public-release boundary against Git-tracked paths."""
from __future__ import annotations

import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

CONFIG_NAME = "public-release.toml"


@dataclass(frozen=True)
class TrackedPathPolicy:
    forbidden_directory_prefixes: frozenset[str]
    forbidden_exact_paths: frozenset[str]


def _validate_path(value: object, *, directory_prefix: bool) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("configured paths must be non-empty strings")
    if directory_prefix != value.endswith("/"):
        suffix = "end with '/'" if directory_prefix else "not end with '/'"
        raise ValueError(f"configured path must {suffix}: {value!r}")
    normalized = value[:-1] if directory_prefix else value
    if "\\" in normalized or normalized.startswith("/") or "//" in normalized:
        raise ValueError(f"configured path is not a canonical relative path: {value!r}")
    if any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise ValueError(f"configured path is not a canonical relative path: {value!r}")
    return value


def _validated_path_set(values: object, *, directory_prefix: bool) -> frozenset[str]:
    if not isinstance(values, list):
        raise ValueError("configured path collections must be arrays")
    paths = [_validate_path(value, directory_prefix=directory_prefix) for value in values]
    if len(paths) != len(set(paths)):
        raise ValueError("configured path collections must not contain duplicates")
    return frozenset(paths)


def load_policy(config_path: Path) -> TrackedPathPolicy:
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"invalid {CONFIG_NAME}: {exc}") from exc
    if set(data) != {"schema_version", "tracked_path_policy"} or data["schema_version"] != 1:
        raise ValueError(f"{CONFIG_NAME} must use schema_version = 1")
    section = data["tracked_path_policy"]
    if not isinstance(section, dict) or set(section) != {
        "forbidden_directory_prefixes",
        "forbidden_exact_paths",
    }:
        raise ValueError(f"{CONFIG_NAME} must define only the tracked_path_policy fields")
    return TrackedPathPolicy(
        forbidden_directory_prefixes=_validated_path_set(
            section["forbidden_directory_prefixes"], directory_prefix=True
        ),
        forbidden_exact_paths=_validated_path_set(
            section["forbidden_exact_paths"], directory_prefix=False
        ),
    )


def tracked_paths(root: Path) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(f"cannot enumerate tracked paths: {message}")
    return tuple(path.decode("utf-8") for path in result.stdout.split(b"\0") if path)


def validate_tracked_paths(policy: TrackedPathPolicy, paths: tuple[str, ...]) -> list[str]:
    violations = sorted(
        path
        for path in paths
        if path in policy.forbidden_exact_paths
        or any(path.startswith(prefix) for prefix in policy.forbidden_directory_prefixes)
    )
    return [f"public-release policy forbids tracked path: {path}" for path in violations]


def validate_public_tree(root: Path) -> list[str]:
    return validate_tracked_paths(load_policy(root / CONFIG_NAME), tracked_paths(root))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        errors = validate_public_tree(root)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("public tree validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
