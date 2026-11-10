#!/usr/bin/env python3
"""Check the default-deny production feature isolation gate."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CARGO = ROOT / "kernel/Cargo.toml"
ALLOWLIST = ROOT / "kernel/production-features.txt"
BUILD = ROOT / "kernel/build.rs"
PRODUCTION = ROOT / "kernel/src/production.rs"
STATUS = ROOT / "docs/ISSUE-19-convergence-status.md"

REQUIRED = {"production", "default", "user-programs"}
CONFIGURATION_ONLY = {"profile-compact", "sched-rr"}


def fail(message: str) -> None:
    print(f"production-feature-isolation: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cargo_toml", nargs="?", default=str(CARGO))
    args = parser.parse_args()
    try:
        manifest = tomllib.loads(Path(args.cargo_toml).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(str(exc))
    features = manifest.get("features")
    if not isinstance(features, dict) or not features:
        fail("kernel feature table is missing")

    allowed = {
        line.strip()
        for line in ALLOWLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    if not REQUIRED.issubset(allowed):
        fail(f"production allowlist is missing {sorted(REQUIRED - allowed)}")
    if allowed != REQUIRED | CONFIGURATION_ONLY:
        fail(f"production allowlist unexpectedly changed: {sorted(allowed)}")
    unknown = allowed - set(features)
    if unknown:
        fail(f"production allowlist names unknown features: {sorted(unknown)}")
    if features.get("production") != []:
        fail("production must not enable dependencies or verification features")
    if features.get("default") != ["user-programs"]:
        fail("the default feature must contain only user-programs")

    build = BUILD.read_text(encoding="utf-8")
    for needle in (
        "enforce_production_feature_isolation(&root);",
        "CARGO_FEATURE_PRODUCTION",
        "kernel/production-features.txt",
        'name.starts_with("CARGO_FEATURE_")',
        "!allowed.contains(name)",
        "production feature isolation: forbidden features enabled",
    ):
        if needle not in build:
            fail(f"build gate lost {needle}")
    if "compile_error!(" in PRODUCTION.read_text(encoding="utf-8"):
        fail("production.rs must not keep a stale partial compile_error feature list")

    protected = sorted(set(features) - allowed)
    if STATUS.is_file():
        status = STATUS.read_text(encoding="utf-8")
        if f"default_denied={len(protected)}" not in status:
            fail("Issue #19 status does not match the protected feature count")
    print(
        "production-feature-isolation: PASS "
        f"allowed={len(allowed)} default_denied={len(protected)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
