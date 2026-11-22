#!/usr/bin/env python3
"""Validate the fail-closed Darling research matrix.

This route is explicitly research-only under Issues #31, #55 and #56. The
checker accepts regression documentation; it never promotes Darling to an
official Jasper-OS compatibility target.
"""

from __future__ import annotations

import copy
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "verification/darling-research.toml"

POLICY_ISSUES = [31, 55, 56]
RELEASE = {
    "release_tag": "v0.1.20260608",
    "release_commit": "e947f0d5a3c6bba27e3631d9bf0da2a9840e6894",
    "license": "GPL-3.0",
    "license_sha256": "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903",
    "source_asset": "darling-source.tar.xz",
    "source_sha256": "4fc9eb9a94af2aa396d4fafa0b6bbf0bcd7e210170854d143c080de3b5bb8df7",
    "source_bytes": 505807588,
    "debs_asset": "debs_20260608.zip",
    "debs_sha256": "27469ef3932da2e91dd7fb34b70e3628a3e54b7af9fb5480051f44af35eca1fd",
    "debs_bytes": 118018438,
}
ENVIRONMENTS = {
    "linux-host-baseline": ("host-only", "host-passed"),
    "jasper-qemu-x86_64": ("jasper-guest", "not-run"),
    "pixel6a-aarch64": ("physical-hardware", "inapplicable"),
}
STAGES = {
    "container-launch",
    "mldr-macho-load",
    "dyld-libsystem",
    "darlingserver-rpc",
    "linux-abi-dependencies",
    "vchroot-filesystem",
    "threads-tls-signals",
    "gui-windowserver",
    "metal-vulkan",
    "resource-security",
}
STAGE_STATUSES = {"not-run", "passed", "blocked"}


class ValidationError(ValueError):
    """The research matrix makes an unsafe or unsupported claim."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _repo_file(path: str) -> Path:
    candidate = (ROOT / path).resolve()
    require(candidate.is_relative_to(ROOT), f"evidence path escapes repository: {path}")
    return candidate


def validate(matrix: dict[str, Any]) -> tuple[int, int]:
    require(matrix.get("schema") == 1, "schema must be 1")
    require(matrix.get("route") == "darling", "route must be darling")
    require(matrix.get("status") == "research-only", "status must remain research-only")
    require(matrix.get("official_support") is False, "Darling cannot claim official support")
    require(matrix.get("kernel_darwin_abi") is False, "Darling cannot add a kernel Darwin ABI")
    require(matrix.get("dag_dependency") is False, "Darling cannot be inserted as a DAG dependency")
    require(matrix.get("policy_issues") == POLICY_ISSUES, "policy issue set must be #31/#55/#56")

    upstream = matrix.get("upstream", {})
    for key, expected in RELEASE.items():
        require(upstream.get(key) == expected, f"upstream {key} mismatch")
    require(
        upstream.get("architecture") == "amd64-x86_64-only",
        "pinned Darling release must remain x86-64 only",
    )
    require(
        upstream.get("submodule_policy") == "individual-license-review-required",
        "submodule licensing must remain a review gate",
    )
    upstream_evidence = upstream.get("audit_evidence")
    require(isinstance(upstream_evidence, str), "upstream evidence path is missing")
    require(
        _repo_file(upstream_evidence).is_file(),
        "upstream release audit evidence is missing",
    )

    environments = {item.get("id"): item for item in matrix.get("environment", [])}
    require(set(environments) == set(ENVIRONMENTS), "environment set mismatch")
    for ident, (scope, status) in ENVIRONMENTS.items():
        item = environments[ident]
        require(item.get("scope") == scope, f"{ident} must remain {scope}")
        require(item.get("status") == status, f"{ident} must remain {status}")
        evidence = item.get("evidence")
        require(isinstance(evidence, str), f"{ident} evidence must be a string")
        if status in {"host-passed", "passed"}:
            require(bool(evidence), f"{ident} pass requires repository evidence")
            path = _repo_file(evidence)
            require(path.is_file(), f"{ident} evidence file is missing")
            marker = item.get("marker")
            require(isinstance(marker, str) and bool(marker), f"{ident} needs a marker")
            require(marker in path.read_text(encoding="utf-8"), f"{ident} marker is absent")

    host_text = (ROOT / environments["linux-host-baseline"]["evidence"]).read_text(
        encoding="utf-8"
    )
    require(
        "No Darling result is claimed for Jasper yet." in host_text,
        "host evidence must explicitly separate Jasper guest execution",
    )

    stages = {item.get("id"): item for item in matrix.get("stage", [])}
    require(set(stages) == STAGES, "Darling stage set mismatch")
    for ident, item in stages.items():
        status = item.get("status")
        require(status in STAGE_STATUSES, f"{ident} has invalid status {status!r}")
        require(bool(item.get("requirements")), f"{ident} lacks prerequisites")
        require(bool(item.get("exit_gate")), f"{ident} lacks an exit gate")
        evidence = item.get("evidence")
        require(isinstance(evidence, str), f"{ident} evidence must be a string")
        if status == "passed":
            raise ValidationError(
                f"{ident} cannot pass: no reviewed Jasper guest run is recorded"
            )
        if evidence:
            path = _repo_file(evidence)
            require(path.is_file(), f"{ident} evidence file is missing")

    protocol = matrix.get("evidence_protocol", {})
    marker = protocol.get("guest_success_marker")
    require(marker == "DARLING_JASPER_GUEST_OK", "guest success marker is not frozen")
    if any(item.get("status") == "passed" for item in stages.values()):
        require(False, "guest stages require an explicitly audited evidence protocol")

    blockers = matrix.get("blocker", [])
    blocker_ids = {item.get("id") for item in blockers}
    require(
        blocker_ids
        == {
            "policy-excluded",
            "architecture",
            "host-privileges",
            "runtime-stack",
            "licensing",
        },
        "required Darling blockers are missing",
    )
    for item in blockers:
        require(bool(item.get("reason")), f"blocker {item.get('id')} lacks a reason")

    claims = matrix.get("claim_boundary", {})
    allowed = " ".join(claims.get("allowed", []))
    forbidden = " ".join(claims.get("forbidden", []))
    for phrase in ("release metadata", "host baseline", "enumerated"):
        require(phrase in allowed, f"allowed claim boundary lacks {phrase}")
    for phrase in (
        "officially supports Darling",
        "native Darwin ABI",
        "Jasper guest",
        "Metal2Vulkan compute success",
    ):
        require(phrase in forbidden, f"forbidden claim boundary lacks {phrase}")
    return len(environments), len(stages)


def self_test(matrix: dict[str, Any]) -> None:
    validate(matrix)

    forged_support = copy.deepcopy(matrix)
    forged_support["official_support"] = True
    try:
        validate(forged_support)
    except ValidationError:
        pass
    else:
        raise AssertionError("official Darling support was accepted")

    forged_pass = copy.deepcopy(matrix)
    forged_pass["stage"][0]["status"] = "passed"
    try:
        validate(forged_pass)
    except ValidationError:
        pass
    else:
        raise AssertionError("unexecuted Jasper guest stage was accepted")

    forged_digest = copy.deepcopy(matrix)
    forged_digest["upstream"]["debs_sha256"] = "0" * 64
    try:
        validate(forged_digest)
    except ValidationError:
        pass
    else:
        raise AssertionError("modified Darling release digest was accepted")

    forged_support_text = copy.deepcopy(matrix)
    forged_support_text["upstream"]["audit_evidence"] = "docs/missing.md"
    try:
        validate(forged_support_text)
    except ValidationError:
        pass
    else:
        raise AssertionError("missing upstream evidence was accepted")

    print("darling-research: self-test PASS")


def main() -> int:
    try:
        matrix = tomllib.loads(MATRIX.read_text(encoding="utf-8"))
        environments, stages = validate(matrix)
        if "--self-test" in sys.argv[1:]:
            self_test(matrix)
    except (OSError, tomllib.TOMLDecodeError, ValidationError, AssertionError) as error:
        print(f"darling-research: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "darling-research: PASS "
        f"status=research-only environments={environments} "
        f"stages={stages} jasper_guest_passed=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
