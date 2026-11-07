#!/usr/bin/env python3
"""Validate issue #12 stage-A topology and heterogeneous-resource constraints."""

from __future__ import annotations

import pathlib
import tomllib


ROOT = pathlib.Path(__file__).resolve().parent.parent
MATRIX = ROOT / "verification/topology_constraints.toml"
DOC = ROOT / "docs/issue-12-拓扑与异构资源约束.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"topology constraints: FAIL: {message}")


def main() -> None:
    with MATRIX.open("rb") as source:
        matrix = tomllib.load(source)
    docs = DOC.read_text(encoding="utf-8")

    require(matrix.get("schema") == 1, "unsupported schema")
    require(matrix.get("baseline") == "04f7391", "unexpected baseline")
    require(matrix.get("scope") == "stage-a-research-contract", "scope must stay research-only")
    require(
        matrix.get("implementation_claim") == "current-modular-monolith-only",
        "must not claim a second kernel implementation",
    )

    identity = matrix.get("identity", {})
    required_scopes = {
        "hardware-cpu-id",
        "logical-cpu-id",
        "numa-domain",
        "device-id-generation",
        "memory-object-id",
        "remote-object-id",
    }
    require(set(identity.get("required_scopes", [])) == required_scopes, "identity scopes incomplete")
    require(identity.get("silent_truncation") == "forbidden", "silent truncation must be forbidden")
    require(identity.get("stale_identity") == "reject", "stale identity must be rejected")

    coordination = matrix.get("coordination", {})
    require(
        coordination.get("levels") == ["per-cpu", "local-domain", "cross-domain-or-node"],
        "coordination levels differ",
    )
    require(
        coordination.get("cross_node_memory") == "explicit-protocol-not-shared-pointer",
        "cross-node memory must remain explicit",
    )

    performance = matrix.get("performance", {})
    require(
        performance.get("required_quantiles")
        == ["p50", "p99", "p99.9", "p99.99", "max"],
        "tail-latency quantiles incomplete",
    )
    require(performance.get("complexity_does_not_imply_tail_latency") is True, "complexity claim missing")
    require(performance.get("fanout_distributions_separate") is True, "fanout distributions not separated")

    for item in matrix.get("source_constraints", []):
        path = ROOT / item["file"]
        require(path.is_file(), f"missing source file: {item['file']}")
        text = path.read_text(encoding="utf-8")
        for pattern in item.get("patterns", []):
            require(pattern in text, f"{item['id']}: source pattern missing: {pattern}")

    levels = matrix.get("capability_levels", [])
    require([item["id"] for item in levels] == ["U0", "U1", "U2", "U3", "U4"], "U0-U4 set incomplete")
    require(levels[0]["status"] == "partial" and all(item["status"] == "not-implemented" for item in levels[1:]),
            "memory capability status overclaims implementation")

    profiles = matrix.get("profiles", [])
    require({item["id"] for item in profiles} == {"cpu-hpc", "gpu-hpc", "service-node"}, "profile set incomplete")
    require(all(item["status"] == "research-only" for item in profiles), "research profiles must not be claimed implemented")

    rejections = {item["id"] for item in matrix.get("required_rejections", [])}
    require(len(rejections) >= 10, "refusal matrix too small")

    for topic in ("硬件标识", "逻辑 CPU ID", "NUMA", "GPU", "U0", "U1", "U2", "U3", "U4", "跨节点", "拒绝"):
        require(topic in docs, f"documentation lacks topic: {topic}")
    require("没有" in docs and "实现" in docs and "不得" in docs, "documentation lacks explicit non-claim/refusal language")

    print(
        "topology constraints: PASS "
        f"source_constraints={len(matrix.get('source_constraints', []))} "
        f"levels={len(levels)} profiles={len(profiles)} rejections={len(rejections)}"
    )


if __name__ == "__main__":
    main()
