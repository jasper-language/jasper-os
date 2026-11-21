#!/usr/bin/env python3
"""Check the normative Trust Framework v1 boundary.

This checks specification presence and versioned message coverage. It does not
claim that a protocol implementation or hardware attester exists.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs/TRUST-FRAMEWORK-SPEC.md"
CDDL = ROOT / "trust/schema/v1/trust.cddl"
MANIFEST = ROOT / "verification/trust-framework-spec.toml"

DOC_TOKENS = (
    "Attester",
    "Evidence Collector",
    "Attestation Broker",
    "Verifier",
    "Relying Party",
    "software-observation",
    "signed-static-package",
    "protected-system-measurement",
    "hardware-backed",
    "audience",
    "nonce",
    "generation",
    "撤销",
    "最小披露",
    "RATS",
    "EAT",
    "不新增 system ABI",
)
CDDL_DEFINITIONS = (
    "challenge = {",
    "evidence = {",
    "result = {",
    "provider-catalog = {",
    "policy-result = {",
    "trust-error = {",
)
CDDL_MESSAGES = (
    "trust.challenge/v1",
    "trust.evidence/v1",
    "trust.result/v1",
    "trust.provider/v1",
    "trust.policy/v1",
    "trust.error/v1",
)
PASSED_ACCEPTANCE = {
    "roles-and-authority",
    "versioned-evidence-protocol",
    "freshness-replay-revocation",
    "privacy-and-bounded-input",
    "rats-eat-mapping",
    "kernel-abi-boundary",
}
PENDING_ACCEPTANCE = {
    "software-evidence-vertical",
    "hardware-attestation",
}


def validate(spec: str, cddl: str, manifest: dict) -> list[str]:
    errors = []
    for token in DOC_TOKENS:
        if token not in spec:
            errors.append(f"specification is missing {token!r}")
    for definition in CDDL_DEFINITIONS:
        if definition not in cddl:
            errors.append(f"CDDL is missing {definition!r}")
    for message in CDDL_MESSAGES:
        if message not in cddl:
            errors.append(f"CDDL is missing message {message!r}")

    if manifest.get("schema") != 1 or manifest.get("stage") != "TRUST-FRAMEWORK-SPEC-1":
        errors.append("manifest schema/stage is invalid")
    acceptance = manifest.get("acceptance")
    if not isinstance(acceptance, list):
        errors.append("manifest acceptance table is missing")
        return errors
    states = {
        item.get("id"): item.get("state")
        for item in acceptance
        if isinstance(item, dict)
    }
    for item in PASSED_ACCEPTANCE:
        if states.get(item) != "passed":
            errors.append(f"acceptance {item!r} must be passed")
    for item in PENDING_ACCEPTANCE:
        if states.get(item) != "pending":
            errors.append(f"acceptance {item!r} must remain pending")
    return errors


def load() -> tuple[str, str, dict]:
    return (
        SPEC.read_text(encoding="utf-8"),
        CDDL.read_text(encoding="utf-8"),
        tomllib.loads(MANIFEST.read_text(encoding="utf-8")),
    )


def self_test() -> None:
    spec, cddl, manifest = load()
    assert not validate(spec, cddl, manifest)
    assert validate(spec.replace("hardware-backed", "", 1), cddl, manifest)
    assert validate(spec, cddl.replace("trust-error = {", "", 1), manifest)
    broken = dict(manifest)
    broken["acceptance"] = [
        dict(item, state="passed")
        if item.get("id") in PENDING_ACCEPTANCE
        else item
        for item in manifest["acceptance"]
    ]
    assert validate(spec, cddl, broken)
    print("trust-framework-spec: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    spec, cddl, manifest = load()
    errors = validate(spec, cddl, manifest)
    if errors:
        for error in errors:
            print(f"trust-framework-spec: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "trust-framework-spec: PASS "
        f"messages={len(CDDL_MESSAGES)} passed={len(PASSED_ACCEPTANCE)} "
        f"pending={len(PENDING_ACCEPTANCE)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
