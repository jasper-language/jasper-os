#!/usr/bin/env bash
# Author: chatgpt. VM-only builder for portable ARM userspace mechanism tests.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${PDA_OUT:?unique evidence directory required}
[[ "$out" =~ ^evidence/krn2/[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]
mkdir -p evidence/krn2
mkdir "$out"
manifest() {
  find kernel kernel-core user jaso modules xtask tools/jasopack abi .cargo scripts \
    -type d \( -name target -o -name __pycache__ \) -prune -o -type f -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum
  sha256sum Cargo.toml Cargo.lock rust-toolchain.toml tools/krn2/arm-tests-build.sh
}
manifest > "$out/source-before.sha256"
source "$HOME/.cargo/env"
export CARGO_BUILD_JOBS=1 CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
export RUSTFLAGS='-C target-feature=+crt-static'
{ rustc -Vv; cargo -V; printf 'target=aarch64-unknown-linux-musl\nlinker=rust-lld\nrustflags=%s\n' "$RUSTFLAGS"; } > "$out/build-config.txt"
rustup target add aarch64-unknown-linux-musl > "$out/target.log" 2>&1
cargo test --locked -p kernel-core --target aarch64-unknown-linux-musl --no-run --message-format=json > "$out/artifacts.json" 2> "$out/build.log"
python3 - "$out" <<'PY'
import json,pathlib,shutil,sys
out=pathlib.Path(sys.argv[1]);dest=out/'bin';dest.mkdir()
for line in (out/'artifacts.json').read_text().splitlines():
    x=json.loads(line)
    if x.get('reason')=='compiler-artifact' and x.get('profile',{}).get('test') and x.get('executable'):
        name=x['target']['name']; assert '/' not in name
        shutil.copy2(x['executable'],dest/name)
assert {'kernel_core','group_tick_index','pi_work_reference','s2_streams'} <= {p.name for p in dest.iterdir()}
PY
manifest > "$out/source-after-build.sha256"
cmp "$out/source-before.sha256" "$out/source-after-build.sha256"
sha256sum "$out"/bin/* > "$out/binaries.sha256"
