#!/usr/bin/env bash
# Build the browser TLSNotary wasm bundle from tlsn's own `crates/wasm` at the
# SAME revision this workspace pins for the Rust `tlsn` dependency.
#
# Self-contained on purpose: this is the ONE script, and it has to work for a
# developer on a laptop and on a CI runner. It installs what it can and fails
# with a specific instruction when it cannot.
#
# Why build rather than take `tlsn-js` from npm: the published package is an
# older build whose Prover has no `set_progress_callback`, which browser
# prover workers call. Shipping the npm build instead makes platform linking
# die at "Notarizing sessions" with
#   w.set_progress_callback is not a function
# The assert near the end of this script is what stops that happening.
#
# Usage:
#   ./scripts/build-tlsn-wasm.sh [--out <dir>]     (TLSN_WASM_FORCE=1 to rebuild)
#
# Outputs tlsn_wasm.js, tlsn_wasm_bg.wasm and spawn.js into the --out dir
# (default: tlsn-wasm/ in the repo root; gitignored). Set TLSN_WASM_CACHE to
# relocate the tlsn checkout + cargo target dir (default: system temp).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/tlsn-wasm"
while [ $# -gt 0 ]; do
    case "$1" in
        --out)
            OUT_DIR="${2:?--out needs a directory}"
            shift 2
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            echo "usage: $0 [--out <dir>]" >&2
            exit 2
            ;;
    esac
done
# Checkout + cargo target dir live outside the repo, so a rebuild is cheap and
# nothing untracked lands in the working tree.
CACHE_DIR="${TLSN_WASM_CACHE:-${TMPDIR:-/tmp}/libid-tlsn-wasm}"
IN_CI="${CI:-}"

# This crate is far too slow to rebuild casually, so a bundle that is already
# staged AND carries the symbol we need is accepted as-is.
if [ -z "${TLSN_WASM_FORCE:-}" ] \
   && [ -f "$OUT_DIR/tlsn_wasm_bg.wasm" ] \
   && grep -q "set_progress_callback" "$OUT_DIR/tlsn_wasm.js" 2>/dev/null; then
    echo "[tlsn-wasm] already staged — skipping (TLSN_WASM_FORCE=1 to rebuild)"
    exit 0
fi

# ONE source of truth for the revision: the pin this workspace's Cargo.lock
# already resolved (it arrives via libid-tlsn and the direct dependency, which
# cargo unifies), so the browser prover and the notary cannot drift onto
# different tlsn versions. The lock line looks like:
#   source = "git+https://github.com/tlsnotary/tlsn?rev=<sha>#<sha>"
TLSN_REV="$(sed -nE 's|^source = "git\+https://github\.com/tlsnotary/tlsn\?rev=([0-9a-f]+)#.*|\1|p' "$REPO_ROOT/Cargo.lock" | sort -u)"
if [ -z "$TLSN_REV" ]; then
    echo "ERROR: could not read the tlsn rev from Cargo.lock."
    echo '       Expected: source = "git+https://github.com/tlsnotary/tlsn?rev=<sha>#..."'
    exit 1
fi
if [ "$(wc -l <<<"$TLSN_REV")" -ne 1 ]; then
    echo "ERROR: Cargo.lock pins more than one tlsn rev:"
    echo "$TLSN_REV"
    echo "       The direct tlsn dependency and libid-tlsn's pin have diverged."
    exit 1
fi

# rustup's bin must come FIRST: some CI images ship a non-rustup cargo that
# cannot add targets, and if that one wins the build fails confusingly.
export PATH="$HOME/.cargo/bin:$PATH"

if ! command -v rustup >/dev/null 2>&1; then
    if [ -z "$IN_CI" ]; then
        echo "ERROR: rustup not found. Install: https://rustup.rs"
        exit 1
    fi
    echo "[tlsn-wasm] installing Rust toolchain (rustup)…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# tlsn's crate ships a rust-toolchain file pinning nightly + rust-src + wasm32.
# rustup honours it automatically, but the components have to exist first.
echo "[tlsn-wasm] ensuring nightly + rust-src + wasm32-unknown-unknown…"
rustup toolchain install nightly --component rust-src --target wasm32-unknown-unknown

if ! command -v wasm-pack >/dev/null 2>&1; then
    if [ -z "$IN_CI" ]; then
        echo "ERROR: wasm-pack not found."
        echo "       Install: cargo install wasm-pack --version 0.15.0 --locked"
        exit 1
    fi
    echo "[tlsn-wasm] installing pinned wasm-pack 0.15.0…"
    cargo install wasm-pack --version 0.15.0 --locked
fi

# `ring` compiles C for wasm32. A clang without that backend fails deep inside
# cc-rs with "unable to create target", which names nothing useful — so detect it
# here and say what to do.
find_wasm_clang() {
    [ -n "${CC_wasm32_unknown_unknown:-}" ] && return 0
    for c in "$(command -v clang || true)" \
             "$( (brew --prefix llvm 2>/dev/null || true) )/bin/clang" \
             /usr/lib/llvm-*/bin/clang; do
        [ -x "$c" ] || continue
        if "$c" --print-targets 2>/dev/null | grep -qi wasm32; then
            export CC_wasm32_unknown_unknown="$c"
            # Only pin the archiver if one actually exists. Distros ship it
            # versioned (llvm-ar-14) rather than bare, so deriving the path from
            # clang's directory yields a file that is not there and cc-rs fails
            # with `failed to find tool "/usr/bin/llvm-ar"`. Leaving it unset lets
            # cc-rs resolve an archiver itself, which works on every runner tried.
            for ar in "$(dirname "$c")/llvm-ar" "$(command -v llvm-ar || true)"; do
                if [ -x "$ar" ]; then
                    export AR_wasm32_unknown_unknown="$ar"
                    break
                fi
            done
            return 0
        fi
    done
    return 1
}

if ! find_wasm_clang && [ -n "$IN_CI" ] && [ "$(uname -s)" = "Linux" ]; then
    echo "[tlsn-wasm] installing clang with a wasm32 target…"
    (sudo apt-get update -qq && sudo apt-get install -y -qq clang lld) || true
    find_wasm_clang || true
fi

if [ -z "${CC_wasm32_unknown_unknown:-}" ]; then
    echo "ERROR: no clang with a wasm32-unknown-unknown target found."
    echo "       'ring' compiles C for that target; Apple's system clang cannot."
    echo "       Linux:  apt-get install -y clang lld"
    echo "       macOS:  brew install llvm   (NOTE: on a non-standard Homebrew"
    echo "               prefix there is no bottle and this builds LLVM from"
    echo "               source, which takes hours — prefer building in CI.)"
    echo "       Or set CC_wasm32_unknown_unknown to a suitable clang."
    exit 1
fi
echo "[tlsn-wasm] wasm clang: $CC_wasm32_unknown_unknown"

mkdir -p "$CACHE_DIR"
SRC="$CACHE_DIR/tlsn"
if [ ! -d "$SRC/.git" ]; then
    mkdir -p "$SRC"
    git -C "$SRC" init -q
    git -C "$SRC" remote add origin https://github.com/tlsnotary/tlsn.git
fi
if [ "$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo none)" != "$TLSN_REV" ]; then
    echo "[tlsn-wasm] fetching tlsn @ $TLSN_REV"
    git -C "$SRC" fetch -q --depth 1 origin "$TLSN_REV"
    git -C "$SRC" checkout -q FETCH_HEAD
fi

echo "[tlsn-wasm] building (large MPC crate; the first build is slow)…"
# Use the crate's own build.sh: it applies post-processing we depend on, notably
# rewriting the spawn.js snippet's import to ../../../tlsn_wasm.js and copying it
# to the package root — consumers serve tlsn_wasm.js and spawn.js side by side
# and rewrite /:path+/spawn.js to the root copy.
#
# RUSTFLAGS is cleared deliberately: an ambient value (CI sets -D warnings)
# OVERRIDES the crate's .cargo/config.toml rustflags, which carry the
# +atomics,+bulk-memory,+mutable-globals wasm features web-spawn requires.
(cd "$SRC/crates/wasm" && env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
    CARGO_TARGET_DIR="$CACHE_DIR/target" sh build.sh)

PKG="$SRC/crates/wasm/pkg"
for f in tlsn_wasm.js tlsn_wasm_bg.wasm spawn.js; do
    if [ ! -f "$PKG/$f" ]; then
        echo "ERROR: expected $f in $PKG after the build; the crate layout changed."
        ls -la "$PKG" || true
        exit 1
    fi
done

# The guarantee that matters. A bundle without this symbol is the npm build, not
# this one, and shipping it breaks platform linking at runtime with an error
# that points nowhere near the cause.
if ! grep -q "set_progress_callback" "$PKG/tlsn_wasm.js"; then
    echo "ERROR: built tlsn_wasm.js has no set_progress_callback."
    echo "       Browser prover workers call it. Refusing to stage a bundle"
    echo "       that would fail at 'Notarizing sessions'."
    exit 1
fi

mkdir -p "$OUT_DIR"
cp "$PKG/tlsn_wasm.js" "$PKG/tlsn_wasm_bg.wasm" "$PKG/spawn.js" "$OUT_DIR/"

echo ""
echo "[tlsn-wasm] staged from tlsn @ ${TLSN_REV:0:8} into $OUT_DIR:"
echo "  tlsn_wasm.js"
echo "  tlsn_wasm_bg.wasm"
echo "  spawn.js"
