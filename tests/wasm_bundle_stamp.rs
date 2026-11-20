//! `scripts/build-tlsn-wasm.sh` keeps a staged bundle only when its
//! `.tlsn-rev` stamp names the tlsn commit `Cargo.lock` resolves.
//!
//! Each test runs the script in a throwaway checkout: a copy of the script, a
//! one-line `Cargo.lock` and a fake staged bundle. The environment has no
//! rustup, so a script that decides to rebuild stops at its rustup check
//! instead of compiling tlsn.

use std::{
    env,
    fs,
    path::PathBuf,
    process::{
        self,
        Command,
        Output,
    },
};

/// The commit the throwaway lock resolves tlsn to.
const LOCK_REV: &str = "40a069565a2eaecbb5e691dbc634be20e8498daf";

/// The pin before v0.1.0-beta.1, as a stale stamp.
const OLD_REV: &str = "01fab038b10d0ed0c8865c0afe1f6d14559fb90e";

/// The line the script prints when it keeps a staged bundle.
const SKIPPED: &str = "already staged";

/// A checkout holding the bundle script, a lock and a staged bundle, removed
/// on drop.
struct StagedCheckout {
    root: PathBuf,
}

impl StagedCheckout {
    /// Stages a bundle with every API the script checks for, stamped with
    /// `stamp` when one is given.
    fn new(name: &str, stamp: Option<&str>) -> Self {
        let root =
            env::temp_dir().join(format!("notary-wasm-stamp-{name}-{}", process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        let scripts = root.join("scripts");
        fs::create_dir_all(&scripts).unwrap();
        fs::copy(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/build-tlsn-wasm.sh"),
            scripts.join("build-tlsn-wasm.sh"),
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            format!(
                "source = \"git+https://github.com/tlsnotary/tlsn?tag=v0.1.0-beta.1#{LOCK_REV}\"\n"
            ),
        )
        .unwrap();

        let out = root.join("tlsn-wasm");
        let spawn = out.join("snippets/web-spawn-0/js");
        fs::create_dir_all(&spawn).unwrap();
        fs::write(out.join("tlsn_wasm_bg.wasm"), b"\0asm").unwrap();
        fs::write(
            out.join("tlsn_wasm.js"),
            "set_progress_callback(); finish();\n",
        )
        .unwrap();
        fs::write(spawn.join("spawn.js"), "").unwrap();
        if let Some(rev) = stamp {
            fs::write(out.join(".tlsn-rev"), format!("{rev}\n")).unwrap();
        }
        Self { root }
    }

    /// Runs the script with no rustup on `PATH` or under `HOME`.
    fn run(&self) -> Output {
        Command::new("bash")
            .arg(self.root.join("scripts/build-tlsn-wasm.sh"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("TMPDIR", &self.root)
            .output()
            .unwrap()
    }
}

impl Drop for StagedCheckout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_bundle_stamped_with_the_lock_commit_is_kept() {
    let checkout = StagedCheckout::new("match", Some(LOCK_REV));
    let output = checkout.run();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{output:?}");
    assert!(stdout.contains(SKIPPED), "{stdout}");
    drop(checkout);
}

#[test]
fn a_bundle_stamped_with_another_commit_is_rebuilt() {
    let checkout = StagedCheckout::new("stale", Some(OLD_REV));
    let output = checkout.run();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(SKIPPED), "{stdout}");
    assert!(stdout.contains("rustup not found"), "{output:?}");
    drop(checkout);
}

#[test]
fn a_bundle_without_a_stamp_is_rebuilt() {
    let checkout = StagedCheckout::new("unstamped", None);
    let output = checkout.run();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(SKIPPED), "{stdout}");
    assert!(stdout.contains("rustup not found"), "{output:?}");
    drop(checkout);
}
