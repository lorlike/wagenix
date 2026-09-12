//! End-to-end integration tests for wagenix.
//!
//! These tests invoke the built `wagenix` binary (via CARGO_BIN_EXE_wagenix)
//! against the test data in `test/`:
//!
//!   test/id_ed25519           test private key
//!   test/id_ed25519.pub       test public key
//!   test/secrets.nix          rules referencing the test key
//!   test/secret1.age          binary secret ("hello wagenix test")
//!   test/armored-secret.age   armored secret ("armored test content")
//!
//! IMPORTANT: `test/*.age` files may be modified by manual testing (e.g.
//! `wagenix -e`). To keep assertions stable, every test first calls
//! [`ensure_test_data`], which OVERWRITES the encrypted test files with the
//! canonical plaintext content before any decryption assertion runs.
//!
//! All other file mutations happen in unique temp dirs so the checked-in
//! test data stays pristine.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

const BIN: &str = env!("CARGO_BIN_EXE_wagenix");

/// Canonical plaintext content of the checked-in test secrets.
const SECRET1_CONTENT: &str = "hello wagenix test\n";
const ARMORED_CONTENT: &str = "armored test content\n";

/// Project root (where test/ lives).
fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn test_dir() -> PathBuf {
    project_root().join("test")
}

fn bin() -> &'static str {
    BIN
}

/// Ensure the checked-in encrypted test files contain the canonical content.
///
/// Manual testing (`wagenix -e`) may have rewritten `test/*.age` with
/// arbitrary content. This OVERWRITES them back to the canonical plaintext so
/// decryption assertions are stable regardless of prior manual testing.
///
/// `OnceLock::get_or_init` guarantees the reset runs exactly once and that
/// any other test thread blocks until it completes (no races on the shared
/// files).
static TEST_DATA_READY: OnceLock<()> = OnceLock::new();

fn ensure_test_data() {
    TEST_DATA_READY
        .get_or_init(|| {
            reset_test_data();
        });
}

/// Overwrite `test/secret1.age` and `test/armored-secret.age` with the
/// canonical content. Files are removed first so the reset does not depend on
/// the previous file being decryptable (it may have been corrupted by hand).
fn reset_test_data() {
    for name in ["secret1.age", "armored-secret.age"] {
        let _ = std::fs::remove_file(test_dir().join(name));
    }
    encrypt_new(&test_dir(), "secret1.age", SECRET1_CONTENT);
    encrypt_new(&test_dir(), "armored-secret.age", ARMORED_CONTENT);
}

/// Encrypt `content` into `dir/name` via `wagenix -e` (stdin mode) using the
/// test identity. The target file must not exist yet.
fn encrypt_new(dir: &Path, name: &str, content: &str) {
    use std::io::Write;
    let mut cmd = Command::new(bin());
    cmd.current_dir(dir)
        .arg("-e")
        .arg(name)
        .arg("-i")
        .arg(test_dir().join("id_ed25519"))
        .env("RULES", test_dir().join("secrets.nix"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn wagenix");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(content.as_bytes())
        .expect("failed to write stdin");
    let out = child.wait_with_output().expect("failed to wait wagenix");
    assert!(
        out.status.success(),
        "reset test data failed for {name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Run wagenix with the given args and env overrides in a working dir.
/// Relative paths passed after `-i` are resolved against the test dir.
fn run_in(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.current_dir(dir)
        .env("RULES", test_dir().join("secrets.nix"))
        .env("EDITOR", ":");
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-i" => {
                let v = args[i + 1];
                let p = Path::new(v);
                let resolved = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    test_dir().join(p)
                };
                cmd.arg("-i").arg(resolved);
                i += 2;
            }
            a => {
                cmd.arg(a);
                i += 1;
            }
        }
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run wagenix")
}

/// A unique temp dir that is cleaned up on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wagenix-test-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Create a cross-platform fake editor script that writes `content` to $1.
/// Returns the EDITOR command string.
fn make_fake_editor(dir: &Path, content: &str) -> String {
    #[cfg(windows)]
    {
        // Use PowerShell to write the file without CRLF surprises.
        let script = dir.join("fake-editor.ps1");
        std::fs::write(
            &script,
            format!("param([string]$p)\r\nSet-Content -Path $p -Value '{content}' -NoNewline\r\n"),
        )
        .unwrap();
        format!(
            "powershell -NoProfile -ExecutionPolicy Bypass -File {}",
            script.display()
        )
    }
    #[cfg(unix)]
    {
        let script = dir.join("fake-editor.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho '{content}' > \"$1\"\n"),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script.to_string_lossy().to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn decrypt_binary_secret() {
    ensure_test_data();
    let out = run_in(&test_dir(), &["-d", "secret1.age", "-i", "id_ed25519"], &[]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), SECRET1_CONTENT);
}

#[test]
fn decrypt_armored_secret() {
    ensure_test_data();
    let out = run_in(&test_dir(), &["-d", "armored-secret.age", "-i", "id_ed25519"], &[]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), ARMORED_CONTENT);
}

#[test]
fn decrypt_with_default_identity_lookup() {
    ensure_test_data();
    // Point HOME/USERPROFILE at a temp dir so the default identity
    // (~/.ssh/id_ed25519) resolves to our test key.
    let tmp = TempDir::new("default-id");
    let home = tmp.path().join("fake-home");
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::copy(test_dir().join("id_ed25519"), ssh.join("id_ed25519")).unwrap();

    let mut cmd = Command::new(bin());
    cmd.current_dir(&test_dir())
        .args(["-d", "secret1.age"])
        .env("RULES", test_dir().join("secrets.nix"))
        .env("HOME", &home);
    if cfg!(windows) {
        cmd.env("USERPROFILE", &home);
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), SECRET1_CONTENT);
}

#[test]
fn edit_roundtrip_with_editor() {
    ensure_test_data();
    let tmp = TempDir::new("edit-roundtrip");
    // Copy the checked-in secret into the temp dir (same name -> rule matches)
    std::fs::copy(test_dir().join("secret1.age"), tmp.path().join("secret1.age")).unwrap();
    let editor = make_fake_editor(tmp.path(), "edited by test");
    let out = run_in(
        tmp.path(),
        &["-e", "secret1.age", "-i", "id_ed25519"],
        &[("EDITOR", &editor)],
    );
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    // Decrypt again: must now contain the edited content
    let out2 = run_in(tmp.path(), &["-d", "secret1.age", "-i", "id_ed25519"], &[]);
    assert!(out2.status.success(), "stderr: {}", String::from_utf8_lossy(&out2.stderr));
    // Editor content may or may not have a trailing newline (platform dependent)
    assert_eq!(
        String::from_utf8_lossy(&out2.stdout).trim_end(),
        "edited by test"
    );
}

#[test]
fn edit_no_change_skips_reencryption() {
    ensure_test_data();
    let tmp = TempDir::new("edit-nochange");
    let original = std::fs::read(test_dir().join("secret1.age")).unwrap();
    std::fs::write(tmp.path().join("secret1.age"), &original).unwrap();

    let out = run_in(
        tmp.path(),
        &["-e", "secret1.age", "-i", "id_ed25519"],
        &[],
    );
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("wasn't changed"),
        "expected skip message, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // File must be byte-identical (not re-encrypted)
    let after = std::fs::read(tmp.path().join("secret1.age")).unwrap();
    assert_eq!(original, after);
}

#[test]
fn edit_via_stdin_pipe() {
    ensure_test_data();
    let tmp = TempDir::new("stdin-pipe");
    std::fs::copy(test_dir().join("secret1.age"), tmp.path().join("secret1.age")).unwrap();

    // Pipe content via stdin (EDITOR is ":" from run_in, but stdin takes priority)
    let mut cmd = Command::new(bin());
    cmd.current_dir(tmp.path())
        .arg("-e")
        .arg("secret1.age")
        .arg("-i")
        .arg(test_dir().join("id_ed25519"))
        .env("RULES", test_dir().join("secrets.nix"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"piped via stdin\n")
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    let out2 = run_in(tmp.path(), &["-d", "secret1.age", "-i", "id_ed25519"], &[]);
    assert_eq!(String::from_utf8_lossy(&out2.stdout), "piped via stdin\n");
}

#[test]
fn rekey_roundtrip() {
    ensure_test_data();
    let tmp = TempDir::new("rekey");
    for name in ["secret1.age", "armored-secret.age"] {
        std::fs::copy(test_dir().join(name), tmp.path().join(name)).unwrap();
    }
    let before1 = std::fs::read(tmp.path().join("secret1.age")).unwrap();

    let out = run_in(tmp.path(), &["-r", "-i", "id_ed25519"], &[]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    // Both files must still decrypt to the same content
    let d1 = run_in(tmp.path(), &["-d", "secret1.age", "-i", "id_ed25519"], &[]);
    assert_eq!(String::from_utf8_lossy(&d1.stdout), SECRET1_CONTENT);
    let d2 = run_in(tmp.path(), &["-d", "armored-secret.age", "-i", "id_ed25519"], &[]);
    assert_eq!(String::from_utf8_lossy(&d2.stdout), ARMORED_CONTENT);

    // Rekey must have rewritten the file (age randomness -> different bytes)
    let after1 = std::fs::read(tmp.path().join("secret1.age")).unwrap();
    assert_ne!(before1, after1, "rekey should rewrite the encrypted file");
}

#[test]
fn error_when_no_rule_for_file() {
    ensure_test_data();
    let tmp = TempDir::new("norule");
    let out = run_in(tmp.path(), &["-d", "unknown.age", "-i", "id_ed25519"], &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no rule for 'unknown.age'"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn error_when_identity_cannot_decrypt() {
    ensure_test_data();
    let tmp = TempDir::new("badidentity");
    std::fs::copy(test_dir().join("secret1.age"), tmp.path().join("secret1.age")).unwrap();
    let out = run_in(tmp.path(), &["-d", "secret1.age", "-i", "id_ed25519.pub"], &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot parse identity") || stderr.contains("decryption failed"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn error_when_no_identity_found() {
    ensure_test_data();
    let tmp = TempDir::new("noid");
    std::fs::copy(test_dir().join("secret1.age"), tmp.path().join("secret1.age")).unwrap();
    // No -i and no default identities (point HOME/USERPROFILE at empty dir)
    let empty_home = tmp.path().join("empty-home");
    std::fs::create_dir_all(&empty_home).unwrap();
    let mut cmd = Command::new(bin());
    cmd.current_dir(tmp.path())
        .args(["-d", "secret1.age"])
        .env("RULES", test_dir().join("secrets.nix"))
        .env("HOME", &empty_home);
    if cfg!(windows) {
        cmd.env("USERPROFILE", &empty_home);
    }
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("No identity found"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
