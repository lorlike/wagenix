//! Encryption/decryption wrappers around the `age` crate.
//!
//! Uses SSH keys directly:
//!   - recipients (public keys) come from `secrets.nix`
//!   - identities (private keys) come from `-i` flags or default SSH paths

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use age::ssh::{Identity as SshIdentity, Recipient as SshRecipient};
use age::{Decryptor, Encryptor};

use crate::nix::SecretRule;

/// Parse an SSH public key string ("ssh-ed25519 AAAA...") into an age recipient.
fn parse_recipient(s: &str) -> Result<Box<dyn age::Recipient>, String> {
    let r: SshRecipient = s
        .parse()
        .map_err(|e| format!("invalid SSH public key '{s}': {e:?}"))?;
    Ok(Box::new(r))
}

/// Load an SSH private key file into an age identity.
fn load_identity(path: &Path) -> Result<Box<dyn age::Identity>, String> {
    let f = File::open(path)
        .map_err(|e| format!("cannot open identity file {}: {e}", path.display()))?;
    let id = SshIdentity::from_buffer(BufReader::new(f), Some(path.display().to_string()))
        .map_err(|e| format!("cannot parse identity {}: {e}", path.display()))?;
    // Wrap with passphrase callbacks so encrypted keys prompt on the terminal.
    let with_cb = id.with_callbacks(age::cli_common::UiCallbacks);
    Ok(Box::new(with_cb))
}

/// Encrypt `plaintext` to the recipients described by `rule`.
/// If `rule.armor` is true, produce ASCII-armored output.
pub fn encrypt_to_bytes(rule: &SecretRule, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let recipients: Vec<Box<dyn age::Recipient>> = rule
        .public_keys
        .iter()
        .map(|s| parse_recipient(s))
        .collect::<Result<_, _>>()?;

    let encryptor =
        Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
            .map_err(|e| format!("cannot create encryptor: {e}"))?;

    let mut out = Vec::new();
    if rule.armor {
        let mut writer = age::armor::ArmoredWriter::wrap_output(
            &mut out,
            age::armor::Format::AsciiArmor,
        )
        .map_err(|e| format!("cannot create armored writer: {e}"))?;
        {
            let mut stream = encryptor
                .wrap_output(&mut writer)
                .map_err(|e| format!("cannot create stream writer: {e}"))?;
            stream
                .write_all(plaintext)
                .map_err(|e| format!("write error: {e}"))?;
            stream
                .finish()
                .map_err(|e| format!("finish error: {e}"))?;
        }
        writer
            .finish()
            .map_err(|e| format!("armor finish error: {e}"))?;
    } else {
        let mut stream = encryptor
            .wrap_output(&mut out)
            .map_err(|e| format!("cannot create stream writer: {e}"))?;
        stream
            .write_all(plaintext)
            .map_err(|e| format!("write error: {e}"))?;
        stream
            .finish()
            .map_err(|e| format!("finish error: {e}"))?;
    }
    Ok(out)
}

/// Decrypt an age file to bytes using the given identity paths.
pub fn decrypt_file(path: &Path, identities: &[&Path]) -> Result<Vec<u8>, String> {
    let file = File::open(path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    // ArmoredReader transparently handles both binary and armored age files.
    let mut reader = age::armor::ArmoredReader::new(BufReader::new(file));

    let decryptor = Decryptor::new(&mut reader)
        .map_err(|e| format!("cannot read age file {}: {e}", path.display()))?;

    let mut identities_loaded = Vec::new();
    for id_path in identities {
        identities_loaded.push(load_identity(id_path)?);
    }

    let mut decrypted = decryptor
        .decrypt(identities_loaded.iter().map(|i| i.as_ref()))
        .map_err(|e| format!("decryption failed for {}: {e}", path.display()))?;

    let mut out = Vec::new();
    decrypted
        .read_to_end(&mut out)
        .map_err(|e| format!("read error while decrypting: {e}"))?;
    Ok(out)
}

/// Encrypt a file atomically: write to temp then replace the target.
pub fn encrypt_to_file(path: &Path, rule: &SecretRule, plaintext: &[u8]) -> Result<(), String> {
    let bytes = encrypt_to_bytes(rule, plaintext)?;

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("cannot create dir {}: {e}", dir.display()))?;

    let name = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "secret".to_string());
    let tmp = dir.join(format!(".{name}.tmp{}", std::process::id()));

    {
        let f = File::create(&tmp)
            .map_err(|e| format!("cannot create temp file {}: {e}", tmp.display()))?;
        let mut bw = BufWriter::new(f);
        bw.write_all(&bytes)
            .map_err(|e| format!("write error: {e}"))?;
        bw.flush().map_err(|e| format!("flush error: {e}"))?;
    }

    // Windows rename fails if destination exists, so remove first.
    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|e| format!("cannot remove old {}: {e}", path.display()))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("cannot rename {} to {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}
