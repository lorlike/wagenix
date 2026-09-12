//! wagenix — Windows-native agenix: edit, decrypt and rekey age secrets
//! using the original `secrets.nix` rule file (no extra config format).
//!
//! CLI is deliberately compatible with the original agenix:
//!
//!   wagenix -e FILE [-i PRIVATE_KEY]
//!   wagenix -r  [-i PRIVATE_KEY]
//!   wagenix -d FILE [-i PRIVATE_KEY]

mod crypto;
mod nix;

use std::env;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nix::SecretRule;

const HELP: &str = r#"wagenix - edit and rekey age secret files

wagenix -e FILE [-i PRIVATE_KEY]
wagenix -r [-i PRIVATE_KEY]

options:
-h, --help                show help
-e, --edit FILE           edits FILE using $EDITOR
-r, --rekey               re-encrypts all secrets with specified recipients
-d, --decrypt FILE        decrypts FILE to STDOUT
-i, --identity            identity to use when decrypting
-v, --verbose             verbose output

FILE an age-encrypted file

PRIVATE_KEY a path to a private SSH key used to decrypt file

EDITOR environment variable of editor to use when editing FILE

If STDIN is not interactive, EDITOR will be set to "cp /dev/stdin"

RULES environment variable with path to Nix file specifying recipient public keys.
Defaults to './secrets.nix'

wagenix version: 0.1.0
"#;

struct Args {
    command: CommandKind,
    file: Option<PathBuf>,
    identities: Vec<PathBuf>,
    rules: PathBuf,
    verbose: bool,
}

enum CommandKind {
    Edit,
    Rekey,
    Decrypt,
}

fn parse_args() -> Result<Args, String> {
    let mut args = env::args().skip(1);
    let mut command: Option<CommandKind> = None;
    let mut file: Option<PathBuf> = None;
    let mut identities: Vec<PathBuf> = Vec::new();
    let mut verbose = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{HELP}");
                std::process::exit(0);
            }
            "-e" | "--edit" => {
                let v = args
                    .next()
                    .ok_or_else(|| "no FILE specified".to_string())?;
                if file.is_some() {
                    return Err("only one FILE allowed".into());
                }
                file = Some(PathBuf::from(v));
                command = Some(CommandKind::Edit);
            }
            "-d" | "--decrypt" => {
                let v = args
                    .next()
                    .ok_or_else(|| "no FILE specified".to_string())?;
                if file.is_some() {
                    return Err("only one FILE allowed".into());
                }
                file = Some(PathBuf::from(v));
                command = Some(CommandKind::Decrypt);
            }
            "-r" | "--rekey" => {
                command = Some(CommandKind::Rekey);
            }
            "-i" | "--identity" => {
                let v = args
                    .next()
                    .ok_or_else(|| "no PRIVATE_KEY specified".to_string())?;
                identities.push(PathBuf::from(v));
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            other => {
                return Err(format!("unknown option: {other}"));
            }
        }
    }

    let command = command.ok_or_else(|| {
        "no command given (use -e FILE, -d FILE or -r)".to_string()
    })?;

    // RULES environment variable, defaults to ./secrets.nix (like agenix)
    let rules = env::var("RULES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./secrets.nix"));

    Ok(Args {
        command,
        file,
        identities,
        rules,
        verbose,
    })
}

/// Resolve default SSH identity paths (Windows: %USERPROFILE%\.ssh\...).
fn default_identities() -> Vec<PathBuf> {
    let home = env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(PathBuf::from));
    let Some(home) = home else {
        return Vec::new();
    };
    let ssh = home.join(".ssh");
    let mut v = Vec::new();
    for name in ["id_ed25519", "id_rsa"] {
        let p = ssh.join(name);
        if p.is_file() {
            v.push(p);
        }
    }
    v
}

fn load_rules(path: &Path) -> Result<nix::Rules, String> {
    let src = fs::read_to_string(path)
        .map_err(|e| format!("cannot read rules file {}: {e}", path.display()))?;
    nix::parse_rules(&src)
}

fn get_rule<'a>(rules: &'a nix::Rules, file: &Path) -> Result<&'a SecretRule, String> {
    let key = file
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .ok_or_else(|| format!("cannot determine file name of {}", file.display()))?;
    rules.get(&key).ok_or_else(|| {
        format!("There is no rule for '{key}' in {}.", rules_file_display())
    })
}

/// Display name of the rules file (for error messages).
fn rules_file_display() -> String {
    env::var("RULES").unwrap_or_else(|_| "./secrets.nix".to_string())
}

fn open_editor(path: &Path) -> Result<(), String> {
    let editor = env::var("EDITOR").or_else(|_| env::var("VISUAL"));

    // If EDITOR is ":" (like agenix rekey), skip editing.
    if let Ok(e) = &editor {
        if e == ":" {
            return Ok(());
        }
    }

    match editor {
        Ok(e) => {
            // Split on whitespace to support "code --wait" style EDITORs
            let parts: Vec<&str> = e.split_whitespace().collect();
            let (prog, rest) = parts
                .split_first()
                .ok_or_else(|| "EDITOR is empty".to_string())?;
            let status = Command::new(prog)
                .args(rest)
                .arg(path)
                .status()
                .map_err(|err| format!("cannot run editor '{prog}': {err}"))?;
            if !status.success() {
                return Err(format!("editor '{prog}' exited with {status}"));
            }
            Ok(())
        }
        Err(_) => {
            // No $EDITOR: try common Windows editors, else fall back to notepad.
            for (prog, args) in [("code", vec!["--wait"]), ("notepad", vec![])] {
                if Command::new(prog)
                    .args(&args)
                    .arg(path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok()
                {
                    return Ok(());
                }
            }
            Err("no editor found; set $EDITOR".to_string())
        }
    }
}

/// Create a unique temporary directory for the cleartext file.
fn make_temp_dir() -> Result<PathBuf, String> {
    let base = env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = base.join(format!("wagenix-{pid}-{nanos}"));
    fs::create_dir_all(&dir)
        .map_err(|e| format!("cannot create temp dir {}: {e}", dir.display()))?;
    Ok(dir)
}

/// The core edit flow. If `skip_editor` is true (rekey), the editor is not
/// opened and the file is re-encrypted as-is.
fn edit_file(
    file: &Path,
    rules: &Path,
    identities: &[PathBuf],
    skip_editor: bool,
    verbose: bool,
) -> Result<(), String> {
    let rules_map = load_rules(rules)?;
    let rule = get_rule(&rules_map, file)?;

    let mut idents: Vec<PathBuf> = identities.to_vec();
    if idents.is_empty() {
        idents = default_identities();
    }
    if idents.is_empty() {
        return Err(
            "No identity found to decrypt. Try adding an SSH key at ~/.ssh/id_ed25519 or ~/.ssh/id_rsa or using the --identity flag to specify a file.".to_string(),
        );
    }
    if verbose {
        eprintln!("[wagenix] using identities: {:?}", idents);
    }

    // Create temp dir for cleartext (auto-cleaned on drop)
    let tmp_dir = make_temp_dir()?;
    struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _guard = Guard(tmp_dir.clone());

    let name = file
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "secret".to_string());
    let cleartext_path = tmp_dir.join(&name);

    let id_refs: Vec<&Path> = idents.iter().map(|p| p.as_path()).collect();

    // Decrypt existing file (if it exists) to cleartext
    let existed = file.is_file();
    if existed {
        let data = crypto::decrypt_file(file, &id_refs)?;
        fs::write(&cleartext_path, &data)
            .map_err(|e| format!("cannot write cleartext: {e}"))?;
    }

    // Snapshot for change detection
    let before = if existed {
        fs::read(&cleartext_path).unwrap_or_default()
    } else {
        Vec::new()
    };

    // Edit unless rekeying (EDITOR=: equivalent).
    //
    // stdin handling (compatible with agenix's `[ -t 0 ] || EDITOR='cp /dev/stdin'`):
    //   - TTY stdin          -> open the editor
    //   - piped stdin w/ data -> use the piped content (echo x | wagenix -e)
    //   - piped stdin w/o data (e.g. /dev/null, CI) -> open the editor
    if !skip_editor {
        if std::io::stdin().is_terminal() {
            open_editor(&cleartext_path)?;
        } else {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("cannot read stdin: {e}"))?;
            if buf.is_empty() {
                open_editor(&cleartext_path)?;
            } else {
                fs::write(&cleartext_path, &buf)
                    .map_err(|e| format!("cannot write cleartext: {e}"))?;
            }
        }
    }

    // Read back
    let after = match fs::read(&cleartext_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("[wagenix] {} wasn't created.", file.display());
            return Ok(());
        }
    };

    // Skip re-encryption if unchanged — but never in rekey mode
    // (rekey must always re-encrypt; age randomness changes the file anyway).
    if existed && before == after && !skip_editor {
        eprintln!("[wagenix] {} wasn't changed, skipping re-encryption.", file.display());
        return Ok(());
    }

    // Re-encrypt atomically
    crypto::encrypt_to_file(file, rule, &after)?;
    if verbose {
        eprintln!(
            "[wagenix] encrypted '{}' with {} recipient(s)",
            file.display(),
            rule.public_keys.len()
        );
    }
    Ok(())
}

fn cmd_decrypt(args: &Args) -> Result<(), String> {
    let file = args
        .file
        .as_ref()
        .ok_or_else(|| "no FILE specified for decrypt".to_string())?;

    // Like agenix, verify the rule exists first (even though decryption only
    // needs the private key, the rule check catches typos early).
    let rules = load_rules(&args.rules)?;
    get_rule(&rules, file)?;

    let mut idents: Vec<PathBuf> = args.identities.clone();
    if idents.is_empty() {
        idents = default_identities();
    }
    if idents.is_empty() {
        return Err(
            "No identity found to decrypt. Try adding an SSH key at ~/.ssh/id_ed25519 or ~/.ssh/id_rsa or using the --identity flag to specify a file.".to_string(),
        );
    }
    if args.verbose {
        eprintln!("[wagenix] using identities: {:?}", idents);
    }

    let id_refs: Vec<&Path> = idents.iter().map(|p| p.as_path()).collect();
    let plaintext = crypto::decrypt_file(file, &id_refs)?;

    let mut stdout = std::io::stdout();
    stdout
        .write_all(&plaintext)
        .map_err(|e| format!("cannot write to stdout: {e}"))?;
    stdout
        .flush()
        .map_err(|e| format!("cannot flush stdout: {e}"))?;
    Ok(())
}

fn cmd_rekey(args: &Args) -> Result<(), String> {
    let rules = load_rules(&args.rules)?;
    let mut names: Vec<String> = rules.keys().cloned().collect();
    names.sort();

    for name in &names {
        eprintln!("rekeying {name}...");
        edit_file(
            &PathBuf::from(name),
            &args.rules,
            &args.identities,
            true, // skip editor
            args.verbose,
        )?;
    }
    Ok(())
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!();
            eprintln!("{HELP}");
            std::process::exit(1);
        }
    };

    let result = match args.command {
        CommandKind::Edit => match args.file.as_ref() {
            Some(file) => edit_file(file, &args.rules, &args.identities, false, args.verbose),
            None => Err("no FILE specified for edit".to_string()),
        },
        CommandKind::Decrypt => cmd_decrypt(&args),
        CommandKind::Rekey => cmd_rekey(&args),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
