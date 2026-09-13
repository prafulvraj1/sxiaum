//! Secure I/O, passphrase prompts, file permissions, and safety confirmations.

use crate::error::{KeytoolError, Result};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use sxiaum_keystore::password::validate_password;
use zeroize::Zeroizing;

/// Security banner printed to stderr before any key generation or export.
pub const SECURITY_BANNER: &str = r#"
╔══════════════════════════════════════════════════════════════════════╗
║              ⚠  SXIAUM VALIDATOR KEY OPERATION  ⚠                   ║
║                                                                      ║
║  You are about to handle sensitive cryptographic key material.       ║
║  LOSS OR EXPOSURE OF YOUR VALIDATOR KEY IS IRREVERSIBLE.            ║
║                                                                      ║
║  • Never share your private key with anyone.                         ║
║  • Store key material in an HSM or encrypted keystore.              ║
║  • Delete plaintext key files immediately after use.                 ║
║  • Rotate keys immediately if you suspect exposure.                  ║
╚══════════════════════════════════════════════════════════════════════╝
"#;

/// Interactively prompt the user for confirmation unless auto-confirm is enabled.
pub fn confirm_or_abort(action: &str, auto_confirm: bool) -> Result<()> {
    if auto_confirm {
        return Ok(());
    }

    eprint!("\nType 'confirm' to {} (anything else aborts): ", action);
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin()
        .lock()
        .read_line(&mut input)
        .map_err(KeytoolError::Io)?;

    if input.trim() != "confirm" {
        return Err(KeytoolError::Aborted);
    }
    Ok(())
}

/// Retrieve a passphrase from:
/// 1. Command-line password file (`--password-file`)
/// 2. Environment variable (`SXIAUM_KEY_PASSWORD`)
/// 3. Interactive masked terminal prompt (`rpassword`)
///
/// Passwords are treated as byte-exact secrets: environment values are used
/// verbatim (no trimming), and only file contents have a single trailing
/// newline convention applied via trim of surrounding whitespace, which is
/// standard for password files written by editors/shells.
pub fn get_passphrase(
    prompt: &str,
    confirm: bool,
    password_file: Option<&Path>,
    enforce_policy: bool,
) -> Result<Zeroizing<String>> {
    let raw = if let Some(path) = password_file {
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(KeytoolError::Other(format!(
                    "Refusing to read password from symlink: {}",
                    path.display()
                )));
            }
        }
        let content = fs::read_to_string(path).map_err(|e| {
            KeytoolError::Other(format!("Failed to read password file {:?}: {e}", path))
        })?;
        content.trim().to_string()
    } else if let Ok(env_pw) = std::env::var("SXIAUM_KEY_PASSWORD") {
        if env_pw.is_empty() {
            prompt_interactive_password(prompt, confirm)?
        } else {
            // Used verbatim: leading/trailing spaces may be intentional
            // password characters.
            env_pw
        }
    } else {
        prompt_interactive_password(prompt, confirm)?
    };

    if enforce_policy {
        if let Err(e) = validate_password(&raw) {
            return Err(KeytoolError::PassphrasePolicy(e.to_string()));
        }
    }

    Ok(Zeroizing::new(raw))
}

fn prompt_interactive_password(prompt: &str, confirm: bool) -> Result<String> {
    let pw = rpassword::prompt_password(prompt)
        .map_err(|e| KeytoolError::Other(format!("Failed to read passphrase: {e}")))?;

    if confirm {
        let confirm_pw = rpassword::prompt_password("Confirm passphrase: ")
            .map_err(|e| KeytoolError::Other(format!("Failed to read confirmation: {e}")))?;
        if pw != confirm_pw {
            return Err(KeytoolError::PassphraseMismatch);
        }
    }

    Ok(pw)
}

/// Write data securely to a file with atomic temporary file renaming and 0600 Unix permissions.
pub fn write_secure_file(path: &Path, content: &str) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(KeytoolError::Other(format!(
                "Refusing to write to symlink target: {}",
                path.display()
            )));
        }
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
    }

    let rnd = rand::random::<u64>();
    let tmp_path = match path.file_name() {
        Some(name) => path.with_file_name(format!("{}.tmp.{}", name.to_string_lossy(), rnd)),
        None => PathBuf::from(format!("key.tmp.{}", rnd)),
    };

    let write_res: Result<()> = (|| {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            opts.open(&tmp_path)?
        };

        #[cfg(not(unix))]
        let mut file = {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            opts.open(&tmp_path)?
        };

        file.write_all(content.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
        drop(file);

        #[cfg(windows)]
        {
            if path.exists() {
                let _ = fs::remove_file(path);
            }
        }

        // Atomic replace/rename
        fs::rename(&tmp_path, path)?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    write_res
}
