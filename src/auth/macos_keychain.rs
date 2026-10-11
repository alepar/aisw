use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use anyhow::{bail, Context, Result};

use super::test_overrides;

pub fn find_generic_password_account(service: &str) -> Result<Option<String>> {
    ensure_available()?;
    let mut command = Command::new(security_bin());
    command.args(["find-generic-password", "-s", service]);
    if let Some(path) = override_keychain_path() {
        command.arg(path);
    }

    let output = command
        .output()
        .context("could not inspect macOS Keychain generic password")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.code() == Some(44)
            || stderr.contains("could not be found")
            || stderr.contains("not found in the keychain")
        {
            return Ok(None);
        }
        if is_user_canceled(&output.status, &stderr) {
            bail!(
                "Keychain access was denied.\n  \
                 Run the command again and click 'Always Allow' so aisw can manage \
                 credentials without repeated prompts."
            );
        }
        bail!(
            "could not inspect macOS Keychain generic password: {}",
            stderr.trim()
        );
    }

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(parse_attribute_value(&combined, "acct"))
}

pub fn read_generic_password(service: &str, account: Option<&str>) -> Result<Option<Vec<u8>>> {
    ensure_available()?;
    let mut command = Command::new(security_bin());
    command.args(["find-generic-password", "-s", service]);
    if let Some(account) = account {
        command.args(["-a", account]);
    }
    command.arg("-w");
    if let Some(path) = override_keychain_path() {
        command.arg(path);
    }

    let output = command
        .output()
        .context("could not read macOS Keychain generic password")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.code() == Some(44)
            || stderr.contains("could not be found")
            || stderr.contains("not found in the keychain")
        {
            return Ok(None);
        }
        if is_user_canceled(&output.status, &stderr) {
            bail!(
                "Keychain access was denied.\n  \
                 Run the command again and click 'Always Allow' so aisw can manage \
                 credentials without repeated prompts."
            );
        }
        bail!(
            "could not read macOS Keychain generic password: {}",
            stderr.trim()
        );
    }

    Ok(Some(strip_cli_output_terminator(output.stdout)))
}

/// Removes the single trailing newline `security(1)` writes after a `-w` value.
///
/// That byte is part of the CLI's output framing, not the stored secret, and it
/// cannot be confused with data: `security` switches from text to hex output as
/// soon as the stored value contains a newline anywhere, so a value printed as
/// text provably has none of its own. Exactly one byte comes off — a trailing
/// space *is* data and survives text mode intact, and the hex form legitimately
/// decodes to bytes that end in a newline.
///
/// Leaving it on meant aisw stored the terminator and wrote it back verbatim
/// through `set_generic_password`, which pushed the Keychain item into the hex
/// form that Claude Code's own reader cannot parse (#250).
fn strip_cli_output_terminator(mut stdout: Vec<u8>) -> Vec<u8> {
    if stdout.last() == Some(&b'\n') {
        stdout.pop();
    }
    stdout
}

pub fn upsert_generic_password(
    service: &str,
    account: &str,
    secret: &[u8],
    trusted_apps: &[PathBuf],
) -> Result<()> {
    ensure_available()?;
    // Validate metadata before launching anything. security's interactive
    // parser understands quotes/backslashes, but a newline starts a command.
    quote_security_argument(service)?;
    quote_security_argument(account)?;

    let mut lookup = Command::new(security_bin());
    lookup.args(["find-generic-password", "-s", service, "-a", account]);
    let keychain = override_keychain_path();
    if let Some(path) = &keychain {
        lookup.arg(path);
    }
    let found = lookup
        .output()
        .context("could not inspect macOS Keychain generic password before update")?;
    let existing = if found.status.success() {
        true
    } else if found.status.code() == Some(44) {
        false
    } else {
        if is_user_canceled(&found.status, &String::from_utf8_lossy(&found.stderr)) {
            bail!("Keychain access was denied; no credentials were written.");
        }
        bail!("could not update macOS Keychain generic password: item lookup failed");
    };

    let mut args = vec!["add-generic-password".to_owned()];
    if existing {
        args.push("-U".to_owned());
    }
    args.extend([
        "-s".to_owned(),
        service.to_owned(),
        "-a".to_owned(),
        account.to_owned(),
    ]);
    if !existing {
        // Claude reads through security(1). Native writes rebuild the item's
        // partition ACL for aisw's signature, which security cannot satisfy.
        // Let Apple's signed tool write instead, and trust its reader as well
        // as Claude. -T on updates would also change the application ACL and
        // request another authorization, so retain existing approvals there.
        args.extend(["-T".to_owned(), "/usr/bin/security".to_owned()]);
        for app in trusted_apps {
            let path = app
                .to_str()
                .context("trusted application path is not valid UTF-8")?;
            if path != "/usr/bin/security" {
                args.extend(["-T".to_owned(), path.to_owned()]);
            }
        }
    }
    // -X carries exact bytes, unlike -w's short, line-oriented terminal prompt.
    // Only -q/-i are argv: credentials and metadata go over the private pipe.
    let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
    args.extend(["-X".to_owned(), hex]);
    if let Some(path) = &keychain {
        args.push(
            path.to_str()
                .context("Keychain path is not valid UTF-8")?
                .to_owned(),
        );
    }
    if args.len() > 32 {
        bail!(
            "too many trusted applications for macOS Keychain update; no credentials were written"
        );
    }
    let mut line = args
        .iter()
        .map(|arg| quote_security_argument(arg))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    line.push('\n');
    // security's interactive reader has a 4096-byte buffer and silently
    // executes truncated lines. Reject before writing, including hex/escaping.
    if line.len() >= 4096 {
        bail!("credential command exceeds macOS security's 4096-byte input limit; no credentials were written");
    }

    let mut command = Command::new(security_bin());
    command.args(["-q", "-i"]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .context("could not update macOS Keychain generic password")?;

    let sent = (|| -> std::io::Result<()> {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("Keychain writer stdin unavailable"))?;
        stdin.write_all(line.as_bytes())
    })();
    if let Err(error) = sent {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("could not write macOS Keychain secret");
    }

    let output = child
        .wait_with_output()
        .context("could not wait for macOS Keychain update")?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_user_canceled(&output.status, &stderr) {
        bail!(
            "Keychain access was denied.\n  \
             Run the command again and click 'Always Allow' so aisw can manage \
             credentials without repeated prompts."
        );
    }
    // Never include child output: an error or verbose wrapper can echo stdin.
    bail!(
        "could not update macOS Keychain generic password (exit status {})",
        output.status
    );
}

fn quote_security_argument(value: &str) -> Result<String> {
    if value
        .bytes()
        .any(|byte| matches!(byte, b'\n' | b'\r' | b'\0'))
    {
        bail!("macOS Keychain command arguments cannot contain newline, carriage return or NUL");
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

pub fn is_available() -> bool {
    cfg!(target_os = "macos")
        || test_overrides::var("AISW_SECURITY_BIN").is_some()
        || test_overrides::var("AISW_SECURITY_KEYCHAIN").is_some()
}

fn ensure_available() -> Result<()> {
    if is_available() {
        Ok(())
    } else {
        bail!("macOS Keychain support is only available on macOS")
    }
}

fn security_bin() -> String {
    test_overrides::string("AISW_SECURITY_BIN").unwrap_or_else(|| "/usr/bin/security".to_owned())
}

fn override_keychain_path() -> Option<PathBuf> {
    test_overrides::string("AISW_SECURITY_KEYCHAIN").map(PathBuf::from)
}

/// Returns true when the `security` CLI was denied by the user (clicked "Deny"
/// or cancelled the Keychain authorisation dialog).
///
/// The CLI exits with code 128 and/or emits a stderr message containing
/// "User canceled" (note: macOS spells "canceled" with one 'l').
fn is_user_canceled(status: &std::process::ExitStatus, stderr: &str) -> bool {
    status.code() == Some(128) || stderr.contains("User canceled")
}

fn parse_first_quoted_value(text: &str) -> Option<String> {
    let start = text.find('"')?;
    let rest = &text[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

fn parse_attribute_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with(&format!("\"{key}\"")) {
            continue;
        }
        let (_, value) = trimmed.split_once('=')?;
        let value = value.trim();
        if let Some(parsed) = parse_first_quoted_value(value) {
            return Some(parsed);
        }
        if !value.is_empty() {
            return Some(value.to_owned());
        }
    }
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use tempfile::tempdir;

    fn exit_status(code: i32) -> std::process::ExitStatus {
        // Portable way to construct an ExitStatus with a known code.
        Command::new("sh")
            .args(["-c", &format!("exit {code}")])
            .status()
            .unwrap()
    }

    #[test]
    fn is_user_canceled_detects_exit_128() {
        assert!(is_user_canceled(&exit_status(128), "some other message"));
    }

    #[test]
    fn is_user_canceled_detects_stderr_message() {
        assert!(is_user_canceled(
            &exit_status(1),
            "User canceled the operation."
        ));
    }

    #[test]
    fn is_user_canceled_returns_false_for_other_errors() {
        assert!(!is_user_canceled(
            &exit_status(1),
            "SecKeychainAddGenericPassword: item already exists"
        ));
        assert!(!is_user_canceled(
            &exit_status(44),
            "could not be found in the keychain"
        ));
    }

    struct EnvVarGuard {
        key: &'static str,
        old: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let old = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, old }
        }

        fn unset(key: &'static str) -> Self {
            let old = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, old }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.old {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn write_mock_security(bin: &std::path::Path, script: &str) {
        fs::write(bin, script).unwrap();
        fs::set_permissions(bin, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn is_available_is_true_with_security_override() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(&bin, "#!/bin/sh\nexit 0\n");
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        assert!(is_available());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn ensure_available_paths_error_without_overrides() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _security = EnvVarGuard::unset("AISW_SECURITY_BIN");
        let _keychain = EnvVarGuard::unset("AISW_SECURITY_KEYCHAIN");
        let err = read_generic_password("aisw", None).unwrap_err();
        assert!(err.to_string().contains("only available on macOS"));
    }

    #[test]
    fn find_generic_password_account_parses_blob_output() {
        let output = "keychain: \"/tmp/test-login.keychain-db\"\n\
                      class: \"genp\"\n\
                      attributes:\n\
                          0x00000007 <blob>=\"Codex Auth\"\n\
                          \"acct\"<blob>=\"burak\"\n";

        assert_eq!(
            parse_attribute_value(output, "acct"),
            Some("burak".to_owned())
        );
    }

    #[test]
    #[cfg(unix)]
    fn read_generic_password_uses_account_when_provided() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        let marker = dir.path().join("args");
        fs::write(
            &bin,
            format!(
                "#!/bin/sh\n\
                 printf '%s ' \"$@\" > \"{}\"\n\
                 if [ \"$1\" = \"find-generic-password\" ] && [ \"$2\" = \"-s\" ] && [ \"$3\" = \"Claude Code-credentials\" ] && [ \"$4\" = \"-a\" ] && [ \"$5\" = \"tester\" ] && [ \"$6\" = \"-w\" ]; then\n\
                   printf '{{\"oauthToken\":\"tok\"}}\\n'\n\
                   exit 0\n\
                 fi\n\
                 exit 1\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();

        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);

        let bytes = read_generic_password("Claude Code-credentials", Some("tester"))
            .unwrap()
            .expect("password");
        assert_eq!(bytes, br#"{"oauthToken":"tok"}"#);
        assert_eq!(
            fs::read_to_string(marker).unwrap(),
            "find-generic-password -s Claude Code-credentials -a tester -w "
        );
    }

    #[test]
    fn strip_cli_output_terminator_removes_exactly_one_newline() {
        assert_eq!(strip_cli_output_terminator(b"{}\n".to_vec()), b"{}");
        // The hex form decodes to bytes that may legitimately end in a
        // newline, so only the CLI's own terminator comes off.
        assert_eq!(strip_cli_output_terminator(b"{}\n\n".to_vec()), b"{}\n");
        // A trailing space survives `security`'s text mode, so it is data.
        assert_eq!(strip_cli_output_terminator(b"{} \n".to_vec()), b"{} ");
        assert_eq!(strip_cli_output_terminator(b"{}".to_vec()), b"{}");
        assert_eq!(strip_cli_output_terminator(Vec::new()), b"");
        assert_eq!(strip_cli_output_terminator(b"\n".to_vec()), b"");
        // Binary payloads must survive untouched apart from the terminator.
        assert_eq!(
            strip_cli_output_terminator(b"\x00\xff\n".to_vec()),
            b"\x00\xff"
        );
    }

    /// The real `security -w` always terminates its output with a newline.
    /// Keeping it meant aisw wrote it back into the Keychain item, which
    /// forced the hex form Claude Code cannot read (#250).
    #[test]
    #[cfg(unix)]
    fn read_generic_password_strips_the_cli_output_terminator() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(
            &bin,
            "#!/bin/sh\nprintf '{\"claudeAiOauth\":{\"accessToken\":\"tok\"}}\\n'\n",
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);

        let bytes = read_generic_password("Claude Code-credentials", None)
            .unwrap()
            .expect("password");
        assert_eq!(bytes, br#"{"claudeAiOauth":{"accessToken":"tok"}}"#);
    }

    /// Guards against "simplifying" the strip into a `trim_ascii_end`: a
    /// trailing space is preserved by `security`'s text mode, so it is part
    /// of the secret and discarding it would silently corrupt the value.
    #[test]
    #[cfg(unix)]
    fn read_generic_password_preserves_trailing_space_in_the_value() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(&bin, "#!/bin/sh\nprintf 'secret \\n'\n");
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);

        let bytes = read_generic_password("aisw", None)
            .unwrap()
            .expect("password");
        assert_eq!(bytes, b"secret ");
    }

    /// An empty stored value must stay distinguishable from a missing item:
    /// `Some(vec![])`, never `None`, so callers do not treat a wiped secret
    /// as "no profile configured" and skip the write that would repair it.
    #[test]
    #[cfg(unix)]
    fn read_generic_password_reports_an_empty_value_as_present() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(&bin, "#!/bin/sh\nprintf '\\n'\n");
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);

        assert_eq!(
            read_generic_password("Claude Code-credentials", None).unwrap(),
            Some(Vec::new())
        );
    }

    /// `security` emits hex whenever the stored value contains a newline. The
    /// reader must hand that form through byte-for-byte; decoding it is the
    /// credential layer's job.
    #[test]
    #[cfg(unix)]
    fn read_generic_password_passes_the_hex_form_through_unchanged() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(
            &bin,
            "#!/bin/sh\nprintf '7b226f61757468546f6b656e223a22746f6b227d0a\\n'\n",
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);

        let bytes = read_generic_password("Claude Code-credentials", None)
            .unwrap()
            .expect("password");
        assert_eq!(bytes, b"7b226f61757468546f6b656e223a22746f6b227d0a");
    }

    #[test]
    fn read_generic_password_returns_none_on_not_found() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(
            &bin,
            "#!/bin/sh\n\
             echo 'security: item could not be found in the keychain' >&2\n\
             exit 44\n",
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        let result = read_generic_password("Claude Code-credentials", Some("missing")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_generic_password_surfaces_canceled_error() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(
            &bin,
            "#!/bin/sh\n\
             echo 'User canceled.' >&2\n\
             exit 128\n",
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        let err = read_generic_password("Claude Code-credentials", Some("tester")).unwrap_err();
        assert!(err.to_string().contains("Keychain access was denied"));
    }

    #[test]
    fn read_generic_password_surfaces_generic_error() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(
            &bin,
            "#!/bin/sh\n\
             echo 'unexpected failure' >&2\n\
             exit 1\n",
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        let err = read_generic_password("Claude Code-credentials", Some("tester")).unwrap_err();
        assert!(err
            .to_string()
            .contains("could not read macOS Keychain generic password"));
    }

    #[test]
    fn find_generic_password_account_returns_none_on_not_found() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(
            &bin,
            "#!/bin/sh\n\
             echo 'security: item could not be found in the keychain' >&2\n\
             exit 44\n",
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        let account = find_generic_password_account("aisw").unwrap();
        assert!(account.is_none());
    }

    #[test]
    fn find_generic_password_account_surfaces_generic_error() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(
            &bin,
            "#!/bin/sh\n\
             echo 'parse blew up' >&2\n\
             exit 1\n",
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        let err = find_generic_password_account("aisw").unwrap_err();
        assert!(err
            .to_string()
            .contains("could not inspect macOS Keychain generic password"));
    }

    /// Pins the `security(1)` behaviour the reader is written against, using
    /// the real binary rather than a stub.
    ///
    /// Every other test here mocks `security`, and a mock cannot model the one
    /// thing that mattered in #250: the CLI switches from text to hex output
    /// the moment the stored value contains a newline, and that switch happens
    /// inside the binary. If a future macOS changes the framing or the
    /// threshold for the hex form, the fix's central assumption — that a
    /// text-mode value provably has no newline of its own — stops holding, and
    /// this is what says so.
    ///
    /// Hermetic: a throwaway keychain in a temp dir, never added to the search
    /// list, so the login keychain is not consulted and no real credential is
    /// touched. The item is both written and read by `security` itself, so
    /// there is no cross-application access check to prompt for.
    #[test]
    #[cfg(target_os = "macos")]
    fn real_security_cli_output_framing_matches_the_reader() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let keychain = dir.path().join("aisw-test.keychain-db");

        let created = Command::new("security")
            .args(["create-keychain", "-p", "aisw-test"])
            .arg(&keychain)
            .output()
            .expect("security should be available on macOS");
        assert!(
            created.status.success(),
            "could not create the throwaway keychain: {}",
            String::from_utf8_lossy(&created.stderr)
        );
        let _keychain_cleanup = ThrowawayKeychain(keychain.clone());

        let unlocked = Command::new("security")
            .args(["unlock-keychain", "-p", "aisw-test"])
            .arg(&keychain)
            .output()
            .expect("security should be available on macOS");
        assert!(unlocked.status.success(), "could not unlock the keychain");

        let _bin = EnvVarGuard::unset("AISW_SECURITY_BIN");
        let _path = EnvVarGuard::set("AISW_SECURITY_KEYCHAIN", &keychain);

        // Text form: the CLI appends a terminator the reader has to drop, and
        // a trailing space inside the value survives, which is why only the
        // final newline may come off.
        store_exact(&keychain, "clean", b"{\"oauthToken\":\"tok\"} ");
        assert_eq!(
            read_generic_password("clean", Some("tester"))
                .unwrap()
                .unwrap(),
            b"{\"oauthToken\":\"tok\"} ",
            "the reader must strip the CLI terminator and nothing else"
        );

        // Hex form: this is the state #250 left the Keychain in. The reader
        // hands it through, and the credential layer decodes it back to the
        // original bytes, trimming only the edges.
        let with_newline = b"{\"oauthToken\":\"tok\"}\n";
        store_exact(&keychain, "newline", with_newline);
        let raw = read_generic_password("newline", Some("tester"))
            .unwrap()
            .unwrap();
        assert!(
            raw.iter().all(u8::is_ascii_hexdigit),
            "security should print a value containing a newline as hex, got: {}",
            String::from_utf8_lossy(&raw)
        );
        assert_eq!(
            crate::auth::claude::normalize_credentials_bytes(&raw).unwrap(),
            br#"{"oauthToken":"tok"}"#,
            "decoding the hex form must recover the payload without the newline"
        );

        // An empty stored value must stay distinguishable from a missing item.
        assert!(read_generic_password("absent", Some("tester"))
            .unwrap()
            .is_none());
    }

    /// Exercise the signed writer and Apple's real interactive parser. Every
    /// item operation targets an unlisted private Keychain, never the login
    /// Keychain, and creating/deleting it must leave selection unchanged.
    #[test]
    #[cfg(target_os = "macos")]
    fn real_signed_writer_preserves_reader_access_across_updates() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        fn selection() -> Vec<Vec<u8>> {
            ["default-keychain", "list-keychains"]
                .iter()
                .map(|arg| {
                    let output = Command::new("/usr/bin/security").arg(arg).output().unwrap();
                    assert!(output.status.success());
                    output.stdout
                })
                .collect()
        }
        let before = selection();
        let dir = tempdir().unwrap();
        // Apple's partition-enabled format is selected by the pathname's
        // Library/Keychains components, even outside the user's actual home.
        // This stays wholly temporary and avoids the special login filename.
        let keychain_dir = dir.path().join("Library/Keychains");
        fs::create_dir_all(&keychain_dir).unwrap();
        let keychain = keychain_dir.join("aisw-writer-test.keychain-db");
        let created = Command::new("/usr/bin/security")
            .args(["create-keychain", "-p", "synthetic-test-password"])
            .arg(&keychain)
            .output()
            .unwrap();
        assert!(created.status.success(), "private Keychain creation failed");
        let cleanup = ThrowawayKeychain(keychain.clone());
        assert_eq!(selection(), before, "private creation changed selection");
        let _bin = EnvVarGuard::unset("AISW_SECURITY_BIN");
        let _path = EnvVarGuard::set("AISW_SECURITY_KEYCHAIN", &keychain);
        let service = "aisw private writer fixture";
        let account = "tést\"er\\ $(literal)";
        let trusted = [PathBuf::from("/usr/bin/true")];
        upsert_generic_password(service, account, b"first", &trusted).unwrap();
        for payload in [b"first".as_slice(), b"second ", b"third"] {
            upsert_generic_password(
                service,
                account,
                payload,
                &[PathBuf::from("/usr/bin/false")],
            )
            .unwrap();
            assert_eq!(
                read_generic_password(service, Some(account))
                    .unwrap()
                    .unwrap(),
                payload,
                "the signed reader must read every updated value exactly"
            );
            let dumped = Command::new("/usr/bin/security")
                .args(["dump-keychain", "-a"])
                .arg(&keychain)
                .output()
                .unwrap();
            assert!(dumped.status.success());
            let acl = String::from_utf8_lossy(&dumped.stdout);
            assert!(
                acl.contains("version: 512"),
                "fixture must use partition ACLs"
            );
            assert!(acl.contains("/usr/bin/security"), "reader approval lost");
            assert!(acl.contains("/usr/bin/true"), "original approval lost");
            assert!(!acl.contains("/usr/bin/false"), "update replaced approvals");
            assert!(acl.contains("partition_id"), "partition ACL missing");
            assert!(acl.contains("apple-tool:"), "signed writer partition lost");
        }
        // Binary/newline values are written as exact bytes; security prints
        // them as hex. This expectation is independent of AISW's normalizer.
        upsert_generic_password(service, account, b"a\0b\n", &[]).unwrap();
        assert_eq!(
            read_generic_password(service, Some(account))
                .unwrap()
                .unwrap(),
            b"6100620a"
        );
        drop(cleanup);
        assert!(!keychain.exists(), "private Keychain was not cleaned up");
        assert_eq!(selection(), before, "private deletion changed selection");
    }

    /// Writes exact bytes into the throwaway keychain via `-X`, so the test
    /// controls the stored value down to the byte rather than going through
    /// the CLI's line-oriented password prompt.
    #[cfg(target_os = "macos")]
    fn store_exact(keychain: &std::path::Path, service: &str, value: &[u8]) {
        let hex: String = value.iter().map(|byte| format!("{byte:02x}")).collect();
        let output = Command::new("security")
            .args([
                "add-generic-password",
                "-U",
                "-a",
                "tester",
                "-s",
                service,
                "-X",
                &hex,
            ])
            .arg(keychain)
            .output()
            .expect("security should be available on macOS");
        assert!(
            output.status.success(),
            "could not store the {service} fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Deletes the throwaway keychain on drop, so a failed assertion does not
    /// strand it.
    #[cfg(target_os = "macos")]
    struct ThrowawayKeychain(std::path::PathBuf);

    #[cfg(target_os = "macos")]
    impl Drop for ThrowawayKeychain {
        fn drop(&mut self) {
            let _ = Command::new("/usr/bin/security")
                .arg("delete-keychain")
                .arg(&self.0)
                .output();
        }
    }

    #[test]
    #[cfg(unix)]
    fn read_generic_password_uses_explicit_keychain_path_for_aisw_service() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        let marker = dir.path().join("args");
        fs::write(
            &bin,
            format!(
                "#!/bin/sh\n\
                 printf '%s ' \"$@\" > \"{}\"\n\
                 if [ \"$1\" = \"find-generic-password\" ] && [ \"$2\" = \"-s\" ] && [ \"$3\" = \"aisw\" ] && [ \"$4\" = \"-a\" ] && [ \"$5\" = \"profile:claude:default\" ] && [ \"$6\" = \"-w\" ]; then\n\
                   printf 'secret\\n'\n\
                   exit 0\n\
                 fi\n\
                 exit 1\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();

        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);

        let bytes = read_generic_password("aisw", Some("profile:claude:default"))
            .unwrap()
            .expect("password");
        assert_eq!(bytes, b"secret");
        assert_eq!(
            fs::read_to_string(marker).unwrap(),
            "find-generic-password -s aisw -a profile:claude:default -w "
        );
    }

    #[test]
    #[cfg(unix)]
    fn upsert_generic_password_writes_secret_via_stdin_and_trusts_apps() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        let marker = dir.path().join("args");
        let stdin_capture = dir.path().join("stdin");
        fs::write(
            &bin,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = \"find-generic-password\" ]; then exit 44; fi\n\
                 printf '%s ' \"$@\" > \"{}\"\n\
                 cat > \"{}\"\n\
                 exit 0\n",
                marker.display(),
                stdin_capture.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();

        let trusted = dir.path().join("claude");
        fs::write(&trusted, "").unwrap();
        fs::set_permissions(&trusted, fs::Permissions::from_mode(0o755)).unwrap();

        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);

        upsert_generic_password(
            "Claude Code-credentials",
            "tester",
            br#"{"claudeAiOauth":{"accessToken":"tok"}}"#,
            std::slice::from_ref(&trusted),
        )
        .unwrap();

        assert_eq!(fs::read_to_string(marker).unwrap(), "-q -i ");
        assert_eq!(
            fs::read_to_string(stdin_capture).unwrap(),
            format!(
                "\"add-generic-password\" \"-s\" \"Claude Code-credentials\" \"-a\" \"tester\" \"-T\" \"/usr/bin/security\" \"-T\" \"{}\" \"-X\" \"7b22636c6175646541694f61757468223a7b22616363657373546f6b656e223a22746f6b227d7d\"\n",
                trusted.display()
            )
        );
    }

    /// Updating credentials must not also replace the application's approval
    /// list: passing -T on an existing entry requests a separate ACL change.
    #[test]
    fn upsert_existing_password_does_not_rewrite_trusted_apps() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        let input = dir.path().join("input");
        write_mock_security(
            &bin,
            &format!(
                "#!/bin/sh\nif [ \"$1\" = find-generic-password ]; then exit 0; fi\ncat > '{}'\n",
                input.display()
            ),
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        upsert_generic_password(
            "Claude Code-credentials",
            "tester",
            b"new",
            &[PathBuf::from("/usr/bin/true")],
        )
        .unwrap();
        assert_eq!(fs::read_to_string(input).unwrap(),
            "\"add-generic-password\" \"-U\" \"-s\" \"Claude Code-credentials\" \"-a\" \"tester\" \"-X\" \"6e6577\"\n");
    }

    #[test]
    fn upsert_rejects_oversized_input_before_starting_a_writer() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        let marker = dir.path().join("writer-started");
        write_mock_security(&bin, &format!(
            "#!/bin/sh\nif [ \"$1\" = find-generic-password ]; then exit 44; fi\ntouch '{}'\ncat >/dev/null\n",
            marker.display()
        ));
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        assert!(upsert_generic_password(
            "Claude Code-credentials",
            "tester",
            &vec![b'x'; 4096],
            &[]
        )
        .is_err());
        assert!(
            !marker.exists(),
            "oversized input must never reach the line-limited writer"
        );
    }

    #[test]
    fn upsert_enforces_security_parser_limit_at_the_boundary() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        let capture = dir.path().join("input");
        write_mock_security(
            &bin,
            &format!(
                "#!/bin/sh\nif [ \"$1\" = find-generic-password ]; then exit 44; fi\ncat > '{}'\n",
                capture.display()
            ),
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        let framing = "\"add-generic-password\" \"-s\" \"s\" \"-a\" \"a\" \"-T\" \"/usr/bin/security\" \"-X\" \"\"\n";
        let mut service = "s".to_owned();
        if (4095 - framing.len()) % 2 != 0 {
            service.push('s');
        }
        let secret = vec![0xAB; (4095 - framing.len() - service.len()).div_ceil(2)];
        upsert_generic_password(&service, "a", &secret, &[]).unwrap();
        let command = fs::read(&capture).unwrap();
        assert_eq!(command.len(), 4095);
        assert!(
            command.ends_with(b"\"\n"),
            "no truncation at the safe limit"
        );
        fs::remove_file(&capture).unwrap();
        service.push('s');
        assert!(upsert_generic_password(&service, "a", &secret, &[]).is_err());
        assert!(
            !capture.exists(),
            "4096-byte input must not reach the writer"
        );
    }

    #[test]
    fn upsert_rejects_excessive_trusted_apps_before_writing() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        let marker = dir.path().join("writer-started");
        write_mock_security(&bin, &format!(
            "#!/bin/sh\nif [ \"$1\" = find-generic-password ]; then exit 44; fi\ntouch '{}'\ncat >/dev/null\n",
            marker.display()
        ));
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        let apps = vec![PathBuf::from("/usr/bin/true"); 16];
        assert!(upsert_generic_password("service", "account", b"secret", &apps).is_err());
        assert!(!marker.exists());
    }

    #[test]
    fn upsert_rejects_command_separators_before_starting_a_process() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        let marker = dir.path().join("started");
        write_mock_security(
            &bin,
            &format!("#!/bin/sh\ntouch '{}'\ncat >/dev/null\n", marker.display()),
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        for account in ["tester\nhelp", "tester\rhelp", "tester\0help"] {
            assert!(
                upsert_generic_password("Claude Code-credentials", account, b"secret", &[])
                    .is_err()
            );
        }
        assert!(!marker.exists());
    }

    #[test]
    fn upsert_failure_never_exposes_the_secret_or_stdin() {
        if std::env::var_os("AISW_KEYCHAIN_SECRET_TEST_CHILD").is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "auth::macos_keychain::tests::upsert_failure_never_exposes_the_secret_or_stdin",
                    "--nocapture",
                ])
                .env("AISW_KEYCHAIN_SECRET_TEST_CHILD", "1")
                .output()
                .unwrap();
            assert!(output.status.success());
            for bytes in [&output.stdout, &output.stderr] {
                let text = String::from_utf8_lossy(bytes);
                assert!(
                    !text.contains("fixture-secret"),
                    "child output must never expose a credential"
                );
                assert!(
                    !text.contains("666978747572652d736563726574"),
                    "child output must never expose its hex encoding"
                );
            }
            return;
        }
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(&bin, "#!/bin/sh\nif [ \"$1\" = find-generic-password ]; then exit 44; fi\ncat >&2\necho fixture-secret >&2\nexit 1\n");
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        let err =
            upsert_generic_password("Claude Code-credentials", "tester", b"fixture-secret", &[])
                .unwrap_err();
        let message = format!("{err:#}");
        assert!(!message.contains("fixture-secret"));
        assert!(!message.contains("666978747572652d736563726574"));
    }

    #[test]
    fn upsert_generic_password_surfaces_canceled_error() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(
            &bin,
            "#!/bin/sh\n\
             if [ \"$1\" = find-generic-password ]; then exit 44; fi\n\
             cat >/dev/null\n\
             echo 'User canceled.' >&2\n\
             exit 128\n",
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        let err = upsert_generic_password("aisw", "acct", b"secret", &[]).unwrap_err();
        assert!(err.to_string().contains("Keychain access was denied"));
    }

    #[test]
    fn upsert_generic_password_surfaces_generic_error() {
        let _g = crate::SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        let bin = dir.path().join("security");
        write_mock_security(
            &bin,
            "#!/bin/sh\n\
             if [ \"$1\" = find-generic-password ]; then exit 44; fi\n\
             cat >/dev/null\n\
             echo 'boom' >&2\n\
             exit 1\n",
        );
        let _security = EnvVarGuard::set("AISW_SECURITY_BIN", &bin);
        let err = upsert_generic_password("aisw", "acct", b"secret", &[]).unwrap_err();
        assert!(err
            .to_string()
            .contains("could not update macOS Keychain generic password"));
    }
}
