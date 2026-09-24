//! macOS Seatbelt profiles for `sandbox-exec`.
//!
//! Profiles deny by default. In SBPL the last matching rule wins, so the
//! protected-path denials come last and override every allowance above them,
//! including the working directory when it is writable. Paths reach the
//! profile only as parameters (`-D NAME=value`), never spliced into its text,
//! so no path can change the profile's meaning.

use std::{
    fmt::Write,
    path::{Path, PathBuf},
};

use tokio::process::Command;

use crate::policy::Grants;

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// What every command may do: read non-protected files, write its private
/// temporary directory and /dev/null, and resolve user names.
const BASE: &str = r#"(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow signal (target same-sandbox))
(allow sysctl-read)
(allow file-read*)
(allow file-write-data (literal "/dev/null"))
(allow file-write* (subpath (param "TMP")))
(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))
"#;

const WRITABLE: &str = "(allow file-write* (subpath (param \"CWD\")))\n";

/// DNS, TLS trust evaluation and network configuration, plus sockets.
const NETWORK: &str = r#"(allow network-outbound)
(allow system-socket)
(allow mach-lookup (global-name "com.apple.dnssd.service" "com.apple.trustd" "com.apple.trustd.agent" "com.apple.SystemConfiguration.configd"))
"#;

/// Any macOS service: launching apps, AppleScript, the clipboard. Commands
/// with this grant can act outside the sandbox through those services.
const SYSTEM_SERVICES: &str = r#"(allow mach-lookup)
(allow appleevent-send)
(allow ipc-posix-shm)
"#;

/// Environment files hold credentials wherever they live.
const DENY_ENV_FILES: &str = "(deny file-read* file-write* (regex #\"/\\.env(\\.[^/]*)?$\"))\n";

/// A profile plus the parameter values it refers to.
#[derive(Debug, Clone)]
pub struct SandboxProfile {
    text: String,
    params: Vec<(String, PathBuf)>,
}

impl SandboxProfile {
    pub fn new(grants: Grants, working_dir: &Path, temp_dir: &Path, protected: &[PathBuf]) -> Self {
        let mut text = String::from(BASE);
        let mut params = vec![
            ("TMP".to_owned(), temp_dir.to_owned()),
            ("CWD".to_owned(), working_dir.to_owned()),
        ];
        if grants.writable {
            text.push_str(WRITABLE);
        }
        if grants.network {
            text.push_str(NETWORK);
        }
        if grants.system_services {
            text.push_str(SYSTEM_SERVICES);
        }
        for (index, path) in protected.iter().enumerate() {
            let name = format!("PROTECTED_{index}");
            let _ = writeln!(
                text,
                "(deny file-read* file-write* (subpath (param \"{name}\")))"
            );
            params.push((name, path.clone()));
        }
        text.push_str(DENY_ENV_FILES);
        Self { text, params }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    /// `sandbox-exec -p <profile> -D ... -- <program> <args...>`.
    pub fn command(&self, program: &Path, args: &[String]) -> Command {
        let mut command = Command::new(SANDBOX_EXEC);
        command.arg("-p").arg(&self.text);
        for (name, value) in &self.params {
            let mut definition = std::ffi::OsString::from(format!("{name}="));
            definition.push(value);
            command.arg("-D").arg(definition);
        }
        command.arg("--").arg(program).args(args);
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_add_exactly_their_rules() {
        let none = SandboxProfile::new(Grants::default(), Path::new("/w"), Path::new("/t"), &[]);
        assert!(!none.text().contains("(param \"CWD\")))"));
        assert!(!none.text().contains("network-outbound"));
        assert!(!none.text().contains("(allow mach-lookup)\n"));

        let all = SandboxProfile::new(
            Grants {
                writable: true,
                network: true,
                system_services: true,
            },
            Path::new("/w"),
            Path::new("/t"),
            &[],
        );
        assert!(all.text().contains(WRITABLE));
        assert!(all.text().contains("(allow network-outbound)"));
        assert!(all.text().contains("(allow mach-lookup)\n"));
    }

    #[test]
    fn protections_come_last_and_paths_are_parameters() {
        let tricky = PathBuf::from("/Users/x/evil\") (allow default) (\"");
        let profile = SandboxProfile::new(
            Grants {
                writable: true,
                ..Grants::default()
            },
            Path::new("/w"),
            Path::new("/t"),
            std::slice::from_ref(&tricky),
        );
        let text = profile.text();
        assert!(!text.contains("evil"), "paths never enter the profile text");
        let last_allow = text.rfind("(allow").unwrap_or(0);
        let first_deny = text.find("(deny file-read* file-write*").unwrap_or(0);
        assert!(first_deny > last_allow, "denials must follow every allow");
        assert!(
            profile
                .params
                .iter()
                .any(|(name, value)| name == "PROTECTED_0" && value == &tricky)
        );
    }
}
