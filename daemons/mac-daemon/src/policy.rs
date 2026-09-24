//! What may run, where, and with which sandbox grants.
//!
//! * Programs on the deny list never run.
//! * A command matching an allowlist entry runs with that entry's grants.
//! * Anything else (unlisted, or asking for more grants than its entry gives)
//!   needs the user's signed approval.
//! * The working directory must lie inside a workspace root and outside every
//!   protected path.

use std::{
    collections::HashSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use crate::proto::device_v1;

/// What a command may do beyond reading non-protected files.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Grants {
    pub writable: bool,
    pub network: bool,
    pub system_services: bool,
}

impl Grants {
    /// True if every grant in `other` is also in `self`.
    pub const fn covers(self, other: Self) -> bool {
        (self.writable || !other.writable)
            && (self.network || !other.network)
            && (self.system_services || !other.system_services)
    }

    pub fn to_proto(self) -> device_v1::SandboxGrants {
        device_v1::SandboxGrants {
            writable: self.writable,
            network: self.network,
            system_services: self.system_services,
        }
    }

    pub fn from_proto(grants: &device_v1::SandboxGrants) -> Self {
        Self {
            writable: grants.writable,
            network: grants.network,
            system_services: grants.system_services,
        }
    }
}

/// One allowlist entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandRule {
    /// Canonical absolute path of the executable.
    pub program: PathBuf,
    pub args_prefix: Vec<String>,
    pub allow_extra_args: bool,
    pub grants: Grants,
    pub requires_approval: bool,
    pub description: String,
}

impl CommandRule {
    fn matches(&self, program: &Path, args: &[String]) -> bool {
        self.program == program
            && args.starts_with(&self.args_prefix)
            && (self.allow_extra_args || args.len() == self.args_prefix.len())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Run now with these grants.
    Run(Grants),
    /// Run only after a signed approval, with these grants.
    NeedsApproval(Grants),
    /// Never run.
    Denied,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    #[error("{0} must be an absolute path")]
    NotAbsolute(&'static str),
    #[error("{0} does not exist or is not accessible")]
    Missing(&'static str),
    #[error("program is not an executable file")]
    NotExecutable,
    #[error("working directory is not a directory")]
    NotADirectory,
    #[error("working directory is outside the workspace roots or inside a protected path")]
    OutsideWorkspace,
}

/// The enforced command policy.
#[derive(Clone, Debug)]
pub struct CommandPolicy {
    /// Canonical workspace roots; the first is the default working directory.
    pub workspace_roots: Vec<PathBuf>,
    /// Paths commands may neither read nor write (canonical where they exist).
    pub protected_paths: Vec<PathBuf>,
    /// Canonical paths of programs that never run.
    pub denied_programs: HashSet<PathBuf>,
    pub rules: Vec<CommandRule>,
}

impl CommandPolicy {
    /// Decides how `program` (canonical) with `args` may run. `requested`
    /// grants default to the matching entry's grants.
    pub fn decide(&self, program: &Path, args: &[String], requested: Option<Grants>) -> Decision {
        if self.denied_programs.contains(program) {
            return Decision::Denied;
        }
        let matching: Vec<&CommandRule> = self
            .rules
            .iter()
            .filter(|rule| rule.matches(program, args))
            .collect();

        let runnable = matching.iter().find(|rule| {
            !rule.requires_approval && requested.is_none_or(|wanted| rule.grants.covers(wanted))
        });
        if let Some(rule) = runnable {
            return Decision::Run(requested.unwrap_or(rule.grants));
        }
        let grants = requested
            .or_else(|| matching.first().map(|rule| rule.grants))
            .unwrap_or_default();
        Decision::NeedsApproval(grants)
    }

    /// Resolves the program to its canonical path; it must be an executable file.
    pub fn resolve_program(program: &str) -> Result<PathBuf, PathError> {
        let path = Path::new(program);
        if program.is_empty() || !path.is_absolute() {
            return Err(PathError::NotAbsolute("program"));
        }
        let canonical = fs::canonicalize(path).map_err(|_| PathError::Missing("program"))?;
        let metadata = fs::metadata(&canonical).map_err(|_| PathError::Missing("program"))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(PathError::NotExecutable);
        }
        Ok(canonical)
    }

    /// Resolves the working directory (default: first workspace root).
    pub fn resolve_working_dir(&self, requested: &str) -> Result<PathBuf, PathError> {
        let canonical = if requested.is_empty() {
            self.workspace_roots
                .first()
                .cloned()
                .ok_or(PathError::OutsideWorkspace)?
        } else {
            let path = Path::new(requested);
            if !path.is_absolute() {
                return Err(PathError::NotAbsolute("working_directory"));
            }
            fs::canonicalize(path).map_err(|_| PathError::Missing("working_directory"))?
        };
        if !canonical.is_dir() {
            return Err(PathError::NotADirectory);
        }
        let inside_root = self
            .workspace_roots
            .iter()
            .any(|root| canonical.starts_with(root));
        let protected = self
            .protected_paths
            .iter()
            .any(|path| canonical.starts_with(path));
        if inside_root && !protected {
            Ok(canonical)
        } else {
            Err(PathError::OutsideWorkspace)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const GIT: &str = "/usr/bin/git";

    fn rule(prefix: &[&str], extra: bool, grants: Grants) -> CommandRule {
        CommandRule {
            program: PathBuf::from(GIT),
            args_prefix: prefix.iter().map(|s| (*s).to_owned()).collect(),
            allow_extra_args: extra,
            grants,
            requires_approval: false,
            description: String::new(),
        }
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }

    fn policy(rules: Vec<CommandRule>) -> CommandPolicy {
        CommandPolicy {
            workspace_roots: vec![fs::canonicalize(std::env::temp_dir()).unwrap()],
            protected_paths: vec![],
            denied_programs: HashSet::from([PathBuf::from("/usr/bin/sudo")]),
            rules,
        }
    }

    const NONE: Grants = Grants {
        writable: false,
        network: false,
        system_services: false,
    };
    const NETWORK: Grants = Grants {
        writable: false,
        network: true,
        system_services: false,
    };

    #[test]
    fn prefix_and_extra_args_are_enforced() {
        let p = policy(vec![
            rule(&["status"], false, NONE),
            rule(&["log"], true, NONE),
        ]);
        let git = Path::new(GIT);
        assert_eq!(p.decide(git, &args(&["status"]), None), Decision::Run(NONE));
        assert_eq!(
            p.decide(git, &args(&["status", "--porcelain"]), None),
            Decision::NeedsApproval(NONE)
        );
        assert_eq!(
            p.decide(git, &args(&["log", "-5", "--oneline"]), None),
            Decision::Run(NONE)
        );
        assert_eq!(
            p.decide(git, &args(&["push"]), None),
            Decision::NeedsApproval(NONE)
        );
        assert_eq!(
            p.decide(Path::new("/bin/ls"), &args(&[]), None),
            Decision::NeedsApproval(NONE)
        );
    }

    #[test]
    fn denied_programs_never_run() {
        let mut p = policy(vec![]);
        p.rules.push(CommandRule {
            program: PathBuf::from("/usr/bin/sudo"),
            ..rule(&[], true, NONE)
        });
        assert_eq!(
            p.decide(Path::new("/usr/bin/sudo"), &args(&["ls"]), None),
            Decision::Denied
        );
    }

    #[test]
    fn grants_beyond_the_entry_need_approval() {
        let p = policy(vec![rule(&["fetch"], false, NETWORK)]);
        let git = Path::new(GIT);
        assert_eq!(
            p.decide(git, &args(&["fetch"]), None),
            Decision::Run(NETWORK)
        );
        assert_eq!(
            p.decide(git, &args(&["fetch"]), Some(NONE)),
            Decision::Run(NONE),
            "asking for less is fine"
        );
        let more = Grants {
            writable: true,
            ..NETWORK
        };
        assert_eq!(
            p.decide(git, &args(&["fetch"]), Some(more)),
            Decision::NeedsApproval(more)
        );
    }

    #[test]
    fn entries_can_require_approval_every_time() {
        let mut entry = rule(&["push"], true, NETWORK);
        entry.requires_approval = true;
        let p = policy(vec![entry]);
        assert_eq!(
            p.decide(Path::new(GIT), &args(&["push"]), None),
            Decision::NeedsApproval(NETWORK)
        );
    }

    #[test]
    fn working_directory_is_confined() {
        let root = fs::canonicalize(std::env::temp_dir()).unwrap();
        let inside = root.join(format!("jarvis-policy-test-{}", uuid::Uuid::new_v4()));
        let protected = inside.join("secrets");
        fs::create_dir_all(&protected).unwrap();

        let mut p = policy(vec![]);
        p.protected_paths.push(protected.clone());

        assert_eq!(p.resolve_working_dir("").unwrap(), root);
        assert_eq!(
            p.resolve_working_dir(inside.to_str().unwrap()).unwrap(),
            inside
        );
        assert_eq!(
            p.resolve_working_dir(protected.to_str().unwrap()),
            Err(PathError::OutsideWorkspace)
        );
        assert_eq!(p.resolve_working_dir("/"), Err(PathError::OutsideWorkspace));
        assert_eq!(
            p.resolve_working_dir("relative/dir"),
            Err(PathError::NotAbsolute("working_directory"))
        );
        // `..` cannot climb out: the path is canonicalised first.
        let climb = format!("{}/../../..", inside.display());
        assert_eq!(
            p.resolve_working_dir(&climb),
            Err(PathError::OutsideWorkspace)
        );

        fs::remove_dir_all(inside).unwrap();
    }

    #[test]
    fn programs_resolve_to_canonical_executables() {
        assert_eq!(
            CommandPolicy::resolve_program("/bin/ls").unwrap(),
            PathBuf::from("/bin/ls")
        );
        assert_eq!(
            CommandPolicy::resolve_program("ls"),
            Err(PathError::NotAbsolute("program"))
        );
        assert_eq!(
            CommandPolicy::resolve_program("/no/such/tool"),
            Err(PathError::Missing("program"))
        );
        assert_eq!(
            CommandPolicy::resolve_program("/etc/hosts"),
            Err(PathError::NotExecutable)
        );
    }
}
