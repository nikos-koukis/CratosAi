//! Runs one command in the sandbox with a scrubbed environment, a private
//! temporary directory, bounded output and a hard timeout.
//!
//! The command gets its own process group. On timeout the whole group gets
//! SIGTERM, then SIGKILL; after a normal exit any processes it left behind
//! are killed too, so nothing outlives its command.

use std::{
    fs::DirBuilder,
    io,
    os::unix::{fs::DirBuilderExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::{Duration, Instant},
};

use rustix::process::{Pid, Signal, kill_process_group};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{approval::CommandSpec, sandbox::SandboxProfile};

const KILL_GRACE: Duration = Duration::from_secs(2);
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Execution {
    /// Exit status, or -1 when killed by a signal.
    pub exit_code: i32,
    /// Terminating signal, or 0.
    pub signal: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub duration: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("cannot create the command's temporary directory")]
    TempDir(#[source] io::Error),
    #[error("cannot start the sandbox")]
    Spawn(#[source] io::Error),
    #[error("cannot wait for the command")]
    Wait(#[source] io::Error),
}

#[derive(Debug)]
pub struct Executor {
    protected_paths: Vec<PathBuf>,
    max_output_bytes: usize,
    temp_root: PathBuf,
    home: PathBuf,
    user: String,
}

impl Executor {
    pub fn new(
        protected_paths: Vec<PathBuf>,
        max_output_bytes: usize,
        temp_root: PathBuf,
        home: PathBuf,
        user: String,
    ) -> Self {
        Self {
            protected_paths,
            max_output_bytes,
            temp_root,
            home,
            user,
        }
    }

    pub async fn run(&self, spec: &CommandSpec) -> Result<Execution, ExecError> {
        let temp_dir = self.temp_root.join(format!("run-{}", uuid::Uuid::new_v4()));
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&temp_dir)
            .map_err(ExecError::TempDir)?;

        let result = self.run_in(spec, &temp_dir).await;
        if let Err(error) = tokio::fs::remove_dir_all(&temp_dir).await {
            tracing::warn!(%error, dir = %temp_dir.display(), "cannot remove command temp dir");
        }
        result
    }

    async fn run_in(&self, spec: &CommandSpec, temp_dir: &Path) -> Result<Execution, ExecError> {
        let profile = SandboxProfile::new(
            spec.grants,
            &spec.working_dir,
            temp_dir,
            &self.protected_paths,
        );
        let mut command = profile.command(&spec.program, &spec.args);
        let mut tmpdir = temp_dir.as_os_str().to_owned();
        tmpdir.push("/");
        command
            .current_dir(&spec.working_dir)
            .env_clear()
            .env("PATH", SAFE_PATH)
            .env("HOME", &self.home)
            .env("USER", &self.user)
            .env("LOGNAME", &self.user)
            .env("TMPDIR", tmpdir)
            .env("LANG", "en_US.UTF-8")
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .env("PAGER", "cat")
            .env("GIT_PAGER", "cat")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .kill_on_drop(true);

        let started = Instant::now();
        let mut child = command.spawn().map_err(ExecError::Spawn)?;
        let group = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(Pid::from_raw);

        let cap = self.max_output_bytes;
        let stdout = child
            .stdout
            .take()
            .map(|pipe| tokio::spawn(read_capped(pipe, cap)));
        let stderr = child
            .stderr
            .take()
            .map(|pipe| tokio::spawn(read_capped(pipe, cap)));

        let (status, timed_out) = match tokio::time::timeout(spec.timeout, child.wait()).await {
            Ok(status) => (status.map_err(ExecError::Wait)?, false),
            Err(_) => {
                signal_group(group, Signal::TERM);
                let status = match tokio::time::timeout(KILL_GRACE, child.wait()).await {
                    Ok(status) => status.map_err(ExecError::Wait)?,
                    Err(_) => {
                        signal_group(group, Signal::KILL);
                        child.wait().await.map_err(ExecError::Wait)?
                    }
                };
                (status, true)
            }
        };
        let duration = started.elapsed();
        // Nothing the command started may outlive it (or hold its pipes open).
        signal_group(group, Signal::KILL);

        let (stdout, stdout_truncated) = collect(stdout).await;
        let (stderr, stderr_truncated) = collect(stderr).await;
        let (exit_code, signal) = exit_parts(status);
        Ok(Execution {
            exit_code,
            signal,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            timed_out,
            duration,
        })
    }
}

fn signal_group(group: Option<Pid>, signal: Signal) {
    if let Some(group) = group {
        // ESRCH (group already gone) is the normal case after a clean exit.
        let _ = kill_process_group(group, signal);
    }
}

fn exit_parts(status: ExitStatus) -> (i32, i32) {
    match (status.code(), status.signal()) {
        (Some(code), _) => (code, 0),
        (None, Some(signal)) => (-1, signal),
        (None, None) => (-1, 0),
    }
}

async fn collect(reader: Option<tokio::task::JoinHandle<(Vec<u8>, bool)>>) -> (Vec<u8>, bool) {
    let Some(reader) = reader else {
        return (Vec::new(), false);
    };
    match tokio::time::timeout(OUTPUT_DRAIN_TIMEOUT, reader).await {
        Ok(Ok(output)) => output,
        _ => (Vec::new(), true),
    }
}

/// Keeps the first `cap` bytes and drains the rest so the writer never blocks.
async fn read_capped(mut reader: impl AsyncRead + Unpin, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let room = cap.saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..read.min(room)]);
                truncated |= read > room;
            }
        }
    }
    (kept, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn output_is_capped_and_flagged() {
        let data = vec![b'x'; 100];
        let (kept, truncated) = read_capped(data.as_slice(), 10).await;
        assert_eq!(kept.len(), 10);
        assert!(truncated);

        let (kept, truncated) = read_capped(&b"short"[..], 10).await;
        assert_eq!(kept, b"short");
        assert!(!truncated);
    }
}
