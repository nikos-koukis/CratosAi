//! The executor against the real macOS sandbox: what a command can and
//! cannot touch, and that nothing it starts outlives it.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    net::TcpListener,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use jarvis_daemon::{
    approval::CommandSpec,
    executor::{Execution, Executor},
    policy::Grants,
};

const OUTPUT_CAP: usize = 4096;

struct Sandbox {
    base: PathBuf,
    workspace: PathBuf,
    protected: PathBuf,
    outside: PathBuf,
    executor: Executor,
}

impl Sandbox {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("jarvisd-sandbox-{}", uuid::Uuid::new_v4()));
        let workspace = base.join("workspace");
        // Protected paths may sit inside the workspace; the denial still wins.
        let protected = workspace.join("secrets");
        let outside = base.join("outside");
        let temp_root = base.join("tmp");
        for dir in [&workspace, &protected, &outside, &temp_root] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(workspace.join("notes.txt"), "workspace-data").unwrap();
        fs::write(protected.join("key"), "TOP-SECRET").unwrap();
        fs::write(workspace.join(".env"), "PASSWORD=hunter2").unwrap();

        let executor = Executor::new(
            vec![protected.clone()],
            OUTPUT_CAP,
            temp_root,
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            std::env::var("USER").unwrap_or_else(|_| "tester".into()),
        );
        Self {
            base,
            workspace,
            protected,
            outside,
            executor,
        }
    }

    async fn run(
        &self,
        program: &str,
        args: &[&str],
        grants: Grants,
        timeout: Duration,
    ) -> Execution {
        self.executor
            .run(&CommandSpec {
                program: PathBuf::from(program),
                args: args.iter().map(|s| (*s).to_owned()).collect(),
                working_dir: self.workspace.clone(),
                timeout,
                grants,
            })
            .await
            .expect("executor failed")
    }

    async fn sh(&self, script: &str, grants: Grants) -> Execution {
        self.run("/bin/sh", &["-c", script], grants, Duration::from_secs(10))
            .await
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

const NONE: Grants = Grants {
    writable: false,
    network: false,
    system_services: false,
};
const WRITABLE: Grants = Grants {
    writable: true,
    network: false,
    system_services: false,
};

fn stdout(execution: &Execution) -> String {
    String::from_utf8_lossy(&execution.stdout).into_owned()
}

fn stderr(execution: &Execution) -> String {
    String::from_utf8_lossy(&execution.stderr).into_owned()
}

fn denied(execution: &Execution) -> bool {
    execution.exit_code != 0 && stderr(execution).contains("Operation not permitted")
}

fn process_alive(pid: &str) -> bool {
    Command::new("/bin/kill")
        .args(["-0", pid.trim()])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn reads_the_workspace_but_never_protected_paths_or_env_files() {
    let sandbox = Sandbox::new();
    let ok = sandbox
        .run("/bin/cat", &["notes.txt"], NONE, Duration::from_secs(5))
        .await;
    assert_eq!((ok.exit_code, stdout(&ok).as_str()), (0, "workspace-data"));

    let key = sandbox.protected.join("key");
    let secret = sandbox
        .run(
            "/bin/cat",
            &[key.to_str().unwrap()],
            NONE,
            Duration::from_secs(5),
        )
        .await;
    assert!(denied(&secret), "{secret:?}");
    assert!(!stdout(&secret).contains("TOP-SECRET"));

    let env = sandbox
        .run("/bin/cat", &[".env"], NONE, Duration::from_secs(5))
        .await;
    assert!(denied(&env), "{env:?}");

    // A symlink inside the workspace does not bypass the denial.
    symlink(&key, sandbox.workspace.join("link")).unwrap();
    let via_link = sandbox
        .run("/bin/cat", &["link"], NONE, Duration::from_secs(5))
        .await;
    assert!(denied(&via_link), "{via_link:?}");

    // Even a writable command cannot touch protected paths inside the workspace.
    let overwrite = sandbox
        .sh(&format!("echo pwned > '{}'", key.display()), WRITABLE)
        .await;
    assert!(denied(&overwrite), "{overwrite:?}");
    assert_eq!(fs::read_to_string(&key).unwrap(), "TOP-SECRET");
}

#[tokio::test]
async fn writes_only_where_granted() {
    let sandbox = Sandbox::new();

    let read_only = sandbox.sh("echo x > created.txt", NONE).await;
    assert!(denied(&read_only), "{read_only:?}");
    assert!(!sandbox.workspace.join("created.txt").exists());

    let writable = sandbox.sh("echo x > created.txt", WRITABLE).await;
    assert_eq!(writable.exit_code, 0, "{writable:?}");
    assert!(sandbox.workspace.join("created.txt").exists());

    let escape = sandbox
        .sh(
            &format!("echo x > '{}/escaped.txt'", sandbox.outside.display()),
            WRITABLE,
        )
        .await;
    assert!(denied(&escape), "{escape:?}");
    assert!(!sandbox.outside.join("escaped.txt").exists());

    let climb = sandbox
        .sh("echo x > ../outside/climbed.txt", WRITABLE)
        .await;
    assert!(denied(&climb), "{climb:?}");
}

#[tokio::test]
async fn each_command_gets_a_private_temp_dir_that_is_removed() {
    let sandbox = Sandbox::new();
    let run = sandbox
        .sh(r#"echo scratch > "$TMPDIR/f" && cat "$TMPDIR/f""#, NONE)
        .await;
    assert_eq!(
        (run.exit_code, stdout(&run).trim()),
        (0, "scratch"),
        "{run:?}"
    );
    let leftovers = fs::read_dir(sandbox.base.join("tmp")).unwrap().count();
    assert_eq!(leftovers, 0, "temp dirs must be removed after the run");
}

#[tokio::test]
async fn network_needs_its_grant() {
    let sandbox = Sandbox::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();

    let blocked = sandbox
        .run(
            "/usr/bin/nc",
            &["-z", "-w", "2", "127.0.0.1", &port],
            NONE,
            Duration::from_secs(5),
        )
        .await;
    assert_ne!(blocked.exit_code, 0, "{blocked:?}");

    let network = Grants {
        network: true,
        ..NONE
    };
    let allowed = sandbox
        .run(
            "/usr/bin/nc",
            &["-z", "-w", "2", "127.0.0.1", &port],
            network,
            Duration::from_secs(5),
        )
        .await;
    assert_eq!(allowed.exit_code, 0, "{allowed:?}");
}

#[tokio::test]
async fn macos_services_need_their_grant() {
    let sandbox = Sandbox::new();
    // notifyutil talks to notifyd over Mach; the base profile blocks that.
    // (Tools that merely read preference files work either way.)
    let query = ["-g", "com.apple.system.timezone"];
    let blocked = sandbox
        .run("/usr/bin/notifyutil", &query, NONE, Duration::from_secs(5))
        .await;
    assert!(stdout(&blocked).contains("Failed"), "{blocked:?}");

    let services = Grants {
        system_services: true,
        ..NONE
    };
    let allowed = sandbox
        .run(
            "/usr/bin/notifyutil",
            &query,
            services,
            Duration::from_secs(5),
        )
        .await;
    assert!(!stdout(&allowed).contains("Failed"), "{allowed:?}");
    assert_eq!(allowed.exit_code, 0);
}

#[tokio::test]
async fn the_environment_is_scrubbed() {
    let sandbox = Sandbox::new();
    let run = sandbox
        .run("/usr/bin/env", &[], NONE, Duration::from_secs(5))
        .await;
    let keys: Vec<String> = stdout(&run)
        .lines()
        .filter_map(|line| line.split_once('=').map(|(k, _)| k.to_owned()))
        .collect();
    // `cargo test` sets CARGO_* in this process; none may reach the command.
    assert!(!keys.iter().any(|k| k.starts_with("CARGO")), "{keys:?}");
    for expected in ["PATH", "HOME", "TMPDIR", "LANG"] {
        assert!(
            keys.iter().any(|k| k == expected),
            "missing {expected}: {keys:?}"
        );
    }
    assert!(keys.len() <= 12, "unexpected variables: {keys:?}");
}

#[tokio::test]
async fn timeouts_kill_the_whole_process_group() {
    let sandbox = Sandbox::new();
    let run = sandbox
        .run(
            "/bin/sh",
            &["-c", "sleep 31 & echo $!; wait"],
            NONE,
            Duration::from_secs(1),
        )
        .await;
    assert!(run.timed_out, "{run:?}");
    assert!(run.duration < Duration::from_secs(5));
    let child = stdout(&run);
    assert!(!child.trim().is_empty());
    assert!(
        !process_alive(&child),
        "background child {child} survived the timeout"
    );
}

#[tokio::test]
async fn nothing_outlives_a_command_that_exits() {
    let sandbox = Sandbox::new();
    let run = sandbox.sh("sleep 32 >/dev/null 2>&1 & echo $!", NONE).await;
    assert_eq!(run.exit_code, 0, "{run:?}");
    assert!(!run.timed_out);
    let child = stdout(&run);
    assert!(
        !process_alive(&child),
        "background child {child} survived its command"
    );
}

#[tokio::test]
async fn output_is_capped_and_exit_status_reported() {
    let sandbox = Sandbox::new();
    let flood = sandbox.sh("yes | head -c 100000", NONE).await;
    assert_eq!(flood.stdout.len(), OUTPUT_CAP);
    assert!(flood.stdout_truncated);

    let failed = sandbox.sh("echo oops >&2; exit 3", NONE).await;
    assert_eq!((failed.exit_code, failed.signal), (3, 0));
    assert_eq!(stderr(&failed).trim(), "oops");

    let killed = sandbox.sh("kill -9 $$", NONE).await;
    assert_eq!((killed.exit_code, killed.signal), (-1, 9));
}

#[tokio::test]
async fn working_directory_is_the_one_given() {
    let sandbox = Sandbox::new();
    let run = sandbox
        .run("/bin/pwd", &[], NONE, Duration::from_secs(5))
        .await;
    assert_eq!(Path::new(stdout(&run).trim()), sandbox.workspace);
}
