//! End-to-end: the daemon over mTLS, with policy, approvals and the sandbox.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::*;
use jarvis_daemon::proto::device_v1::{
    ApprovalPayload, ApprovalRequired, CommandResult, ExecuteCommandResponse,
    GetCapabilitiesRequest, SandboxGrants, execute_command_response::Outcome,
};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use prost::Message;
use tonic::{Code, Response};

fn ran(response: Response<ExecuteCommandResponse>) -> CommandResult {
    match response.into_inner().outcome {
        Some(Outcome::Result(result)) => result,
        other => panic!("expected a result, got {other:?}"),
    }
}

fn needs_approval(response: Response<ExecuteCommandResponse>) -> ApprovalRequired {
    match response.into_inner().outcome {
        Some(Outcome::ApprovalRequired(required)) => required,
        other => panic!("expected ApprovalRequired, got {other:?}"),
    }
}

#[tokio::test]
async fn capabilities_describe_the_enforced_policy() {
    let daemon = TestDaemon::start(Options::default()).await;
    let mut observer = daemon.client(OBSERVER).await;
    let caps = observer
        .get_capabilities(GetCapabilitiesRequest {})
        .await
        .unwrap()
        .into_inner();

    assert_eq!(caps.device_name, "Test Mac");
    assert!(caps.approvals_enabled);
    assert_eq!(
        caps.workspace_roots,
        [daemon.workspace.display().to_string()]
    );
    assert_eq!(caps.allowed_commands.len(), 2);
    assert_eq!(caps.allowed_commands[0].program, "/bin/echo");
    assert_eq!(caps.allowed_commands[0].args_prefix, ["hello"]);
    assert!(caps.denied_programs.contains(&"/usr/bin/sudo".to_owned()));
    assert!(caps.limits.is_some());
}

#[tokio::test]
async fn allowlisted_commands_run_immediately() {
    let daemon = TestDaemon::start(Options::default()).await;
    let mut client = daemon.client(ORCHESTRATOR).await;
    let result = ran(client
        .execute_command(command("/bin/echo", &["hello", "world"]))
        .await
        .unwrap());
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, b"hello world\n");
    assert!(!result.timed_out);
}

#[tokio::test]
async fn other_commands_run_once_with_a_signed_approval() {
    let daemon = TestDaemon::start(Options::default()).await;
    let mut client = daemon.client(ORCHESTRATOR).await;
    let request = command("/bin/cat", &["readme.txt"]);

    let required = needs_approval(client.execute_command(request.clone()).await.unwrap());
    let payload = ApprovalPayload::decode(required.payload.as_slice()).unwrap();
    assert_eq!(payload.approval_id, required.approval_id);
    assert_eq!(payload.device_name, "Test Mac");
    assert_eq!(payload.program, "/bin/cat");
    assert_eq!(payload.args, ["readme.txt"]);
    assert_eq!(
        payload.working_directory,
        daemon.workspace.display().to_string()
    );
    assert_eq!(payload.sandbox, Some(SandboxGrants::default()));

    let mut approved = request.clone();
    approved.approval = Some(daemon.approve(&required));
    let result = ran(client.execute_command(approved.clone()).await.unwrap());
    assert_eq!(result.stdout, b"hello from the workspace");

    let replay = client.execute_command(approved).await.unwrap_err();
    assert_eq!(replay.code(), Code::FailedPrecondition);
    assert_eq!(
        error_reason(&replay).as_deref(),
        Some("ERROR_REASON_APPROVAL_EXPIRED")
    );
}

#[tokio::test]
async fn an_approval_covers_only_its_exact_command() {
    let daemon = TestDaemon::start(Options::default()).await;
    let mut client = daemon.client(ORCHESTRATOR).await;

    let asked = command("/bin/echo", &["goodbye"]);
    let required = needs_approval(client.execute_command(asked.clone()).await.unwrap());
    let approval = daemon.approve(&required);

    let mut swapped = command("/bin/echo", &["goodbye", "and", "more"]);
    swapped.approval = Some(approval.clone());
    let status = client.execute_command(swapped).await.unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(
        error_reason(&status).as_deref(),
        Some("ERROR_REASON_APPROVAL_INVALID")
    );

    // A misused approval is burned; the original command needs a new one.
    let mut original = asked;
    original.approval = Some(approval);
    let status = client.execute_command(original).await.unwrap_err();
    assert_eq!(
        error_reason(&status).as_deref(),
        Some("ERROR_REASON_APPROVAL_EXPIRED")
    );
}

#[tokio::test]
async fn forged_approvals_are_rejected() {
    let daemon = TestDaemon::start(Options::default()).await;
    let mut client = daemon.client(ORCHESTRATOR).await;
    let impostor = SigningKey::try_generate().unwrap();

    for forge in [
        |required: &ApprovalRequired, _: &TestDaemon, key: &SigningKey| {
            sign_with(key, APPROVER_ID, required)
        },
        |required: &ApprovalRequired, daemon: &TestDaemon, _: &SigningKey| {
            let mut approval = daemon.approve(required);
            approval.approver_id = "someone-else".into();
            approval
        },
        |required: &ApprovalRequired, daemon: &TestDaemon, _: &SigningKey| {
            let mut approval = daemon.approve(required);
            approval.signature[10] ^= 0xff;
            approval
        },
    ] {
        let request = command("/bin/ls", &[]);
        let required = needs_approval(client.execute_command(request.clone()).await.unwrap());
        let mut forged = request;
        forged.approval = Some(forge(&required, &daemon, &impostor));
        let status = client.execute_command(forged).await.unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(
            error_reason(&status).as_deref(),
            Some("ERROR_REASON_APPROVAL_INVALID")
        );
    }
}

#[tokio::test]
async fn grants_beyond_the_allowlist_need_approval() {
    let daemon = TestDaemon::start(Options::default()).await;
    let mut client = daemon.client(ORCHESTRATOR).await;
    let mut request = command("/bin/echo", &["hello"]);
    request.sandbox = Some(SandboxGrants {
        network: true,
        ..SandboxGrants::default()
    });
    let required = needs_approval(client.execute_command(request).await.unwrap());
    let payload = ApprovalPayload::decode(required.payload.as_slice()).unwrap();
    assert!(
        payload.sandbox.unwrap().network,
        "the approver must see the grant"
    );
}

#[tokio::test]
async fn denied_programs_never_run() {
    let daemon = TestDaemon::start(Options::default()).await;
    let mut client = daemon.client(ORCHESTRATOR).await;
    for program in ["/usr/bin/sudo", "/usr/bin/security", "/bin/launchctl"] {
        let status = client
            .execute_command(command(program, &["-h"]))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied, "{program}");
        assert_eq!(
            error_reason(&status).as_deref(),
            Some("ERROR_REASON_COMMAND_DENIED")
        );
    }
}

#[tokio::test]
async fn working_directory_is_confined() {
    let daemon = TestDaemon::start(Options::default()).await;
    let mut client = daemon.client(ORCHESTRATOR).await;
    for dir in [
        "/".to_owned(),
        daemon.protected.display().to_string(),
        format!("{}/..", daemon.workspace.display()),
    ] {
        let mut request = command("/bin/echo", &["hello"]);
        request.working_directory = dir.clone();
        let status = client.execute_command(request).await.unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied, "{dir}");
        assert_eq!(
            error_reason(&status).as_deref(),
            Some("ERROR_REASON_WORKING_DIRECTORY_NOT_ALLOWED")
        );
    }
}

#[tokio::test]
async fn invalid_requests_are_rejected() {
    let daemon = TestDaemon::start(Options::default()).await;
    let mut client = daemon.client(ORCHESTRATOR).await;

    let mut too_long = command("/bin/echo", &["hello"]);
    too_long.timeout = Some(prost_types::Duration {
        seconds: 100_000,
        nanos: 0,
    });
    let mut missing_dir = command("/bin/echo", &["hello"]);
    missing_dir.working_directory = format!("{}/nope", daemon.workspace.display());
    for request in [
        command("echo", &["hello"]),
        command("/no/such/program", &[]),
        command("/etc/hosts", &[]),
        command("/bin/echo", &["hello", "nul\0byte"]),
        too_long,
        missing_dir,
    ] {
        let status = client.execute_command(request.clone()).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{request:?}");
    }
}

#[tokio::test]
async fn callers_need_a_certificate_and_a_grant() {
    let daemon = TestDaemon::start(Options::default()).await;
    let mut observer = daemon.client(OBSERVER).await;
    let status = observer
        .execute_command(command("/bin/echo", &["hello"]))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);

    let rejected = match daemon.anonymous_client().await {
        Err(_) => true,
        Ok(mut client) => client
            .execute_command(command("/bin/echo", &["hello"]))
            .await
            .is_err(),
    };
    assert!(rejected);
}

#[tokio::test]
async fn without_approvers_only_the_allowlist_runs() {
    let daemon = TestDaemon::start(Options {
        with_approver: false,
        ..Options::default()
    })
    .await;
    let mut client = daemon.client(ORCHESTRATOR).await;
    assert_eq!(
        ran(client
            .execute_command(command("/bin/echo", &["hello"]))
            .await
            .unwrap())
        .exit_code,
        0
    );
    let status = client
        .execute_command(command("/bin/ls", &[]))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        error_reason(&status).as_deref(),
        Some("ERROR_REASON_NO_APPROVERS")
    );
}

#[tokio::test]
async fn concurrent_commands_are_bounded() {
    let daemon = TestDaemon::start(Options {
        max_concurrent: 1,
        ..Options::default()
    })
    .await;
    let mut first = daemon.client(ORCHESTRATOR).await;
    let mut second = first.clone();

    let long =
        tokio::spawn(async move { first.execute_command(command("/bin/sleep", &["2"])).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let status = second
        .execute_command(command("/bin/echo", &["hello"]))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(
        error_reason(&status).as_deref(),
        Some("ERROR_REASON_TOO_MANY_COMMANDS")
    );

    assert_eq!(ran(long.await.unwrap().unwrap()).exit_code, 0);
    assert_eq!(
        ran(second
            .execute_command(command("/bin/echo", &["hello"]))
            .await
            .unwrap())
        .exit_code,
        0,
        "the slot is free again"
    );
}

#[tokio::test]
async fn timeouts_are_reported() {
    let daemon = TestDaemon::start(Options::default()).await;
    let mut client = daemon.client(ORCHESTRATOR).await;
    let mut request = command("/bin/sleep", &["30"]);
    request.timeout = Some(prost_types::Duration {
        seconds: 1,
        nanos: 0,
    });
    let result = ran(client.execute_command(request).await.unwrap());
    assert!(result.timed_out);
    assert_ne!(result.signal, 0);
}

#[tokio::test]
async fn health_check_reports_serving() {
    use tonic_health::pb::{
        HealthCheckRequest, health_check_response::ServingStatus, health_client::HealthClient,
    };

    let daemon = TestDaemon::start(Options::default()).await;
    let mut health = HealthClient::new(daemon.channel(OBSERVER).await);
    let status = health
        .check(HealthCheckRequest {
            service: "jarvis.device.v1.DeviceService".into(),
        })
        .await
        .unwrap()
        .into_inner()
        .status();
    assert_eq!(status, ServingStatus::Serving);
}
