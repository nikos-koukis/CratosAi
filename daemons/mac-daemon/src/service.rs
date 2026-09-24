//! gRPC handlers. Every call is checked in this order: caller identity
//! (mTLS), network origin (tailnet or loopback), authorization, input
//! validation, command policy, approval, then execution. Every call is
//! audited, whatever the outcome.

use std::{collections::HashMap, error::Error, path::PathBuf, sync::Arc, time::Duration};

use jarvis_common::{authz::AuthzPolicy, mtls::Principal};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tonic::{Code, Request, Response, Status};
use tonic_types::{ErrorDetails, StatusExt};

use crate::{
    approval::{ApprovalError, Approvers, CommandSpec, PendingApprovals},
    config::{Config, Limits, NetworkMode},
    executor::{Execution, Executor},
    network,
    policy::{CommandPolicy, Decision, Grants, PathError},
    proto::device_v1::{
        self, ApprovalRequired, CommandResult, ErrorReason, ExecuteCommandRequest,
        ExecuteCommandResponse, GetCapabilitiesRequest, GetCapabilitiesResponse,
        device_service_server, execute_command_response::Outcome,
    },
};

/// `google.rpc.ErrorInfo.domain` for every error this service reports.
pub const ERROR_DOMAIN: &str = "device.jarvis";
/// Correlation id header; generated when absent or malformed.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

const MAX_ARGS: usize = 256;
const MAX_ARGS_BYTES: usize = 64 * 1024;

/// The daemon's RPCs, as named in `[[principal]]` grants and the audit log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
pub enum Rpc {
    GetCapabilities,
    ExecuteCommand,
}

impl Rpc {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetCapabilities => "GetCapabilities",
            Self::ExecuteCommand => "ExecuteCommand",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("caller identity could not be established from the client certificate")]
    Unauthenticated,
    #[error("caller is not allowed to call this method")]
    CallerNotAllowed,
    #[error("connection does not come from an allowed network")]
    PeerNotAllowed,
    #[error("program is on the device's deny list")]
    CommandDenied,
    #[error("working directory is outside the workspace roots or inside a protected path")]
    WorkingDirectoryNotAllowed,
    #[error("approval is invalid: {0}")]
    ApprovalInvalid(&'static str),
    #[error("approval is unknown, already used or expired")]
    ApprovalExpired,
    #[error("command needs approval but no approvers are configured")]
    NoApprovers,
    #[error("the device is already running its maximum number of commands")]
    TooManyCommands,
    #[error("too many approvals are waiting for a signature")]
    TooManyPendingApprovals,
    #[error("internal error: {0}")]
    Internal(String),
}

impl DeviceError {
    pub const fn code(&self) -> Code {
        match self {
            Self::InvalidArgument(_) => Code::InvalidArgument,
            Self::Unauthenticated => Code::Unauthenticated,
            Self::CallerNotAllowed
            | Self::PeerNotAllowed
            | Self::CommandDenied
            | Self::WorkingDirectoryNotAllowed
            | Self::ApprovalInvalid(_) => Code::PermissionDenied,
            Self::ApprovalExpired | Self::NoApprovers => Code::FailedPrecondition,
            Self::TooManyCommands | Self::TooManyPendingApprovals => Code::ResourceExhausted,
            Self::Internal(_) => Code::Internal,
        }
    }

    pub const fn reason(&self) -> Option<ErrorReason> {
        match self {
            Self::CommandDenied => Some(ErrorReason::CommandDenied),
            Self::WorkingDirectoryNotAllowed => Some(ErrorReason::WorkingDirectoryNotAllowed),
            Self::ApprovalInvalid(_) => Some(ErrorReason::ApprovalInvalid),
            Self::ApprovalExpired => Some(ErrorReason::ApprovalExpired),
            Self::NoApprovers => Some(ErrorReason::NoApprovers),
            Self::TooManyCommands => Some(ErrorReason::TooManyCommands),
            Self::TooManyPendingApprovals => Some(ErrorReason::TooManyPendingApprovals),
            _ => None,
        }
    }

    fn from_path(error: PathError) -> Self {
        match error {
            PathError::OutsideWorkspace => Self::WorkingDirectoryNotAllowed,
            other => Self::InvalidArgument(other.to_string()),
        }
    }
}

impl From<ApprovalError> for DeviceError {
    fn from(error: ApprovalError) -> Self {
        match error {
            ApprovalError::TooManyPending => Self::TooManyPendingApprovals,
            ApprovalError::Expired => Self::ApprovalExpired,
            ApprovalError::Invalid(detail) => Self::ApprovalInvalid(detail),
        }
    }
}

impl From<DeviceError> for Status {
    fn from(error: DeviceError) -> Self {
        if error.code() == Code::Internal {
            return Status::internal("internal error");
        }
        match error.reason() {
            Some(reason) => Status::with_error_details(
                error.code(),
                error.to_string(),
                ErrorDetails::with_error_info(
                    reason.as_str_name(),
                    ERROR_DOMAIN,
                    HashMap::<String, String>::new(),
                ),
            ),
            None => Status::new(error.code(), error.to_string()),
        }
    }
}

/// Everything the handlers need, built once from the configuration.
#[derive(Debug)]
pub struct DaemonState {
    pub device_name: String,
    pub network_mode: NetworkMode,
    pub authz: AuthzPolicy<Rpc>,
    pub approvers: Approvers,
    pub policy: CommandPolicy,
    pub limits: Limits,
    pub pending: PendingApprovals,
    pub executor: Executor,
    pub slots: Semaphore,
}

impl DaemonState {
    pub fn new(config: Config, temp_root: PathBuf, home: PathBuf, user: String) -> Self {
        let limits = config.limits;
        Self {
            executor: Executor::new(
                config.policy.protected_paths.clone(),
                limits.max_output_bytes,
                temp_root,
                home,
                user,
            ),
            pending: PendingApprovals::new(limits.approval_ttl, limits.max_pending_approvals),
            slots: Semaphore::new(limits.max_concurrent),
            device_name: config.device_name,
            network_mode: config.network.mode,
            authz: config.authz,
            approvers: config.approvers,
            policy: config.policy,
            limits,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceService {
    state: Arc<DaemonState>,
}

/// Facts gathered during one call, for the audit record.
#[derive(Default)]
struct Call {
    request_id: String,
    caller: Option<String>,
    program: Option<PathBuf>,
    args: Vec<String>,
    working_dir: Option<PathBuf>,
    grants: Option<Grants>,
    decision: &'static str,
    approval_id: Option<String>,
    approver: Option<String>,
    execution: Option<(i32, i32, bool, Duration)>,
}

impl DeviceService {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    fn authorize<T>(
        &self,
        call: &mut Call,
        request: &Request<T>,
        rpc: Rpc,
    ) -> Result<(), DeviceError> {
        let certs = request.peer_certs();
        let principal = Principal::from_peer_certs(certs.as_deref().map(Vec::as_slice))
            .map_err(|_| DeviceError::Unauthenticated)?;
        call.caller = Some(principal.as_str().to_owned());
        if !network::peer_allowed(self.state.network_mode, request.remote_addr()) {
            return Err(DeviceError::PeerNotAllowed);
        }
        if !self.state.authz.is_allowed(&principal, rpc) {
            return Err(DeviceError::CallerNotAllowed);
        }
        Ok(())
    }

    fn capabilities(&self) -> GetCapabilitiesResponse {
        let state = &self.state;
        let path = |p: &PathBuf| p.display().to_string();
        let mut denied: Vec<String> = state.policy.denied_programs.iter().map(path).collect();
        denied.sort();
        GetCapabilitiesResponse {
            device_name: state.device_name.clone(),
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
            workspace_roots: state.policy.workspace_roots.iter().map(path).collect(),
            allowed_commands: state
                .policy
                .rules
                .iter()
                .map(|rule| device_v1::AllowedCommand {
                    program: path(&rule.program),
                    args_prefix: rule.args_prefix.clone(),
                    allow_extra_args: rule.allow_extra_args,
                    sandbox: Some(rule.grants.to_proto()),
                    requires_approval: rule.requires_approval,
                    description: rule.description.clone(),
                })
                .collect(),
            denied_programs: denied,
            limits: Some(device_v1::CommandLimits {
                default_timeout: prost_types::Duration::try_from(state.limits.default_timeout).ok(),
                max_timeout: prost_types::Duration::try_from(state.limits.max_timeout).ok(),
                max_output_bytes: state.limits.max_output_bytes as u64,
                max_concurrent_commands: u32::try_from(state.limits.max_concurrent)
                    .unwrap_or(u32::MAX),
            }),
            approvals_enabled: !state.approvers.is_empty(),
        }
    }

    fn timeout(&self, requested: Option<&prost_types::Duration>) -> Result<Duration, DeviceError> {
        let Some(requested) = requested else {
            return Ok(self.state.limits.default_timeout);
        };
        let timeout = Duration::try_from(*requested)
            .ok()
            .filter(|t| !t.is_zero() && *t <= self.state.limits.max_timeout)
            .ok_or_else(|| {
                DeviceError::InvalidArgument(format!(
                    "timeout must be positive and at most {}s",
                    self.state.limits.max_timeout.as_secs()
                ))
            })?;
        Ok(timeout)
    }

    async fn handle_execute(
        &self,
        call: &mut Call,
        request: Request<ExecuteCommandRequest>,
    ) -> Result<ExecuteCommandResponse, DeviceError> {
        self.authorize(call, &request, Rpc::ExecuteCommand)?;
        let state = &self.state;
        let request = request.into_inner();

        validate_args(&request.args)?;
        let program =
            CommandPolicy::resolve_program(&request.program).map_err(DeviceError::from_path)?;
        call.program = Some(program.clone());
        call.args.clone_from(&request.args);
        let working_dir = state
            .policy
            .resolve_working_dir(&request.working_directory)
            .map_err(DeviceError::from_path)?;
        call.working_dir = Some(working_dir.clone());
        let timeout = self.timeout(request.timeout.as_ref())?;
        let requested = request.sandbox.as_ref().map(Grants::from_proto);

        let (grants, needs_approval) = match state.policy.decide(&program, &request.args, requested)
        {
            Decision::Denied => {
                call.decision = "denied";
                return Err(DeviceError::CommandDenied);
            }
            Decision::Run(grants) => (grants, false),
            Decision::NeedsApproval(grants) => (grants, true),
        };
        call.grants = Some(grants);
        let spec = CommandSpec {
            program,
            args: request.args,
            working_dir,
            timeout,
            grants,
        };

        if needs_approval && request.approval.is_none() {
            if state.approvers.is_empty() {
                call.decision = "approval_unavailable";
                return Err(DeviceError::NoApprovers);
            }
            let issued = state.pending.issue(&state.device_name, &spec)?;
            call.decision = "approval_requested";
            call.approval_id = Some(issued.approval_id.clone());
            return Ok(ExecuteCommandResponse {
                outcome: Some(Outcome::ApprovalRequired(ApprovalRequired {
                    approval_id: issued.approval_id,
                    payload: issued.payload,
                    expire_time: Some(issued.expire_time.into()),
                })),
            });
        }

        // Take a slot before consuming the approval, so a busy device does
        // not burn the user's signature.
        let _slot = state
            .slots
            .try_acquire()
            .map_err(|_| DeviceError::TooManyCommands)?;
        if let (true, Some(approval)) = (needs_approval, &request.approval) {
            call.approval_id = Some(approval.approval_id.clone());
            call.decision = "approval_rejected";
            let approver = state.pending.redeem(&state.approvers, approval, &spec)?;
            call.decision = "approved";
            call.approver = Some(approver);
        } else {
            call.decision = "allowlisted";
        }

        let execution = state
            .executor
            .run(&spec)
            .await
            .map_err(|e| DeviceError::Internal(error_chain(&e)))?;
        call.execution = Some((
            execution.exit_code,
            execution.signal,
            execution.timed_out,
            execution.duration,
        ));
        Ok(ExecuteCommandResponse {
            outcome: Some(Outcome::Result(command_result(execution))),
        })
    }

    fn finish<T>(
        &self,
        rpc: Rpc,
        call: &Call,
        result: Result<T, DeviceError>,
    ) -> Result<Response<T>, Status> {
        let (outcome, code) = match &result {
            Ok(_) => ("success", Code::Ok),
            Err(error) => ("failure", error.code()),
        };
        let (exit_code, signal, timed_out, duration_ms) = call
            .execution
            .map(|(exit, signal, timed_out, duration)| {
                (
                    Some(exit),
                    Some(signal),
                    Some(timed_out),
                    Some(duration.as_millis()),
                )
            })
            .unwrap_or_default();
        tracing::info!(
            target: "audit",
            rpc = rpc.as_str(),
            request_id = %call.request_id,
            caller = call.caller.as_deref(),
            program = call.program.as_ref().map(|p| tracing::field::display(p.display())),
            args = ?call.args,
            working_dir = call.working_dir.as_ref().map(|p| tracing::field::display(p.display())),
            grants = call.grants.map(tracing::field::debug),
            decision = call.decision,
            approval_id = call.approval_id.as_deref(),
            approver = call.approver.as_deref(),
            exit_code,
            signal,
            timed_out,
            duration_ms,
            outcome,
            code = ?code,
            "device audit event"
        );
        result.map(Response::new).map_err(|error| {
            if error.code() == Code::Internal {
                tracing::error!(rpc = rpc.as_str(), error = %error, "request failed");
            }
            error.into()
        })
    }
}

#[tonic::async_trait]
impl device_service_server::DeviceService for DeviceService {
    async fn get_capabilities(
        &self,
        request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        let mut call = Call {
            request_id: request_id(&request),
            decision: "capabilities",
            ..Call::default()
        };
        let result = self
            .authorize(&mut call, &request, Rpc::GetCapabilities)
            .map(|()| self.capabilities());
        self.finish(Rpc::GetCapabilities, &call, result)
    }

    async fn execute_command(
        &self,
        request: Request<ExecuteCommandRequest>,
    ) -> Result<Response<ExecuteCommandResponse>, Status> {
        let mut call = Call {
            request_id: request_id(&request),
            decision: "rejected",
            ..Call::default()
        };
        let result = self.handle_execute(&mut call, request).await;
        self.finish(Rpc::ExecuteCommand, &call, result)
    }
}

fn command_result(execution: Execution) -> CommandResult {
    CommandResult {
        exit_code: execution.exit_code,
        signal: execution.signal,
        stdout: execution.stdout,
        stderr: execution.stderr,
        stdout_truncated: execution.stdout_truncated,
        stderr_truncated: execution.stderr_truncated,
        timed_out: execution.timed_out,
        duration: prost_types::Duration::try_from(execution.duration).ok(),
    }
}

fn validate_args(args: &[String]) -> Result<(), DeviceError> {
    if args.len() > MAX_ARGS {
        return Err(DeviceError::InvalidArgument(format!(
            "at most {MAX_ARGS} arguments are allowed"
        )));
    }
    if args.iter().map(String::len).sum::<usize>() > MAX_ARGS_BYTES {
        return Err(DeviceError::InvalidArgument(format!(
            "arguments may total at most {MAX_ARGS_BYTES} bytes"
        )));
    }
    if args.iter().any(|arg| arg.contains('\0')) {
        return Err(DeviceError::InvalidArgument(
            "arguments must not contain NUL bytes".into(),
        ));
    }
    Ok(())
}

fn request_id<T>(request: &Request<T>) -> String {
    request
        .metadata()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        })
        .map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_owned)
}

fn error_chain(error: &dyn Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_limits_are_enforced() {
        assert!(validate_args(&["status".into()]).is_ok());
        assert!(validate_args(&vec![String::new(); MAX_ARGS + 1]).is_err());
        assert!(validate_args(&["x".repeat(MAX_ARGS_BYTES + 1)]).is_err());
        assert!(validate_args(&["a\0b".into()]).is_err());
    }

    #[test]
    fn errors_map_to_codes_and_reasons() {
        let status = Status::from(DeviceError::CommandDenied);
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(
            status.get_details_error_info().map(|i| i.reason),
            Some("ERROR_REASON_COMMAND_DENIED".to_owned())
        );
        let internal = Status::from(DeviceError::Internal("disk full at /x".into()));
        assert_eq!(internal.message(), "internal error");
    }
}
