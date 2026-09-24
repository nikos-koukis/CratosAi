//! SealData / OpenData: services store their own secrets (e.g. OAuth tokens)
//! as Vault-sealed blobs that only open under the exact same binding.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use jarvis_vault::proto::vault_v1::{OpenDataRequest, SealDataRequest};
use tonic::Code;
use uuid::Uuid;

const TOKENS: &[u8] = br#"{"access_token":"at-SECRET","refresh_token":"rt-SECRET"}"#;

fn seal_request(tenant: Uuid, purpose: &str, subject: &str, plaintext: &[u8]) -> SealDataRequest {
    let mut request = SealDataRequest::default();
    request.tenant_id = tenant.to_string();
    request.purpose = purpose.to_owned();
    request.subject_id = subject.to_owned();
    request.plaintext = plaintext.to_vec();
    request
}

fn open_request(tenant: Uuid, purpose: &str, subject: &str, sealed: Vec<u8>) -> OpenDataRequest {
    OpenDataRequest {
        tenant_id: tenant.to_string(),
        purpose: purpose.to_owned(),
        subject_id: subject.to_owned(),
        sealed,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sealed_data_opens_only_under_its_exact_binding() {
    let vault = TestVault::start().await;
    let tenant = Uuid::now_v7();
    let mut router = vault.client(MCP_ROUTER).await;

    let sealed = router
        .seal_data(seal_request(
            tenant,
            "mcp.oauth-tokens",
            "integration-1",
            TOKENS,
        ))
        .await
        .unwrap()
        .into_inner()
        .sealed;
    assert!(!String::from_utf8_lossy(&sealed).contains("SECRET"));

    let opened = router
        .open_data(open_request(
            tenant,
            "mcp.oauth-tokens",
            "integration-1",
            sealed.clone(),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(opened.plaintext, TOKENS);

    let other_tenant = Uuid::now_v7();
    let mut tampered = sealed.clone();
    *tampered.last_mut().unwrap() ^= 1;
    for request in [
        open_request(
            other_tenant,
            "mcp.oauth-tokens",
            "integration-1",
            sealed.clone(),
        ),
        open_request(tenant, "mcp.other-purpose", "integration-1", sealed.clone()),
        open_request(tenant, "mcp.oauth-tokens", "integration-2", sealed.clone()),
        open_request(tenant, "mcp.oauth-tokens", "integration-1", tampered),
        open_request(
            tenant,
            "mcp.oauth-tokens",
            "integration-1",
            b"not sealed data".to_vec(),
        ),
    ] {
        let status = router.open_data(request).await.unwrap_err();
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert_eq!(
            error_reason(&status).as_deref(),
            Some("ERROR_REASON_SEALED_DATA_INVALID")
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_granted_services_may_seal_or_open() {
    let vault = TestVault::start().await;
    let tenant = Uuid::now_v7();
    let sealed = vault
        .client(MCP_ROUTER)
        .await
        .seal_data(seal_request(tenant, "mcp.oauth-tokens", "i", TOKENS))
        .await
        .unwrap()
        .into_inner()
        .sealed;

    for principal in [DASHBOARD, GATEWAY, STRANGER] {
        let mut client = vault.client(principal).await;
        let seal = client
            .seal_data(seal_request(tenant, "mcp.oauth-tokens", "i", TOKENS))
            .await
            .unwrap_err();
        let open = client
            .open_data(open_request(
                tenant,
                "mcp.oauth-tokens",
                "i",
                sealed.clone(),
            ))
            .await
            .unwrap_err();
        assert_eq!(
            (seal.code(), open.code()),
            (Code::PermissionDenied, Code::PermissionDenied),
            "{principal}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_requests_are_rejected_and_audit_never_holds_data() {
    let vault = TestVault::start().await;
    let tenant = Uuid::now_v7();
    let mut router = vault.client(MCP_ROUTER).await;

    for request in [
        seal_request(tenant, "", "i", TOKENS),
        seal_request(tenant, "Has Spaces", "i", TOKENS),
        seal_request(tenant, "mcp.oauth", "", TOKENS),
        seal_request(tenant, "mcp.oauth", "with space", TOKENS),
        seal_request(tenant, "mcp.oauth", "i", b""),
        seal_request(tenant, "mcp.oauth", "i", &vec![b'x'; 64 * 1024 + 1]),
    ] {
        let status = router.seal_data(request).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(!status.message().contains("SECRET"));
    }

    router
        .seal_data(seal_request(
            tenant,
            "mcp.oauth-tokens",
            "integration-9",
            TOKENS,
        ))
        .await
        .unwrap();
    let events = vault.audit.events();
    let last = events.last().unwrap();
    assert_eq!(
        last.subject.as_deref(),
        Some("mcp.oauth-tokens/integration-9")
    );
    assert!(!format!("{events:?}").contains("SECRET"));
}
