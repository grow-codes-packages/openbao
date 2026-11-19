//! Auth module: login methods, token self-operations, token creation, token renewer.

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use grow_openbao as sdk;
use sdk::core::ErrorCode;
use sdk::{
    AppRoleAuth, Auth, AuthInfo, AuthMethod, JwtAuth, KubernetesAuth, Secret, TokenAuth,
    TokenCreateOptions, TokenRenewerOptions, UserpassAuth,
};
use serde_json::json;
use support::*;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn approle_login_sets_token() {
    let server = MockServer::start().await;
    on(&server, "POST", "/v1/auth/approle/login", "appRoleLogin.ok").await;
    on(
        &server,
        "POST",
        "/v1/auth/ar-1/login",
        "appRoleLogin.secret-id-used-up",
    )
    .await;
    let c = client(&server);
    let info = c
        .auth()
        .login(AppRoleAuth::new("role-1", "secret-id-123456"))
        .await
        .unwrap();
    assert_eq!(info.metadata["role_name"], "sdk-app");
    assert_eq!(info.lease_duration, Duration::from_secs(3600));
    assert!(info.renewable && info.orphan);
    assert_eq!(info.policies, vec!["default", "sdk-app"]);
    assert_eq!(info.token_type, "service");
    assert_eq!(c.token().unwrap().expose_secret(), "<redacted>");
    assert_eq!(
        sent(&server, "/v1/auth/approle/login").await[0],
        json!({"role_id": "role-1", "secret_id": "secret-id-123456"})
    );
    // login endpoints never carry the old token
    let req = &requests(&server, "/v1/auth/approle/login").await[0];
    assert!(req.headers.get("x-vault-token").is_none());
    // a custom mount and a used-up secret id
    let err = c
        .auth()
        .login(AppRoleAuth::new("role-1", "secret-id-123456").mount("/ar-1/"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication);
    assert!(!err.message().contains("secret-id-123456"));
    // role id only (bind_secret_id = false) sends no secret id
    let _ = c.auth().login(AppRoleAuth::new("role-2", "")).await;
    assert_eq!(
        sent(&server, "/v1/auth/approle/login").await[1],
        json!({"role_id": "role-2"})
    );
    assert_eq!(
        c.auth()
            .login(AppRoleAuth::new("", "x"))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn userpass_jwt_and_errors() {
    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/v1/auth/userpass/login/sdk-user",
        "userpassLogin.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/auth/up2/login/bad%20user",
        "userpassLogin.invalid-password",
    )
    .await;
    on(&server, "POST", "/v1/auth/jwt/login", "jwtLogin.ok").await;
    on(&server, "POST", "/v1/auth/jwt2/login", "jwtLogin.expired").await;
    let c = client(&server);
    let info = c
        .auth()
        .login(UserpassAuth::new("sdk-user", "pw-123456"))
        .await
        .unwrap();
    assert_eq!(info.metadata["username"], "sdk-user");
    assert_eq!(
        sent(&server, "/v1/auth/userpass/login/sdk-user").await[0],
        json!({"password": "pw-123456"})
    );
    let err = c
        .auth()
        .login(UserpassAuth::new("bad user", "pw-123456").mount("up2"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication);
    assert!(err.message().contains("invalid username or password"));
    assert!(c.auth().login(UserpassAuth::new("", "x")).await.is_err());

    let info = c
        .auth()
        .login(JwtAuth::new("sdk-jwt", "eyJ.jwt.token"))
        .await
        .unwrap();
    assert_eq!(info.metadata["role"], "sdk-jwt");
    assert_eq!(
        sent(&server, "/v1/auth/jwt/login").await[0],
        json!({"role": "sdk-jwt", "jwt": "eyJ.jwt.token"})
    );
    let err = c
        .auth()
        .login(JwtAuth::new("", "eyJ.expired.jwt").mount("jwt2"))
        .await
        .unwrap_err();
    assert!(err.message().contains("token is expired"));
    assert_eq!(
        sent(&server, "/v1/auth/jwt2/login").await[0],
        json!({"jwt": "eyJ.expired.jwt"})
    );
    assert_eq!(
        c.auth()
            .login(JwtAuth::new("r", ""))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn kubernetes_login_reads_the_jwt_file() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/login"))
        .and(body_json(json!({"role": "sdk-k8s", "jwt": "k8s.sa.jwt"})))
        .respond_with(reply("appRoleLogin.ok"))
        .mount(&server)
        .await;
    on(
        &server,
        "POST",
        "/v1/auth/k8s2/login",
        "kubernetesLogin.no-kubernetes-api",
    )
    .await;
    let dir = std::env::temp_dir().join(format!("grow-openbao-k8s-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let jwt = dir.join("token");
    std::fs::write(&jwt, "k8s.sa.jwt\n").unwrap();
    let c = client(&server);
    let m = KubernetesAuth::new("sdk-k8s", &jwt);
    assert_eq!(m.jwt_path(), jwt.as_path());
    c.auth().login(m.clone()).await.unwrap();
    // no Kubernetes API behind the server: TokenReview fails with a plain 403
    let err = c.auth().login(m.mount("k8s2")).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication);
    let default = KubernetesAuth::new("r", "");
    assert_eq!(
        default.jwt_path(),
        std::path::Path::new(sdk::DEFAULT_KUBERNETES_JWT_PATH)
    );
    let missing = KubernetesAuth::new("r", dir.join("missing"));
    assert_eq!(
        c.auth().login(missing).await.unwrap_err().code(),
        ErrorCode::Config
    );
    assert_eq!(
        c.auth()
            .login(KubernetesAuth::new("", &jwt))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn token_auth_and_lookup_self() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/auth/token/lookup-self"))
        .and(header("x-vault-token", "tok-from-ci-1"))
        .respond_with(reply("lookupSelf.ok"))
        .mount(&server)
        .await;
    on(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        "lookupSelf.revoked",
    )
    .await;
    let c = client(&server);
    let info = c
        .auth()
        .login(TokenAuth::new("tok-from-ci-1"))
        .await
        .unwrap();
    assert_eq!(info.client_token.expose_secret(), "tok-from-ci-1");
    assert_eq!(info.lease_duration, Duration::from_secs(3599));
    assert_eq!(info.metadata["run"], "f43633d7");
    let t = c.auth().lookup_self().await.unwrap();
    assert_eq!(t.display_name, "token-sdk-test");
    assert_eq!(t.policies, vec!["default", "sdk-app"]);
    assert_eq!(t.creation_ttl, Duration::from_secs(3600));
    assert!(t.creation_time.is_some() && t.expire_time.is_some() && t.issue_time.is_some());
    assert!(t.renewable);
    assert_eq!(
        (t.path.as_str(), t.token_type.as_str()),
        ("auth/token/create", "service")
    );
    assert_eq!(t.explicit_max_ttl, Duration::ZERO);
    assert!(!format!("{t:?}").contains("tok-from-ci-1"));
    c.set_token(Some(Secret::new("revoked-token")));
    assert_eq!(
        c.auth().lookup_self().await.unwrap_err().code(),
        ErrorCode::Authentication
    );
    assert_eq!(
        c.auth().login(TokenAuth::new("")).await.unwrap_err().code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn renew_revoke_and_create_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .and(body_json(json!({"increment": "1800s"})))
        .respond_with(reply("renewSelf.ok"))
        .mount(&server)
        .await;
    on(
        &server,
        "POST",
        "/v1/auth/token/renew-self",
        "renewSelf.not-renewable",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/auth/token/revoke-self",
        "revokeSelf.ok",
    )
    .await;
    once(&server, "POST", "/v1/auth/token/create", "createToken.ok").await;
    once(
        &server,
        "POST",
        "/v1/auth/token/create/my-role",
        "createToken.orphan",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/auth/token/create",
        "createToken.permission-denied",
    )
    .await;
    let c = client(&server);
    let a = c.auth();
    let r = a.renew_self(Some(Duration::from_secs(1800))).await.unwrap();
    assert_eq!(r.lease_duration, Duration::from_secs(1800));
    let err = a.renew_self(None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("lease is not renewable"));
    assert_eq!(
        sent(&server, "/v1/auth/token/renew-self").await[1],
        json!({})
    );

    let opts = TokenCreateOptions {
        policies: vec!["sdk-app".into()],
        ttl: Some(Duration::from_secs(3600)),
        explicit_max_ttl: Some(Duration::from_secs(7200)),
        period: Some(Duration::from_millis(1500)),
        renewable: Some(true),
        display_name: Some("sdk".into()),
        meta: BTreeMap::from([("run".to_owned(), "1".to_owned())]),
        num_uses: 3,
        no_parent: true,
        no_default_policy: true,
        token_type: Some("service".into()),
        id: Some(Secret::new("custom-id-1")),
        role: None,
    };
    let t = a.create_token(&opts).await.unwrap();
    assert!(!t.client_token.is_empty());
    assert_eq!(
        sent(&server, "/v1/auth/token/create").await[0],
        json!({
            "policies": ["sdk-app"], "ttl": "3600s", "explicit_max_ttl": "7200s",
            "period": "2s", "renewable": true, "display_name": "sdk", "meta": {"run": "1"},
            "num_uses": 3, "no_parent": true, "no_default_policy": true, "type": "service",
            "id": "custom-id-1"
        })
    );
    let orphan = a
        .create_token(&TokenCreateOptions {
            role: Some("my-role".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(orphan.orphan);
    // a policy denial stays PERMISSION_DENIED
    let err = a
        .create_token(&TokenCreateOptions::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);

    a.revoke_self().await.unwrap();
    assert!(c.token().is_none());

    // a response without an auth block
    on_reply(
        &server,
        "POST",
        "/v1/auth/odd/login",
        json(200, json!({"data": {}})),
    )
    .await;
    on_reply(
        &server,
        "POST",
        "/v1/auth/token/create/odd",
        json(200, json!({"data": {}})),
    )
    .await;
    assert_eq!(
        a.login_with("odd/login", json!({"x": 1}))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Authentication
    );
    assert_eq!(
        a.create_token(&TokenCreateOptions {
            role: Some("odd".into()),
            ..Default::default()
        })
        .await
        .unwrap_err()
        .code(),
        ErrorCode::Unavailable
    );
}

#[derive(Debug)]
struct CountingMethod {
    calls: Arc<AtomicU32>,
    ttl: u64,
    fail_after: u32,
}

#[async_trait::async_trait]
impl AuthMethod for CountingMethod {
    async fn login(&self, auth: &Auth) -> sdk::Result<AuthInfo> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if n > self.fail_after {
            return Err(sdk::Error::unavailable("login failed"));
        }
        let _ = auth;
        Ok(AuthInfo {
            client_token: Secret::new(format!(
                "relogin-token-{}",
                self.calls.load(Ordering::SeqCst)
            )),
            lease_duration: Duration::from_secs(self.ttl),
            renewable: false,
            ..AuthInfo::default()
        })
    }
}

fn lookup(ttl: u64, renewable: bool) -> ResponseTemplate {
    json(200, json!({"data": {"ttl": ttl, "renewable": renewable}}))
}

fn renewed(ttl: u64, renewable: bool) -> ResponseTemplate {
    json(
        200,
        json!({"auth": {"client_token": "x-token", "lease_duration": ttl, "renewable": renewable}}),
    )
}

#[tokio::test]
async fn token_renewer_renews_then_expires() {
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        lookup(1, true),
    )
    .await;
    // first renewal grants 1 s and stays renewable, the second is capped (not renewable)
    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(renewed(1, true))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    on_reply(
        &server,
        "POST",
        "/v1/auth/token/renew-self",
        renewed(1, false),
    )
    .await;
    let c = client(&server);
    let renews = Arc::new(AtomicU32::new(0));
    let expired = Arc::new(AtomicU32::new(0));
    let (r1, e1) = (renews.clone(), expired.clone());
    let renewer = c
        .auth()
        .start_renewer(TokenRenewerOptions {
            increment: None,
            on_renew: Some(Arc::new(move |_| {
                r1.fetch_add(1, Ordering::SeqCst);
            })),
            on_expire: Some(Arc::new(move || {
                e1.fetch_add(1, Ordering::SeqCst);
                panic!("callback panics are contained");
            })),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!renewer.is_stopped());
    assert!(format!("{renewer:?}").contains("TokenRenewer"));
    tokio::time::timeout(Duration::from_secs(10), renewer.done())
        .await
        .expect("renewer ends");
    assert_eq!(renews.load(Ordering::SeqCst), 2);
    assert_eq!(expired.load(Ordering::SeqCst), 1);
    assert!(renewer.is_stopped());
}

#[tokio::test]
async fn token_renewer_capped_increment_errors_and_relogin() {
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        lookup(1, true),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // granted 1 s < requested 60 s: capped, no more renewals
    on_reply(
        &server,
        "POST",
        "/v1/auth/token/renew-self",
        renewed(1, true),
    )
    .await;
    let c = client(&server);
    let calls = Arc::new(AtomicU32::new(0));
    c.auth()
        .login(CountingMethod {
            calls: calls.clone(),
            ttl: 1,
            fail_after: u32::MAX,
        })
        .await
        .unwrap();
    let errors = Arc::new(Mutex::new(Vec::new()));
    let renews = Arc::new(AtomicU32::new(0));
    let (errs, r1) = (errors.clone(), renews.clone());
    let renewer = c
        .auth()
        .start_renewer(TokenRenewerOptions {
            increment: Some(Duration::from_secs(60)),
            relogin: true,
            on_error: Some(Arc::new(move |e| errs.lock().unwrap().push(e.code()))),
            on_renew: Some(Arc::new(move |_| {
                r1.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        })
        .await
        .unwrap();
    // 503 (retryable) → renew (capped) → re-login (ttl 1, not renewable) → re-login …
    tokio::time::timeout(Duration::from_secs(10), async {
        while calls.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("re-logins happen");
    assert_eq!(errors.lock().unwrap().as_slice(), &[ErrorCode::Unavailable]);
    assert!(renews.load(Ordering::SeqCst) >= 2);
    assert!(c
        .token()
        .unwrap()
        .expose_secret()
        .starts_with("relogin-token-"));
    c.close().await;
    tokio::time::timeout(Duration::from_secs(5), renewer.done())
        .await
        .expect("close stops the renewer");
    assert!(renewer.is_stopped());
}

#[tokio::test]
async fn token_renewer_failed_relogin_expires_and_stop() {
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        lookup(1, false),
    )
    .await;
    let c = client(&server);
    let calls = Arc::new(AtomicU32::new(0));
    // the remembered method fails (retryable) until the token expired
    let method: Arc<dyn AuthMethod> = Arc::new(CountingMethod {
        calls: calls.clone(),
        ttl: 1,
        fail_after: 1,
    });
    c.auth().login_arc(method).await.unwrap();
    let expired = Arc::new(AtomicU32::new(0));
    let e1 = expired.clone();
    let renewer = c
        .auth()
        .start_renewer(TokenRenewerOptions {
            relogin: true,
            on_expire: Some(Arc::new(move || {
                e1.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), renewer.done())
        .await
        .expect("renewer expires");
    assert_eq!(expired.load(Ordering::SeqCst), 1);
    assert!(calls.load(Ordering::SeqCst) >= 3);

    // a token without TTL never needs renewal; stop() ends it
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        lookup(0, false),
    )
    .await;
    let c = client(&server);
    let r = c
        .auth()
        .start_renewer(TokenRenewerOptions::default())
        .await
        .unwrap();
    assert!(format!("{:?}", TokenRenewerOptions::default()).contains("relogin"));
    r.stop();
    r.stop();
    tokio::time::timeout(Duration::from_secs(5), r.done())
        .await
        .unwrap();
    assert!(r.is_stopped());

    // non-retryable renewal error: expires at the TTL without re-login
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        lookup(1, true),
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/auth/token/renew-self",
        "renewSelf.not-renewable",
    )
    .await;
    let c = client(&server);
    let expired = Arc::new(AtomicU32::new(0));
    let e1 = expired.clone();
    let r = c
        .auth()
        .start_renewer(TokenRenewerOptions {
            on_expire: Some(Arc::new(move || {
                e1.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), r.done())
        .await
        .unwrap();
    assert_eq!(expired.load(Ordering::SeqCst), 1);
}
