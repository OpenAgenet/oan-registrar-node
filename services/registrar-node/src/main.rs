// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use anyhow::{anyhow, Result};
use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Datelike, Duration, Utc};
use futures::TryStreamExt;
use oan_core::{CapabilityTagTree, CryptoSuite, DidDocument};
use oan_credentials::sign_credential;
use oan_crypto::{
    hash_json_with_suite, signing_key_from_bytes, verify_payload_with_proof,
    verifying_key_from_method, SigningKey,
};
use oan_protocol::{
    HealthResponse, RegistrationCredentialQueryRequest, ResourceRegistrationSubmission,
    ResourceVerifyAndPublishRequest, OAN_RESOURCE_PROTOCOL_VERSION,
    PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH, PROTOCOL_REGISTRATION_CREDENTIAL_QUERY_V1,
    PURPOSE_CONTROLLER_AUTHORIZATION_REGISTRATION, PURPOSE_REGISTRATION_CREDENTIAL_QUERY,
    PURPOSE_VERIFY_AND_PUBLISH,
};
use oan_semantic_recommender::{
    normalize_capability_tags, RegistrationSuggestionContext, RegistrationSuggestionInput,
    SemanticRecommender,
};
use oan_service_security::{
    create_signed_request_envelope, find_relationship_method, request_id, request_nonce,
    verify_and_store_nonce, verify_controller_authorization_proof,
    ControllerAuthorizationVerificationContext, SignedRequestEnvelopeInput,
    VerificationRelationship,
};
use oan_storage::{
    did_to_file_name, DatabaseBackend, DatabaseConfig, JsonStore, PostgresJsonStore,
    SqliteJsonStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    #[serde(default)]
    cors: CorsConfig,
    #[serde(default)]
    security: SecurityConfig,
    #[serde(default)]
    stats_report: StatsReportConfig,
    upstream: UpstreamConfig,
    paths: PathConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CorsConfig {
    #[serde(default)]
    allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct UpstreamConfig {
    root_endpoint: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct SecurityConfig {
    #[serde(default)]
    upstream: UpstreamSecurityConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct UpstreamSecurityConfig {
    #[serde(default = "default_root_did")]
    root_did: String,
}

#[derive(Clone, Debug, Deserialize)]
struct StatsReportConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    node_id: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default = "default_stats_report_interval_seconds")]
    interval_seconds: u64,
}

impl Default for StatsReportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: None,
            endpoint: None,
            token: None,
            interval_seconds: default_stats_report_interval_seconds(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct PathConfig {
    data_dir: PathBuf,
    #[serde(default = "default_records_dir")]
    records_dir: PathBuf,
    #[serde(default = "default_keys_dir")]
    keys_dir: PathBuf,
    #[serde(default = "default_controller_authorization_nonce_file")]
    controller_authorization_nonce_file: PathBuf,
    #[serde(default = "default_registration_credential_query_nonce_file")]
    registration_credential_query_nonce_file: PathBuf,
    #[serde(default)]
    database_url: Option<String>,
}

fn default_records_dir() -> PathBuf {
    PathBuf::from("../../data/registrar/resource-records")
}

fn default_keys_dir() -> PathBuf {
    PathBuf::from("../../data/registrar/keys")
}

fn default_controller_authorization_nonce_file() -> PathBuf {
    PathBuf::from("../../data/registrar/controller-authorization-nonces.json")
}

fn default_registration_credential_query_nonce_file() -> PathBuf {
    PathBuf::from("../../data/registrar/registration-credential-query-nonces.json")
}

fn default_root_did() -> String {
    "did:oan:INRT:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned()
}

fn default_stats_report_interval_seconds() -> u64 {
    60
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    config: Config,
    did: String,
    signing_key: SigningKey,
    sqlite: Option<SqliteJsonStore>,
    postgres: Option<PostgresJsonStore>,
    client: reqwest::Client,
    recommender: Arc<SemanticRecommender>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ResourceListQuery {
    #[serde(rename = "afterDid")]
    after_did: Option<String>,
    limit: Option<u32>,
}

const REGISTRAR_DEFAULT_PAGE_SIZE: u32 = 100;
const REGISTRAR_MAX_PAGE_SIZE: u32 = 500;
const REGISTRAR_MAX_RECORD_BYTES: usize = 1024 * 1024;
const REGISTRAR_MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
struct DevKeyFile {
    algorithm: String,
    #[serde(rename = "privateKeyJwk")]
    private_key_jwk: PrivateKeyJwk,
}

#[derive(Clone, Debug, Deserialize)]
struct PrivateKeyJwk {
    d: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

fn crypto_suite_from_algorithm(value: &str) -> Result<CryptoSuite> {
    match value {
        "Ed25519" => Ok(CryptoSuite::Ed25519Sha256),
        "SM2" => Ok(CryptoSuite::Sm2Sm3),
        other => Err(anyhow::anyhow!("unsupported_algorithm: {other}")),
    }
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(error: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.into().to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

const REGISTRATION_CREDENTIAL_QUERY_MAX_CLOCK_SKEW_SECONDS: i64 = 300;
const REGISTRATION_CREDENTIAL_QUERY_NONCE_TTL_SECONDS: i64 = 600;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "services/registrar-node/config.example.toml".to_owned());
    let config = load_config(config_path)?;
    validate_stats_report_config(&config.stats_report)?;
    let did_doc: DidDocument = JsonStore::new(&config.paths.data_dir).read("did-document.json")?;
    let key: DevKeyFile = JsonStore::new(".").read(config.paths.keys_dir.join("keypair.json"))?;
    let crypto_suite = crypto_suite_from_algorithm(&key.algorithm)?;
    let signing_key = signing_key_from_bytes(
        crypto_suite,
        &URL_SAFE_NO_PAD.decode(key.private_key_jwk.d)?,
    )?;
    let (sqlite, postgres) = match config.paths.database_url.as_deref() {
        Some(url) if !url.is_empty() => {
            let database = DatabaseConfig::parse(url)?;
            match database.backend() {
                DatabaseBackend::Sqlite => {
                    let sqlite = SqliteJsonStore::connect(url).await?;
                    (Some(sqlite), None)
                }
                DatabaseBackend::Postgres => {
                    let postgres = PostgresJsonStore::connect(url).await?;
                    (None, Some(postgres))
                }
            }
        }
        _ => (None, None),
    };
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        config: config.clone(),
        did: did_doc.id,
        signing_key,
        sqlite,
        postgres,
        client: reqwest::Client::new(),
        recommender: Arc::new(SemanticRecommender::new()?),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/registrar/did", get(registrar_did_document))
        .route("/resources/register", post(register_resource))
        .route("/resources/submit", post(register_resource))
        .route("/registrar/status", get(api_status))
        .route("/registrar/stats", get(api_stats))
        .route("/registrar/root-authorization", get(api_root_authorization))
        .route("/resources", get(api_resources))
        .route("/resources/{did}", get(api_resource_detail))
        .route(
            "/resources/{did}/registration-credential",
            post(api_registration_credential),
        )
        .route("/capability-tree", get(api_capability_tree))
        .route("/capability-tags/suggest", post(api_suggest_tags))
        .route("/capability-tags/normalize", post(api_normalize_tags))
        .route(
            "/registration/domain-catalog",
            get(api_registration_domain_catalog),
        )
        .route(
            "/registration/suggestions",
            post(api_registration_suggestions),
        )
        .layer(build_cors_layer(&config.cors)?)
        .with_state(state.clone());

    if state.config.stats_report.enabled {
        let report_state = state.clone();
        tokio::spawn(async move {
            registrar_stats_report_loop(report_state).await;
        });
    }

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("registrar-node listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: String) -> Result<Config> {
    let path = PathBuf::from(path);
    let mut config: Config = toml::from_str(&std::fs::read_to_string(&path)?)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    config.paths.records_dir = resolve_relative(base, &config.paths.records_dir);
    config.paths.keys_dir = resolve_relative(base, &config.paths.keys_dir);
    config.paths.controller_authorization_nonce_file =
        resolve_relative(base, &config.paths.controller_authorization_nonce_file);
    config.paths.registration_credential_query_nonce_file =
        resolve_relative(base, &config.paths.registration_credential_query_nonce_file);
    if let Some(database_url) = config.paths.database_url.as_mut() {
        *database_url = resolve_database_url(base, database_url);
    }
    Ok(config)
}

fn validate_stats_report_config(config: &StatsReportConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }
    if config
        .node_id
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(anyhow!("stats_report.node_id is required when enabled"));
    }
    if config
        .endpoint
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(anyhow!("stats_report.endpoint is required when enabled"));
    }
    if config
        .token
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(anyhow!("stats_report.token is required when enabled"));
    }
    if config.interval_seconds == 0 {
        return Err(anyhow!(
            "stats_report.interval_seconds must be greater than 0"
        ));
    }
    Ok(())
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn resolve_database_url(base: &Path, url: &str) -> String {
    let Some(raw_path) = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
    else {
        return url.to_owned();
    };
    let resolved = resolve_relative(base, Path::new(raw_path));
    format!("sqlite:{}", resolved.display())
}

fn build_cors_layer(config: &CorsConfig) -> Result<CorsLayer> {
    let origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .map(|origin| HeaderValue::from_str(origin))
        .collect::<std::result::Result<_, _>>()?;
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers(AllowHeaders::any()))
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        node_type: "registrar".to_owned(),
        did: Some(state.did),
    })
}

async fn registrar_did_document(State(state): State<AppState>) -> ApiResult<DidDocument> {
    state
        .data
        .read("did-document.json")
        .map(Json)
        .map_err(ApiError::internal)
}

async fn register_resource(
    State(state): State<AppState>,
    Json(submission): Json<ResourceRegistrationSubmission>,
) -> ApiResult<Value> {
    submission.validate_shape().map_err(ApiError::bad_request)?;
    let verified_controller_method =
        verify_controller_authorization_for_submission(&state, &submission)
            .map_err(ApiError::bad_request)?;
    let authorized_domains =
        validate_resource_authorized_domains_for_registrar(&state, &submission)?;
    let request = build_resource_verify_and_publish_request(&state, submission.clone())?;
    let response = state
        .client
        .post(format!(
            "{}{}",
            state.config.upstream.root_endpoint, PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH
        ))
        .json(&request)
        .send()
        .await
        .map_err(ApiError::internal)?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        return Err(ApiError {
            status,
            message: body
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("root_resource_registration_failed")
                .to_owned(),
        });
    }
    let did_document_hash =
        hash_json_with_suite(state.signing_key.crypto_suite(), &submission.did_document)
            .map_err(ApiError::internal)?;
    let registration_credential =
        issue_resource_registration_credential(&state, &submission, &did_document_hash)?;
    let mut record = json!({
        "resourceDid": submission.resource_did,
        "resourceType": submission.resource_type,
        "packageVersion": submission.package_version,
        "didDocumentHash": did_document_hash,
        "metadataHash": submission.metadata_hash,
        "packageHash": submission.package_hash,
        "authorizedDomains": authorized_domains,
        "registrationCredential": registration_credential,
        "rootResponse": body,
        "submittedAt": chrono::Utc::now()
    });
    if let Some(verification_method) = verified_controller_method {
        if let Some(controller_did) = submission
            .did_document
            .oan_metadata
            .as_ref()
            .and_then(|metadata| metadata.controller_did.as_deref())
        {
            let controller_method_hash = submission
                .controller_authorization_proof
                .as_ref()
                .and_then(|bundle| {
                    controller_method_hash(
                        &state,
                        &bundle.controller_did_document,
                        &verification_method,
                    )
                    .ok()
                })
                .ok_or_else(|| ApiError::bad_request("controller_authorization_method_missing"))?;
            record["registrationCredentialAccess"] = json!({
                "enabled": true,
                "controllerDid": controller_did,
                "verifiedVerificationMethod": verification_method,
                "verifiedControllerMethodHash": controller_method_hash,
                "verifiedAuthorityBindingHash": hash_json_with_suite(
                    state.signing_key.crypto_suite(),
                    &json!({
                        "resourceDid": submission.resource_did,
                        "controllerDid": controller_did,
                        "verificationMethod": verification_method,
                        "didDocumentHash": submission.did_document_hash,
                        "metadataHash": submission.metadata_hash,
                        "registrarDid": state.did,
                        "purpose": PURPOSE_CONTROLLER_AUTHORIZATION_REGISTRATION
                    })
                )
                .map_err(ApiError::internal)?,
                "verifiedAt": Utc::now(),
                "policyVersion": "registration-credential-access-v1"
            });
        }
    }
    write_resource_record(&state, &record).await?;
    Ok(Json(json!({
        "status": "submitted",
        "resourceDid": record["resourceDid"],
        "resourceType": record["resourceType"],
        "registrationCredential": record["registrationCredential"],
        "rootResponse": record["rootResponse"]
    })))
}

fn verify_controller_authorization_for_submission(
    state: &AppState,
    submission: &ResourceRegistrationSubmission,
) -> std::result::Result<Option<String>, String> {
    let Some(metadata) = submission.did_document.oan_metadata.as_ref() else {
        return Ok(None);
    };
    let Some(controller_did) = metadata.controller_did.as_deref() else {
        return Ok(None);
    };
    if controller_did == submission.resource_did {
        return Ok(None);
    }
    let Some(bundle) = submission.controller_authorization_proof.as_ref() else {
        eprintln!(
            "controller authorization proof missing for resource {} controlled by {}",
            submission.resource_did, controller_did
        );
        return Err("controller_authorization_proof_required".to_owned());
    };
    let expected_publisher_did = metadata.publisher_did.as_deref();
    let verification_method = verify_controller_authorization_proof(
        bundle,
        &ControllerAuthorizationVerificationContext {
            expected_resource_did: &submission.resource_did,
            expected_controller_did: controller_did,
            expected_publisher_did,
            expected_did_document_hash: &submission.did_document_hash,
            expected_metadata_hash: &submission.metadata_hash,
            expected_registrar_did: &state.did,
            expected_purpose: PURPOSE_CONTROLLER_AUTHORIZATION_REGISTRATION,
            max_clock_skew_seconds: 60,
            now: Utc::now(),
        },
    )
    .map_err(|err| {
        let message = err.to_string();
        eprintln!(
            "controller authorization proof rejected for resource {} controlled by {}: {}",
            submission.resource_did, controller_did, message
        );
        message
    })?;
    verify_and_store_nonce(
        &state.config.paths.controller_authorization_nonce_file,
        &bundle.challenge.nonce,
        Utc::now(),
        Utc::now(),
        300,
    )
    .map_err(|err| {
        let message = if err.to_string() == "trusted_upstream_nonce_replayed" {
            "controller_authorization_nonce_replayed".to_owned()
        } else {
            err.to_string()
        };
        eprintln!(
            "controller authorization nonce rejected for resource {} controlled by {}: {}",
            submission.resource_did, controller_did, message
        );
        message
    })?;
    Ok(Some(verification_method))
}

fn validate_resource_authorized_domains_for_registrar(
    state: &AppState,
    submission: &ResourceRegistrationSubmission,
) -> std::result::Result<Vec<String>, ApiError> {
    let registrar_document: DidDocument = state
        .data
        .read("did-document.json")
        .map_err(ApiError::internal)?;
    let registrar_domains = registrar_document
        .oan_metadata
        .as_ref()
        .map(|metadata| metadata.authorized_domains.clone())
        .unwrap_or_default();
    let resource_domains = submission
        .did_document
        .oan_metadata
        .as_ref()
        .map(|metadata| metadata.authorized_domains.clone())
        .unwrap_or_default();

    if let Some(metadata_domains) = submission
        .metadata
        .get("authorizedDomains")
        .and_then(Value::as_array)
        .map(|domains| {
            domains
                .iter()
                .map(|domain| {
                    domain
                        .as_str()
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| "invalid_authorized_domains".to_owned())
                })
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(ApiError::bad_request)?
    {
        if metadata_domains != resource_domains {
            return Err(ApiError::bad_request("authorized_domains_mismatch"));
        }
    }

    validate_resource_authorized_domains(&resource_domains, &registrar_domains)
        .map_err(ApiError::bad_request)?;
    Ok(resource_domains)
}

fn validate_authorized_domain_list(domains: &[String]) -> std::result::Result<(), String> {
    if domains.iter().any(|domain| domain == "*") {
        return if domains.len() == 1 {
            Ok(())
        } else {
            Err("invalid_authorized_domains".to_owned())
        };
    }
    for domain in domains {
        if domain.trim().is_empty()
            || domain != domain.trim()
            || domain.contains("..")
            || domain.starts_with('.')
            || domain.ends_with('.')
        {
            return Err("invalid_authorized_domains".to_owned());
        }
    }
    if domains.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("invalid_authorized_domains".to_owned());
    }
    Ok(())
}

fn authorized_domain_covers(granted: &str, requested: &str) -> bool {
    granted == requested
        || requested
            .strip_prefix(granted)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn authorized_domains_cover(granted: &[String], requested: &[String]) -> bool {
    if requested.is_empty() {
        return true;
    }
    if granted.iter().any(|domain| domain == "*") {
        return true;
    }
    if granted.is_empty() {
        return false;
    }
    requested.iter().all(|requested_domain| {
        granted
            .iter()
            .any(|granted_domain| authorized_domain_covers(granted_domain, requested_domain))
    })
}

fn validate_resource_authorized_domains(
    resource_domains: &[String],
    registrar_domains: &[String],
) -> std::result::Result<(), String> {
    if resource_domains.is_empty() {
        return Err("resource_domains_required".to_owned());
    }
    validate_authorized_domain_list(resource_domains)?;
    validate_authorized_domain_list(registrar_domains)?;
    if !authorized_domains_cover(registrar_domains, resource_domains) {
        return Err("unauthorized_domains".to_owned());
    }
    Ok(())
}

fn build_resource_verify_and_publish_request(
    state: &AppState,
    submission: ResourceRegistrationSubmission,
) -> std::result::Result<ResourceVerifyAndPublishRequest, ApiError> {
    let mut root_submission = submission;
    root_submission.registration_credential = Value::Null;
    let envelope = create_signed_request_envelope(SignedRequestEnvelopeInput {
        request_id: request_id("resource-verify-and-publish"),
        protocol_version: OAN_RESOURCE_PROTOCOL_VERSION.to_owned(),
        purpose: PURPOSE_VERIFY_AND_PUBLISH.to_owned(),
        method: "POST".to_owned(),
        path: PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH.to_owned(),
        aud: state.config.security.upstream.root_did.clone(),
        payload: &root_submission,
        creator: state.did.clone(),
        verification_method: format!("{}#key-1", state.did),
        signing_key: &state.signing_key,
        nonce: request_nonce("resource-verify-and-publish"),
    })
    .map_err(ApiError::internal)?;
    Ok(ResourceVerifyAndPublishRequest {
        registrar_did: state.did.clone(),
        submission: root_submission,
        upstream_auth: envelope,
    })
}

fn issue_resource_registration_credential(
    state: &AppState,
    submission: &ResourceRegistrationSubmission,
    did_document_hash: &str,
) -> std::result::Result<Value, ApiError> {
    let issued_at = chrono::Utc::now();
    let key_id = format!("{}#key-1", state.did);
    let authorized_domains = submission
        .did_document
        .oan_metadata
        .as_ref()
        .map(|metadata| metadata.authorized_domains.clone())
        .unwrap_or_default();
    let mut credential = json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://openagenet.org/credentials/v1"
        ],
        "id": format!("urn:oan:credential:resource-registration:{}", did_to_file_name(&submission.resource_did).trim_end_matches(".json")),
        "type": [
            "VerifiableCredential",
            "OANResourceRegistrationCredential"
        ],
        "issuer": state.did,
        "issuanceDate": issued_at,
        "credentialSubject": {
            "id": submission.resource_did,
            "resourceDid": submission.resource_did,
            "resourceType": submission.resource_type,
            "didDocumentHash": did_document_hash,
            "metadataHash": submission.metadata_hash,
            "packageHash": submission.package_hash,
            "packageVersion": submission.package_version,
            "hashAlgorithm": submission.hash_algorithm,
            "authorizedDomains": authorized_domains,
            "lifecycleState": submission.metadata["lifecycleState"].as_str().unwrap_or("active")
        },
        "credentialStatus": {
            "type": "OANResourceRegistrationStatus",
            "status": "active"
        }
    });
    let proof = sign_credential(&credential, key_id.clone(), key_id, &state.signing_key)
        .map_err(ApiError::internal)?;
    credential["proof"] = serde_json::to_value(proof).map_err(ApiError::internal)?;
    Ok(credential)
}

async fn write_resource_record(
    state: &AppState,
    record: &Value,
) -> std::result::Result<(), ApiError> {
    let did = record["resourceDid"]
        .as_str()
        .ok_or_else(|| ApiError::bad_request("resource_did_missing"))?;
    if let Some(sqlite) = &state.sqlite {
        sqlite
            .upsert_json("registrar.resource_records", did, record)
            .await
            .map_err(ApiError::internal)?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        postgres
            .upsert_json("registrar.resource_records", did, record)
            .await
            .map_err(ApiError::internal)?;
        return Ok(());
    }
    state
        .data
        .write(
            format!("resource-records/{}", did_to_file_name(did)),
            record,
        )
        .map_err(ApiError::internal)?;
    Ok(())
}

async fn read_resource_records(state: &AppState) -> Result<Vec<Value>> {
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .read_namespace("registrar.resource_records")
            .await
            .map_err(Into::into);
    }
    if let Some(postgres) = &state.postgres {
        return postgres
            .read_namespace("registrar.resource_records")
            .await
            .map_err(Into::into);
    }
    Ok(state
        .data
        .read("resource-records/index.json")
        .unwrap_or_else(|_| {
            let mut records = Vec::new();
            if let Ok(entries) =
                std::fs::read_dir(state.config.paths.data_dir.join("resource-records"))
            {
                for entry in entries.flatten() {
                    if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                        if let Ok(value) = JsonStore::new(".").read(entry.path()) {
                            records.push(value);
                        }
                    }
                }
            }
            records
        }))
}

async fn read_resource_record(state: &AppState, did: &str) -> Result<Option<Value>> {
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .read_json("registrar.resource_records", did)
            .await
            .map_err(Into::into);
    }
    if let Some(postgres) = &state.postgres {
        return postgres
            .read_json("registrar.resource_records", did)
            .await
            .map_err(Into::into);
    }
    Ok(state
        .data
        .read(format!("resource-records/{}", did_to_file_name(did)))
        .ok())
}

async fn resource_record_count(state: &AppState) -> Result<usize> {
    if let Some(sqlite) = &state.sqlite {
        return Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM json_records WHERE namespace = ?",
        )
        .bind("registrar.resource_records")
        .fetch_one(sqlite.pool())
        .await? as usize);
    }
    if let Some(postgres) = &state.postgres {
        return Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM json_records WHERE namespace = $1",
        )
        .bind("registrar.resource_records")
        .fetch_one(postgres.pool())
        .await? as usize);
    }
    Ok(read_resource_records(state).await?.len())
}

async fn api_status(State(state): State<AppState>) -> ApiResult<Value> {
    let resource_count = resource_record_count(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "registrarDid": state.did,
        "rootEndpoint": state.config.upstream.root_endpoint,
        "resourceRecordCount": resource_count,
        "protocolVersion": OAN_RESOURCE_PROTOCOL_VERSION
    })))
}

async fn api_stats(State(state): State<AppState>) -> ApiResult<Value> {
    registrar_stats_body(&state)
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

async fn registrar_stats_body(state: &AppState) -> Result<Value> {
    let generated_at = Utc::now();
    let today = generated_at.date_naive();
    let week_start = today - chrono::Duration::days(today.weekday().num_days_from_monday() as i64);
    let month_start = today.with_day(1).unwrap_or(today);
    let today_text = today.to_string();
    let week_start_text = week_start.to_string();
    let month_start_text = month_start.to_string();
    let (resource_record_count, type_counts, today_count, week_count, month_count) = if let Some(
        sqlite,
    ) =
        &state.sqlite
    {
        let row = sqlx::query(
                "SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN json_extract(value_json, '$.resourceType') = 'agent_service' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN json_extract(value_json, '$.resourceType') = 'skill' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN json_extract(value_json, '$.resourceType') = 'mcp_server' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN json_extract(value_json, '$.resourceType') = 'tool_api' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN substr(json_extract(value_json, '$.submittedAt'), 1, 10) = ? THEN 1 ELSE 0 END),
                    SUM(CASE WHEN substr(json_extract(value_json, '$.submittedAt'), 1, 10) >= ? THEN 1 ELSE 0 END),
                    SUM(CASE WHEN substr(json_extract(value_json, '$.submittedAt'), 1, 10) >= ? THEN 1 ELSE 0 END)
                 FROM json_records
                 WHERE namespace = ?",
            )
            .bind(&today_text)
            .bind(&week_start_text)
            .bind(&month_start_text)
            .bind("registrar.resource_records")
            .fetch_one(sqlite.pool())
            .await?;
        (
            row.get::<i64, _>(0) as usize,
            [
                row.get::<Option<i64>, _>(1).unwrap_or(0),
                row.get::<Option<i64>, _>(2).unwrap_or(0),
                row.get::<Option<i64>, _>(3).unwrap_or(0),
                row.get::<Option<i64>, _>(4).unwrap_or(0),
            ],
            row.get::<Option<i64>, _>(5).unwrap_or(0),
            row.get::<Option<i64>, _>(6).unwrap_or(0),
            row.get::<Option<i64>, _>(7).unwrap_or(0),
        )
    } else if let Some(postgres) = &state.postgres {
        let row = sqlx::query(
            "SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE value_json::jsonb ->> 'resourceType' = 'agent_service'),
                    COUNT(*) FILTER (WHERE value_json::jsonb ->> 'resourceType' = 'skill'),
                    COUNT(*) FILTER (WHERE value_json::jsonb ->> 'resourceType' = 'mcp_server'),
                    COUNT(*) FILTER (WHERE value_json::jsonb ->> 'resourceType' = 'tool_api'),
                    COUNT(*) FILTER (WHERE LEFT(value_json::jsonb ->> 'submittedAt', 10) = $1),
                    COUNT(*) FILTER (WHERE LEFT(value_json::jsonb ->> 'submittedAt', 10) >= $2),
                    COUNT(*) FILTER (WHERE LEFT(value_json::jsonb ->> 'submittedAt', 10) >= $3)
                 FROM json_records
                 WHERE namespace = $4",
        )
        .bind(&today_text)
        .bind(&week_start_text)
        .bind(&month_start_text)
        .bind("registrar.resource_records")
        .fetch_one(postgres.pool())
        .await?;
        (
            row.get::<i64, _>(0) as usize,
            [
                row.get::<i64, _>(1),
                row.get::<i64, _>(2),
                row.get::<i64, _>(3),
                row.get::<i64, _>(4),
            ],
            row.get::<i64, _>(5),
            row.get::<i64, _>(6),
            row.get::<i64, _>(7),
        )
    } else {
        let records = read_resource_records(state).await?;
        let mut type_counts = [0_i64; 4];
        let mut today_count = 0_i64;
        let mut week_count = 0_i64;
        let mut month_count = 0_i64;
        for record in &records {
            accumulate_registrar_stats(
                record,
                &mut type_counts,
                &mut today_count,
                &mut week_count,
                &mut month_count,
                (today, week_start, month_start),
            );
        }
        (
            records.len(),
            type_counts,
            today_count,
            week_count,
            month_count,
        )
    };
    Ok(json!({
        "registrarDid": state.did,
        "generatedAt": generated_at.to_rfc3339(),
        "windowTimezone": "UTC",
        "resourceRecordCount": resource_record_count,
        "agentServiceCount": type_counts[0],
        "skillCount": type_counts[1],
        "mcpServerCount": type_counts[2],
        "toolApiCount": type_counts[3],
        "todayRegistrationCount": today_count,
        "weekRegistrationCount": week_count,
        "monthRegistrationCount": month_count,
    }))
}

fn accumulate_registrar_stats(
    record: &Value,
    type_counts: &mut [i64; 4],
    today_count: &mut i64,
    week_count: &mut i64,
    month_count: &mut i64,
    (today, week_start, month_start): (chrono::NaiveDate, chrono::NaiveDate, chrono::NaiveDate),
) {
    match record.get("resourceType").and_then(Value::as_str) {
        Some("agent_service") => type_counts[0] += 1,
        Some("skill") => type_counts[1] += 1,
        Some("mcp_server") => type_counts[2] += 1,
        Some("tool_api") => type_counts[3] += 1,
        _ => {}
    }
    let Some(submitted_at) = record.get("submittedAt").and_then(Value::as_str) else {
        return;
    };
    let Ok(submitted_at) = DateTime::parse_from_rfc3339(submitted_at) else {
        return;
    };
    let submitted_day = submitted_at.with_timezone(&Utc).date_naive();
    if submitted_day == today {
        *today_count += 1;
    }
    if submitted_day >= week_start {
        *week_count += 1;
    }
    if submitted_day >= month_start {
        *month_count += 1;
    }
}

async fn registrar_stats_report_loop(state: AppState) {
    loop {
        if let Err(err) = report_registrar_stats_once(&state).await {
            eprintln!("registrar stats report failed: {err}");
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(
            state.config.stats_report.interval_seconds,
        ))
        .await;
    }
}

async fn report_registrar_stats_once(state: &AppState) -> Result<()> {
    let config = &state.config.stats_report;
    let stats = registrar_stats_body(state).await?;
    let endpoint = config
        .endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("stats_report.endpoint is required"))?;
    let token = config
        .token
        .as_deref()
        .ok_or_else(|| anyhow!("stats_report.token is required"))?;
    let payload = json!({
        "nodeId": config
            .node_id
            .as_deref()
            .ok_or_else(|| anyhow!("stats_report.node_id is required"))?,
        "role": "registrar",
        "status": "online",
        "generatedAt": stats["generatedAt"],
        "resourceTotals": {
            "registeredResources": stats["resourceRecordCount"]
        },
        "resourcesByType": {
            "agentService": stats["agentServiceCount"],
            "skill": stats["skillCount"],
            "mcpServer": stats["mcpServerCount"],
            "toolApi": stats["toolApiCount"]
        },
        "registrationWindows": {
            "today": stats["todayRegistrationCount"],
            "thisWeek": stats["weekRegistrationCount"],
            "thisMonth": stats["monthRegistrationCount"]
        }
    });
    let response = state
        .client
        .post(endpoint)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("homepage returned {status}: {body}"));
    }
    Ok(())
}

async fn api_root_authorization(State(state): State<AppState>) -> ApiResult<Value> {
    let response = state
        .client
        .get(format!(
            "{}/root/registrars/{}",
            state.config.upstream.root_endpoint.trim_end_matches('/'),
            state.did
        ))
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            let body: Value = response.json().await.unwrap_or_else(|_| json!({}));
            Ok(Json(json!({
                "registrarDid": state.did,
                "rootEndpoint": state.config.upstream.root_endpoint,
                "rootReachable": true,
                "authorization": body
            })))
        }
        Ok(response) => Ok(Json(json!({
            "registrarDid": state.did,
            "rootEndpoint": state.config.upstream.root_endpoint,
            "rootReachable": true,
            "status": "unknown",
            "rootStatusCode": response.status().as_u16()
        }))),
        Err(err) => Ok(Json(json!({
            "registrarDid": state.did,
            "rootEndpoint": state.config.upstream.root_endpoint,
            "rootReachable": false,
            "error": err.to_string()
        }))),
    }
}

async fn api_resources(
    State(state): State<AppState>,
    Query(query): Query<ResourceListQuery>,
) -> ApiResult<Value> {
    let limit = query.limit.unwrap_or(REGISTRAR_DEFAULT_PAGE_SIZE);
    if limit == 0 || limit > REGISTRAR_MAX_PAGE_SIZE {
        return Err(ApiError::bad_request("invalid_resource_page_limit"));
    }
    let after_did = query.after_did.as_deref().unwrap_or("");
    let mut items = Vec::new();
    let mut has_more = false;
    let mut next_did = None;
    let mut page_bytes = 0_usize;
    if let Some(sqlite) = &state.sqlite {
        let mut rows = sqlx::query(
            "SELECT record_key, value_json FROM json_records
             WHERE namespace = ? AND record_key > ?
             ORDER BY record_key LIMIT ?",
        )
        .bind("registrar.resource_records")
        .bind(after_did)
        .bind(i64::from(limit))
        .fetch(sqlite.pool());
        while let Some(row) = rows.try_next().await.map_err(ApiError::internal)? {
            let did = row.get::<String, _>(0);
            next_did = Some(did);
            let value_json = row.get::<String, _>(1);
            items.push(public_resource_record_projection_from_json(
                &value_json,
                &mut page_bytes,
            )?);
        }
        let probe_after = next_did.as_deref().unwrap_or(after_did);
        has_more = sqlx::query(
            "SELECT 1 FROM json_records
             WHERE namespace = ? AND record_key > ?
             LIMIT 1",
        )
        .bind("registrar.resource_records")
        .bind(probe_after)
        .fetch_optional(sqlite.pool())
        .await
        .map_err(ApiError::internal)?
        .is_some();
    } else if let Some(postgres) = &state.postgres {
        let mut rows = sqlx::query(
            "SELECT record_key, value_json::text FROM json_records
             WHERE namespace = $1 AND record_key > $2
             ORDER BY record_key LIMIT $3",
        )
        .bind("registrar.resource_records")
        .bind(after_did)
        .bind(i64::from(limit))
        .fetch(postgres.pool());
        while let Some(row) = rows.try_next().await.map_err(ApiError::internal)? {
            let did = row.get::<String, _>(0);
            next_did = Some(did);
            let value_json = row.get::<String, _>(1);
            items.push(public_resource_record_projection_from_json(
                &value_json,
                &mut page_bytes,
            )?);
        }
        let probe_after = next_did.as_deref().unwrap_or(after_did);
        has_more = sqlx::query(
            "SELECT 1 FROM json_records
             WHERE namespace = $1 AND record_key > $2
             LIMIT 1",
        )
        .bind("registrar.resource_records")
        .bind(probe_after)
        .fetch_optional(postgres.pool())
        .await
        .map_err(ApiError::internal)?
        .is_some();
    } else {
        let records = read_resource_records(&state)
            .await
            .map_err(ApiError::internal)?;
        let mut records = records
            .iter()
            .filter_map(|record| {
                let did = record.get("resourceDid")?.as_str()?;
                (did > after_did).then_some((did.to_owned(), record))
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0));
        has_more = records.len() > limit as usize;
        records.truncate(limit as usize);
        for (did, record) in records {
            next_did = Some(did);
            let value_json = serde_json::to_string(record).map_err(ApiError::internal)?;
            items.push(public_resource_record_projection_from_json(
                &value_json,
                &mut page_bytes,
            )?);
        }
    }
    if !has_more {
        next_did = None;
    }
    Ok(Json(json!({
        "items": items,
        "count": items.len(),
        "afterDid": if after_did.is_empty() { Value::Null } else { json!(after_did) },
        "nextDid": next_did,
        "hasMore": has_more
    })))
}

fn public_resource_record_projection_from_json(
    value_json: &str,
    page_bytes: &mut usize,
) -> std::result::Result<Value, ApiError> {
    let record_bytes = value_json.len();
    if record_bytes > REGISTRAR_MAX_RECORD_BYTES {
        return Err(ApiError::bad_request("resource_record_too_large"));
    }
    *page_bytes = page_bytes.saturating_add(record_bytes);
    if *page_bytes > REGISTRAR_MAX_PAGE_BYTES {
        return Err(ApiError::bad_request("resource_page_too_large"));
    }
    let record: Value = serde_json::from_str(value_json).map_err(ApiError::internal)?;
    Ok(public_resource_record_projection(&record))
}

async fn api_resource_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let record = read_resource_record(&state, &did)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("resource_not_found"))?;
    Ok(Json(json!({
        "resourceDid": did,
        "record": public_resource_record_projection(&record)
    })))
}

fn public_resource_record_projection(record: &Value) -> Value {
    let mut projection = serde_json::Map::new();
    for field in [
        "resourceDid",
        "resourceType",
        "packageVersion",
        "didDocumentHash",
        "metadataHash",
        "packageHash",
        "authorizedDomains",
        "submittedAt",
    ] {
        if let Some(value) = record.get(field) {
            projection.insert(field.to_owned(), value.clone());
        }
    }
    if let Some(status) = record
        .get("rootResponse")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
    {
        projection.insert("rootStatus".to_owned(), json!(status));
    }
    Value::Object(projection)
}

async fn api_registration_credential(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
    Json(request): Json<RegistrationCredentialQueryRequest>,
) -> std::result::Result<Response, ApiError> {
    let record = read_resource_record(&state, &did)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("resource_not_found"))?;
    let registration_credential = record
        .get("registrationCredential")
        .cloned()
        .ok_or_else(|| ApiError::forbidden("registration_credential_access_denied"))?;
    verify_registration_credential_query(&state, &did, &record, &request)?;
    let body = json!({
        "resourceDid": did,
        "controllerDid": request.challenge.controller_did,
        "registrationCredential": registration_credential
    });
    Ok((
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(body),
    )
        .into_response())
}

fn verify_registration_credential_query(
    state: &AppState,
    resource_did: &str,
    record: &Value,
    request: &RegistrationCredentialQueryRequest,
) -> std::result::Result<(), ApiError> {
    let challenge = &request.challenge;
    if challenge.method != "POST"
        || challenge.path != registration_credential_query_path(resource_did)
        || challenge.resource_did != resource_did
        || challenge.purpose != PURPOSE_REGISTRATION_CREDENTIAL_QUERY
        || challenge.aud != state.did
        || challenge.protocol_version != PROTOCOL_REGISTRATION_CREDENTIAL_QUERY_V1
        || challenge.request_nonce.trim().is_empty()
    {
        return Err(ApiError::bad_request(
            "invalid_registration_credential_query",
        ));
    }
    if challenge.request_timestamp
        > Utc::now() + Duration::seconds(REGISTRATION_CREDENTIAL_QUERY_MAX_CLOCK_SKEW_SECONDS)
        || Utc::now()
            > challenge.request_timestamp
                + Duration::seconds(REGISTRATION_CREDENTIAL_QUERY_MAX_CLOCK_SKEW_SECONDS)
    {
        return Err(ApiError::bad_request(
            "registration_credential_query_expired",
        ));
    }
    let access = record
        .get("registrationCredentialAccess")
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::forbidden("registration_credential_access_denied"))?;
    if access.get("enabled").and_then(Value::as_bool) != Some(true) {
        return Err(ApiError::forbidden("registration_credential_access_denied"));
    }
    if access
        .get("controllerDid")
        .and_then(Value::as_str)
        .map(|value| value != challenge.controller_did)
        .unwrap_or(true)
    {
        return Err(ApiError::forbidden("registration_credential_access_denied"));
    }
    if access
        .get("verifiedVerificationMethod")
        .and_then(Value::as_str)
        .map(|value| value != challenge.verification_method)
        .unwrap_or(true)
    {
        return Err(ApiError::forbidden("registration_credential_access_denied"));
    }
    if request.controller_did_document.id != challenge.controller_did {
        return Err(ApiError::unauthorized("invalid_controller_signature"));
    }
    let method = find_relationship_method(
        &request.controller_did_document,
        VerificationRelationship::CapabilityInvocation,
        Some(&challenge.verification_method),
    )
    .or_else(|_| {
        find_relationship_method(
            &request.controller_did_document,
            VerificationRelationship::Authentication,
            Some(&challenge.verification_method),
        )
    })
    .or_else(|_| {
        find_relationship_method(
            &request.controller_did_document,
            VerificationRelationship::AssertionMethod,
            Some(&challenge.verification_method),
        )
    })
    .map_err(|_| ApiError::unauthorized("invalid_controller_signature"))?;
    let verifying_key = verifying_key_from_method(method)
        .map_err(|_| ApiError::unauthorized("invalid_controller_signature"))?;
    let expected_method_hash = access
        .get("verifiedControllerMethodHash")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::forbidden("registration_credential_access_denied"))?;
    let actual_method_hash = hash_json_with_suite(state.signing_key.crypto_suite(), method)
        .map_err(|_| ApiError::unauthorized("invalid_controller_signature"))?;
    if actual_method_hash != expected_method_hash {
        return Err(ApiError::forbidden("registration_credential_access_denied"));
    }
    verify_payload_with_proof(challenge, &request.proof, &verifying_key)
        .map_err(|_| ApiError::unauthorized("invalid_controller_signature"))?;
    verify_and_store_nonce(
        &state.config.paths.registration_credential_query_nonce_file,
        &challenge.request_nonce,
        challenge.request_timestamp,
        Utc::now(),
        REGISTRATION_CREDENTIAL_QUERY_NONCE_TTL_SECONDS,
    )
    .map_err(|err| {
        if err.to_string().contains("nonce_replayed") {
            ApiError::forbidden("registration_credential_query_replay")
        } else {
            ApiError::bad_request("invalid_registration_credential_query")
        }
    })?;
    Ok(())
}

fn registration_credential_query_path(resource_did: &str) -> String {
    format!(
        "/resources/{}/registration-credential",
        percent_encode_path_segment(resource_did)
    )
}

fn controller_method_hash(
    state: &AppState,
    controller_document: &DidDocument,
    verification_method: &str,
) -> std::result::Result<String, ApiError> {
    let method = controller_document
        .verification_method
        .iter()
        .find(|method| method.id == verification_method)
        .ok_or_else(|| ApiError::bad_request("controller_authorization_method_missing"))?;
    hash_json_with_suite(state.signing_key.crypto_suite(), method).map_err(ApiError::internal)
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

async fn api_capability_tree() -> ApiResult<Value> {
    let tree = CapabilityTagTree::load_from_path("../../docs/capability-tree-v1.json").unwrap_or(
        CapabilityTagTree {
            version: 1,
            tags: vec![],
            tree: vec![],
        },
    );
    Ok(Json(json!(tree)))
}

async fn api_suggest_tags(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let text = payload["description"]
        .as_str()
        .or_else(|| payload["query"].as_str())
        .unwrap_or("");
    let input = RegistrationSuggestionInput {
        resource_type: None,
        name: payload["name"].as_str().unwrap_or("").to_owned(),
        description: text.to_owned(),
        endpoint: payload["endpoint"].as_str().map(ToOwned::to_owned),
        manifest_text: payload["manifestText"].as_str().map(ToOwned::to_owned),
        schema_text: payload["schemaText"].as_str().map(ToOwned::to_owned),
        locale: payload["locale"].as_str().map(ToOwned::to_owned),
    };
    let result = state
        .recommender
        .suggest_registration_metadata(input, registration_suggestion_context(&state)?)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    let suggestions = result
        .capability_tags
        .iter()
        .map(|tag| tag.value.clone())
        .collect::<Vec<_>>();
    Ok(Json(
        json!({ "suggestions": suggestions, "capabilityTags": result.capability_tags }),
    ))
}

async fn api_normalize_tags(Json(payload): Json<Value>) -> ApiResult<Value> {
    let tags = payload["tags"]
        .as_array()
        .or_else(|| payload["capabilityTags"].as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let normalized = normalize_capability_tags(&tags);
    Ok(Json(json!({
        "tags": normalized,
        "capabilityTags": normalized
    })))
}

async fn api_registration_domain_catalog(State(state): State<AppState>) -> ApiResult<Value> {
    let registrar_domains = registrar_authorized_domains(&state)?;
    let domains = state
        .recommender
        .taxonomy()
        .domains
        .iter()
        .filter(|domain| {
            domain_covered_by_scope(&state, &domain.id, &registrar_domains).unwrap_or(false)
        })
        .map(|domain| {
            json!({
                "id": domain.id,
                "label": domain.label,
                "aliases": domain.aliases,
                "selectable": true
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "registrarDid": state.did,
        "authorizedDomains": registrar_domains,
        "catalogVersion": state.recommender.taxonomy().version,
        "snapshotHash": state.recommender.taxonomy().snapshot_hash,
        "domains": domains
    })))
}

async fn api_registration_suggestions(
    State(state): State<AppState>,
    Json(payload): Json<RegistrationSuggestionInput>,
) -> ApiResult<Value> {
    let result = state
        .recommender
        .suggest_registration_metadata(payload, registration_suggestion_context(&state)?)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    Ok(Json(
        serde_json::to_value(result).map_err(ApiError::internal)?,
    ))
}

fn registration_suggestion_context(
    state: &AppState,
) -> std::result::Result<RegistrationSuggestionContext, ApiError> {
    Ok(RegistrationSuggestionContext {
        registrar_did: state.did.clone(),
        allowed_domains: registrar_authorized_domains(state)?,
        max_authorized_domain_candidates: 8,
        max_capability_tag_candidates: 12,
    })
}

fn registrar_authorized_domains(state: &AppState) -> std::result::Result<Vec<String>, ApiError> {
    let registrar_document: DidDocument = state
        .data
        .read("did-document.json")
        .map_err(ApiError::internal)?;
    Ok(registrar_document
        .oan_metadata
        .as_ref()
        .map(|metadata| metadata.authorized_domains.clone())
        .unwrap_or_default())
}

fn domain_covered_by_scope(
    state: &AppState,
    domain: &str,
    scope: &[String],
) -> std::result::Result<bool, ApiError> {
    if scope.iter().any(|item| item == "*") {
        return Ok(true);
    }
    Ok(state
        .recommender
        .taxonomy()
        .covers_authorized_domains(&[domain.to_owned()], scope))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Router};
    use chrono::{Duration, Utc};
    use oan_core::{
        OanMetadata, ProtocolBinding, ResourceDescription, ResourceType, ServiceEndpoint,
        VerificationMethod,
    };
    use oan_crypto::{generate_ed25519_keypair, public_key_multibase, VerifyingKey};
    use oan_protocol::{
        ControllerAuthorizationChallenge, ControllerAuthorizationProofBundle, DidControlChallenge,
        RegistrationCredentialQueryChallenge, SubjectControlProofBundle,
    };
    use tempfile::tempdir;

    fn app_state(dir: &std::path::Path) -> AppState {
        let key = generate_ed25519_keypair();
        AppState {
            data: JsonStore::new(dir),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8002,
                },
                cors: CorsConfig::default(),
                security: SecurityConfig {
                    upstream: UpstreamSecurityConfig {
                        root_did: "did:oan:AGRT:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned(),
                    },
                },
                stats_report: StatsReportConfig::default(),
                upstream: UpstreamConfig {
                    root_endpoint: "http://127.0.0.1:8001".to_owned(),
                },
                paths: PathConfig {
                    data_dir: dir.to_path_buf(),
                    records_dir: dir.join("records"),
                    keys_dir: dir.join("keys"),
                    controller_authorization_nonce_file: dir
                        .join("controller-authorization-nonces.json"),
                    registration_credential_query_nonce_file: dir
                        .join("registration-credential-query-nonces.json"),
                    database_url: None,
                },
            },
            did: "did:oan:AGRG:6HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned(),
            signing_key: SigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256,
                key,
            },
            sqlite: None,
            postgres: None,
            client: reqwest::Client::new(),
            recommender: Arc::new(SemanticRecommender::new().unwrap()),
        }
    }

    fn sample_document(did: &str) -> DidDocument {
        let key = generate_ed25519_keypair();
        let verifying_key = VerifyingKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256,
            key: key.verifying_key(),
        };
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#key-1"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(public_key_multibase(&verifying_key)),
                public_key_jwk: None,
            }],
            authentication: vec![format!("{did}#key-1")],
            assertion_method: vec![format!("{did}#key-1")],
            capability_invocation: vec![format!("{did}#key-1")],
            service: vec![ServiceEndpoint {
                id: format!("{did}#download"),
                service_type: "SkillPackageDownload".to_owned(),
                service_endpoint: "https://example.org/skill.json".to_owned(),
                version: Some("1".to_owned()),
                protocol: Some("https".to_owned()),
                server_type: None,
                port: None,
            }],
            oan_metadata: Some(OanMetadata {
                subject_type: ResourceType::Skill,
                resource_type: ResourceType::Skill,
                node_role: None,
                identity_type: None,
                controller_did: None,
                publisher_did: None,
                issuer_did: None,
                ttl: None,
                resource_description: Some(ResourceDescription {
                    name: Some("Contract Skill".to_owned()),
                    description: Some("Review contracts".to_owned()),
                    capability_tags: vec!["legal.contract.review".to_owned()],
                    ..Default::default()
                }),
                agent_description: None,
                capability_tags: vec!["legal.contract.review".to_owned()],
                authorized_domains: vec!["legal".to_owned()],
                protocol_bindings: vec![ProtocolBinding {
                    id: format!("{did}#binding-https"),
                    protocol: "https".to_owned(),
                    version: None,
                    transport: Some("http".to_owned()),
                    service_ref: Some(format!("{did}#download")),
                    schema_ref: None,
                    extra: Default::default(),
                }],
                implementation_links: vec![],
                credential_requirements: vec![],
                package_info: None,
                service_policy: None,
                network_scope: None,
                lifecycle_state: Some("active".to_owned()),
                extra: Default::default(),
            }),
        }
    }

    fn sample_submission() -> ResourceRegistrationSubmission {
        let did = "did:oan:SKLG:7HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu";
        let document = sample_document(did);
        let did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256, &document).unwrap();
        ResourceRegistrationSubmission {
            resource_did: did.to_owned(),
            resource_type: ResourceType::Skill,
            did_document: document,
            did_document_hash: format!("sha256:{did_document_hash}"),
            metadata: json!({"name": "Contract Skill", "description": "Review contracts"}),
            package_version: "1".to_owned(),
            package_hash: "sha256:placeholder-package".to_owned(),
            metadata_hash: "sha256:placeholder-metadata".to_owned(),
            hash_algorithm: "sha256".to_owned(),
            registration_credential: json!({"status": "active"}),
            subject_control_proof: SubjectControlProofBundle {
                challenge: DidControlChallenge {
                    challenge_id: "challenge-1".to_owned(),
                    draft_id: "resource-draft-1".to_owned(),
                    subject_did: did.to_owned(),
                    did_document_hash: format!("sha256:{did_document_hash}"),
                    registrar_did: "did:oan:AGRG:6HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned(),
                    purpose: "resource-registration".to_owned(),
                    verification_method: format!("{did}#key-1"),
                    nonce: "nonce-1".to_owned(),
                    issued_at: Utc::now(),
                    expires_at: Utc::now() + Duration::seconds(300),
                },
                proof: oan_core::DataIntegrityProof {
                    proof_type: "DataIntegrityProof".to_owned(),
                    creator: format!("{did}#key-1"),
                    created: Utc::now(),
                    proof_purpose: "assertionMethod".to_owned(),
                    proof_value: "proof".to_owned(),
                    crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                    hash_algorithm: Some("sha256".to_owned()),
                    verification_method: Some(format!("{did}#key-1")),
                },
                verified_at: Some(Utc::now()),
                verified_verification_method: Some(format!("{did}#key-1")),
                proof_hash: Some("proof-hash".to_owned()),
            },
            controller_authorization_proof: None,
        }
    }

    fn attach_external_controller_proof(
        submission: &mut ResourceRegistrationSubmission,
        controller_did: &str,
    ) {
        let controller_key = generate_ed25519_keypair();
        let controller_method = format!("{controller_did}#key-1");
        let verifying_key = VerifyingKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256,
            key: controller_key.verifying_key(),
        };
        let controller_document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: controller_did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: controller_method.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: controller_did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(public_key_multibase(&verifying_key)),
                public_key_jwk: None,
            }],
            authentication: vec![controller_method.clone()],
            assertion_method: vec![controller_method.clone()],
            capability_invocation: vec![controller_method.clone()],
            service: vec![],
            oan_metadata: None,
        };
        let metadata = submission.did_document.oan_metadata.as_mut().unwrap();
        metadata.controller_did = Some(controller_did.to_owned());
        metadata.publisher_did = Some(controller_did.to_owned());
        let did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256, &submission.did_document).unwrap();
        submission.did_document_hash = format!("sha256:{did_document_hash}");
        submission.subject_control_proof.challenge.did_document_hash =
            submission.did_document_hash.clone();
        let challenge = ControllerAuthorizationChallenge {
            challenge_id: "controller-auth-test".to_owned(),
            resource_did: submission.resource_did.clone(),
            controller_did: controller_did.to_owned(),
            publisher_did: Some(controller_did.to_owned()),
            did_document_hash: submission.did_document_hash.clone(),
            metadata_hash: submission.metadata_hash.clone(),
            registrar_did: "did:oan:AGRG:6HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned(),
            purpose: PURPOSE_CONTROLLER_AUTHORIZATION_REGISTRATION.to_owned(),
            verification_method: controller_method.clone(),
            nonce: "controller-auth-nonce".to_owned(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
        };
        let signing_key = SigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256,
            key: controller_key,
        };
        let proof = oan_crypto::build_data_integrity_proof(
            &challenge,
            controller_did.to_owned(),
            controller_method,
            &signing_key,
        )
        .unwrap();
        submission.controller_authorization_proof = Some(ControllerAuthorizationProofBundle {
            challenge,
            controller_did_document: controller_document,
            proof,
        });
    }

    fn controller_query_request(
        state: &AppState,
        resource_did: &str,
        controller_did: &str,
        nonce: &str,
    ) -> RegistrationCredentialQueryRequest {
        let controller_key = generate_ed25519_keypair();
        let controller_method = format!("{controller_did}#key-1");
        let verifying_key = VerifyingKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256,
            key: controller_key.verifying_key(),
        };
        let controller_document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: controller_did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: controller_method.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: controller_did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(public_key_multibase(&verifying_key)),
                public_key_jwk: None,
            }],
            authentication: vec![controller_method.clone()],
            assertion_method: vec![controller_method.clone()],
            capability_invocation: vec![controller_method.clone()],
            service: vec![],
            oan_metadata: None,
        };
        let challenge = RegistrationCredentialQueryChallenge {
            method: "POST".to_owned(),
            path: registration_credential_query_path(resource_did),
            resource_did: resource_did.to_owned(),
            controller_did: controller_did.to_owned(),
            verification_method: controller_method.clone(),
            purpose: PURPOSE_REGISTRATION_CREDENTIAL_QUERY.to_owned(),
            request_timestamp: Utc::now(),
            request_nonce: nonce.to_owned(),
            aud: state.did.clone(),
            protocol_version: PROTOCOL_REGISTRATION_CREDENTIAL_QUERY_V1.to_owned(),
            body_hash: None,
        };
        let signing_key = SigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256,
            key: controller_key,
        };
        let proof = oan_crypto::build_data_integrity_proof(
            &challenge,
            controller_did.to_owned(),
            controller_method,
            &signing_key,
        )
        .unwrap();
        RegistrationCredentialQueryRequest {
            challenge,
            controller_did_document: controller_document,
            proof,
        }
    }

    fn credential_access_marker(
        state: &AppState,
        request: &RegistrationCredentialQueryRequest,
    ) -> Value {
        let method = request
            .controller_did_document
            .verification_method
            .iter()
            .find(|method| method.id == request.challenge.verification_method)
            .unwrap();
        json!({
            "enabled": true,
            "controllerDid": request.challenge.controller_did,
            "verifiedVerificationMethod": request.challenge.verification_method,
            "verifiedControllerMethodHash": hash_json_with_suite(state.signing_key.crypto_suite(), method).unwrap(),
            "verifiedAt": Utc::now().to_rfc3339(),
            "policyVersion": "registration-credential-access-v1"
        })
    }

    fn write_registrar_document(state: &AppState, domains: Vec<String>) {
        let mut document = sample_document(&state.did);
        document.oan_metadata.as_mut().unwrap().authorized_domains = domains;
        state.data.write("did-document.json", &document).unwrap();
    }

    fn set_submission_domains(
        submission: &mut ResourceRegistrationSubmission,
        domains: Vec<String>,
    ) {
        submission
            .did_document
            .oan_metadata
            .as_mut()
            .unwrap()
            .authorized_domains = domains;
    }

    #[test]
    fn build_resource_verify_request_uses_resource_contract() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let request =
            build_resource_verify_and_publish_request(&state, sample_submission()).unwrap();
        assert_eq!(
            request.upstream_auth.path,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH
        );
        assert_eq!(request.upstream_auth.purpose, PURPOSE_VERIFY_AND_PUBLISH);
        assert!(request.submission.resource_did.starts_with("did:oan:"));
    }

    #[tokio::test]
    async fn normalize_tags_accepts_sdk_and_legacy_payload_shapes() {
        let sdk_response = api_normalize_tags(Json(json!({
            "tags": [" Protocol MCP ", "security audit", "protocol-mcp"]
        })))
        .await
        .unwrap();
        assert_eq!(
            sdk_response.0["tags"],
            json!(["protocol-mcp", "security-audit"])
        );
        assert_eq!(
            sdk_response.0["capabilityTags"],
            json!(["protocol-mcp", "security-audit"])
        );

        let legacy_response = api_normalize_tags(Json(json!({
            "capabilityTags": [" Contract Review ", "contract-review"]
        })))
        .await
        .unwrap();
        assert_eq!(legacy_response.0["tags"], json!(["contract-review"]));
        assert_eq!(
            legacy_response.0["capabilityTags"],
            json!(["contract-review"])
        );
    }

    #[tokio::test]
    async fn registrar_stats_report_payload_matches_stats_counts() {
        async fn handler(Json(request): Json<Value>) -> Json<Value> {
            assert_eq!(request["nodeId"], "registrar-test");
            assert_eq!(request["role"], "registrar");
            assert_eq!(request["status"], "online");
            assert_eq!(request["resourceTotals"]["registeredResources"], 2);
            assert_eq!(request["resourcesByType"]["skill"], 1);
            assert_eq!(request["resourcesByType"]["mcpServer"], 1);
            assert_eq!(request["registrationWindows"]["today"], 1);
            Json(json!({ "status": "ok" }))
        }
        let app = Router::new().route("/api/internal/node-stats/report", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        state.config.stats_report = StatsReportConfig {
            enabled: true,
            node_id: Some("registrar-test".to_owned()),
            endpoint: Some(format!("http://{addr}/api/internal/node-stats/report")),
            token: Some("test-token".to_owned()),
            interval_seconds: 60,
        };
        write_resource_record(
            &state,
            &json!({
                "resourceDid": "did:oan:SKLG:today",
                "resourceType": "skill",
                "submittedAt": Utc::now().to_rfc3339()
            }),
        )
        .await
        .unwrap();
        write_resource_record(
            &state,
            &json!({
                "resourceDid": "did:oan:MCPS:old",
                "resourceType": "mcp_server",
                "submittedAt": (Utc::now() - Duration::days(40)).to_rfc3339()
            }),
        )
        .await
        .unwrap();

        report_registrar_stats_once(&state).await.unwrap();
    }

    #[test]
    fn public_resource_record_projection_redacts_sensitive_fields() {
        let record = json!({
            "resourceDid": "did:oan:SKLG:redaction",
            "resourceType": "skill",
            "packageVersion": "1",
            "didDocumentHash": "sha256:did",
            "metadataHash": "sha256:metadata",
            "packageHash": "sha256:package",
            "authorizedDomains": ["legal"],
            "submittedAt": "2026-09-18T00:00:00Z",
            "registrationCredential": {
                "proof": {
                    "proofValue": "secret-proof"
                }
            },
            "rootResponse": {
                "status": "resource-verified-and-queued",
                "package": {
                    "internal": true
                }
            },
            "registrationCredentialAccess": {
                "enabled": true,
                "controllerDid": "did:oan:AGUS:controller",
                "verifiedAuthorityBindingHash": "sha256:binding"
            },
            "databasePath": "/internal/registrar.db"
        });

        let projection = public_resource_record_projection(&record);

        assert_eq!(projection["resourceDid"], "did:oan:SKLG:redaction");
        assert_eq!(projection["resourceType"], "skill");
        assert_eq!(projection["rootStatus"], "resource-verified-and-queued");
        assert!(projection.get("registrationCredential").is_none());
        assert!(projection.get("rootResponse").is_none());
        assert!(projection.get("registrationCredentialAccess").is_none());
        assert!(projection.get("verifiedAuthorityBindingHash").is_none());
        assert!(projection.get("databasePath").is_none());
    }

    #[tokio::test]
    async fn resource_get_handlers_return_redacted_public_projection() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let resource_did = "did:oan:SKLG:redacted-handler";
        write_resource_record(
            &state,
            &json!({
                "resourceDid": resource_did,
                "resourceType": "skill",
                "packageVersion": "1",
                "didDocumentHash": "sha256:did",
                "metadataHash": "sha256:metadata",
                "packageHash": "sha256:package",
                "authorizedDomains": ["legal"],
                "submittedAt": "2026-09-18T00:00:00Z",
                "registrationCredential": {
                    "type": ["VerifiableCredential", "OANResourceRegistrationCredential"],
                    "proof": {
                        "proofValue": "secret-proof"
                    }
                },
                "rootResponse": {
                    "status": "resource-verified-and-queued",
                    "privateRootDetail": "internal"
                },
                "registrationCredentialAccess": {
                    "enabled": true,
                    "controllerDid": "did:oan:AGUS:controller",
                    "verifiedAuthorityBindingHash": "sha256:binding"
                }
            }),
        )
        .await
        .unwrap();

        let detail = api_resource_detail(State(state.clone()), AxumPath(resource_did.to_owned()))
            .await
            .unwrap()
            .0;
        assert_eq!(detail["resourceDid"], resource_did);
        assert_eq!(detail["record"]["resourceDid"], resource_did);
        assert_eq!(
            detail["record"]["rootStatus"],
            "resource-verified-and-queued"
        );
        assert!(detail["record"].get("registrationCredential").is_none());
        assert!(detail["record"].get("rootResponse").is_none());
        assert!(detail["record"]
            .get("registrationCredentialAccess")
            .is_none());

        let list = api_resources(State(state.clone()), Query(ResourceListQuery::default()))
            .await
            .unwrap()
            .0;
        assert_eq!(list["count"], 1);
        assert_eq!(list["items"][0]["resourceDid"], resource_did);
        assert!(list["items"][0].get("registrationCredential").is_none());
        assert!(list["items"][0].get("rootResponse").is_none());
        assert!(list["items"][0]
            .get("registrationCredentialAccess")
            .is_none());

        let stored = read_resource_record(&state, resource_did)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored["registrationCredential"]["proof"]["proofValue"],
            "secret-proof"
        );
    }

    #[tokio::test]
    async fn resource_list_uses_after_did_pagination() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        for did in [
            "did:oan:SKLG:pagination-a",
            "did:oan:SKLG:pagination-b",
            "did:oan:SKLG:pagination-c",
        ] {
            state
                .data
                .write(
                    format!("resource-records/{}", did_to_file_name(did)),
                    &json!({
                        "resourceDid": did,
                        "resourceType": "skill",
                        "packageVersion": "1",
                        "didDocumentHash": "sha256:did",
                        "metadataHash": "sha256:metadata",
                        "packageHash": "sha256:package",
                        "authorizedDomains": ["technology"],
                        "submittedAt": "2026-09-18T00:00:00Z"
                    }),
                )
                .unwrap();
        }

        let first = api_resources(
            State(state.clone()),
            Query(ResourceListQuery {
                after_did: None,
                limit: Some(2),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(first["count"], 2);
        assert_eq!(
            first["items"][0]["resourceDid"],
            "did:oan:SKLG:pagination-a"
        );
        assert_eq!(
            first["items"][1]["resourceDid"],
            "did:oan:SKLG:pagination-b"
        );
        assert_eq!(first["nextDid"], "did:oan:SKLG:pagination-b");
        assert_eq!(first["hasMore"], true);

        let second = api_resources(
            State(state),
            Query(ResourceListQuery {
                after_did: Some("did:oan:SKLG:pagination-b".to_owned()),
                limit: Some(2),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(second["count"], 1);
        assert_eq!(
            second["items"][0]["resourceDid"],
            "did:oan:SKLG:pagination-c"
        );
        assert_eq!(second["hasMore"], false);
        assert!(second["nextDid"].is_null());
    }

    #[tokio::test]
    async fn sqlite_resource_list_stops_before_an_oversized_extra_row() {
        let dir = tempdir().unwrap();
        let sqlite = SqliteJsonStore::connect(&format!(
            "sqlite:{}",
            dir.path().join("registrar.db").display()
        ))
        .await
        .unwrap();
        let mut state = app_state(dir.path());
        state.sqlite = Some(sqlite);

        for (index, did) in ["did:oan:SKLG:stream-a", "did:oan:SKLG:stream-b"]
            .into_iter()
            .enumerate()
        {
            state
                .sqlite
                .as_ref()
                .unwrap()
                .upsert_json(
                    "registrar.resource_records",
                    did,
                    &json!({
                        "resourceDid": did,
                        "resourceType": "skill",
                        "packageVersion": "1",
                        "didDocumentHash": format!("sha256:did-{index}"),
                        "metadataHash": format!("sha256:metadata-{index}"),
                        "packageHash": format!("sha256:package-{index}"),
                        "authorizedDomains": ["technology"],
                        "submittedAt": "2026-09-18T00:00:00Z"
                    }),
                )
                .await
                .unwrap();
        }
        state
            .sqlite
            .as_ref()
            .unwrap()
            .upsert_json(
                "registrar.resource_records",
                "did:oan:SKLG:stream-c",
                &json!({
                    "resourceDid": "did:oan:SKLG:stream-c",
                    "resourceType": "skill",
                    "diagnosticPayload": "x".repeat(REGISTRAR_MAX_RECORD_BYTES)
                }),
            )
            .await
            .unwrap();

        let page = api_resources(
            State(state),
            Query(ResourceListQuery {
                after_did: None,
                limit: Some(2),
            }),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(page["count"], 2);
        assert_eq!(page["hasMore"], true);
        assert_eq!(page["nextDid"], "did:oan:SKLG:stream-b");
    }

    #[tokio::test]
    async fn resource_list_rejects_invalid_page_limits() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());

        for limit in [Some(0), Some(REGISTRAR_MAX_PAGE_SIZE + 1)] {
            let err = api_resources(
                State(state.clone()),
                Query(ResourceListQuery {
                    after_did: None,
                    limit,
                }),
            )
            .await
            .unwrap_err();

            assert_eq!(err.status, StatusCode::BAD_REQUEST);
            assert_eq!(err.message, "invalid_resource_page_limit");
        }
    }

    #[tokio::test]
    async fn resource_list_rejects_oversized_records_before_projection() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let resource_did = "did:oan:SKLG:oversized-record";
        state
            .data
            .write(
                format!("resource-records/{}", did_to_file_name(resource_did)),
                &json!({
                    "resourceDid": resource_did,
                    "resourceType": "skill",
                    "packageVersion": "1",
                    "didDocumentHash": "sha256:did",
                    "metadataHash": "sha256:metadata",
                    "packageHash": "sha256:package",
                    "authorizedDomains": ["technology"],
                    "submittedAt": "2026-09-18T00:00:00Z",
                    "diagnosticPayload": "x".repeat(REGISTRAR_MAX_RECORD_BYTES)
                }),
            )
            .unwrap();

        let err = api_resources(State(state), Query(ResourceListQuery::default()))
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.message, "resource_record_too_large");
    }

    #[tokio::test]
    async fn resource_detail_returns_not_found_for_missing_record() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());

        let err = api_resource_detail(
            State(state),
            AxumPath("did:oan:SKLG:missing-resource".to_owned()),
        )
        .await
        .unwrap_err();

        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(err.message, "resource_not_found");
    }

    #[tokio::test]
    async fn registration_credential_query_returns_vc_for_authorized_new_record() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let resource_did = "did:oan:SKLG:credential-query";
        let controller_did = "did:oan:AGUS:CredentialQueryController";
        let request =
            controller_query_request(&state, resource_did, controller_did, "query-nonce-1");
        write_resource_record(
            &state,
            &json!({
                "resourceDid": resource_did,
                "resourceType": "skill",
                "registrationCredential": {
                    "id": "urn:credential:registration",
                    "proof": {
                        "proofValue": "secret-proof"
                    }
                },
                "registrationCredentialAccess": credential_access_marker(&state, &request)
            }),
        )
        .await
        .unwrap();

        let response = api_registration_credential(
            State(state),
            AxumPath(resource_did.to_owned()),
            Json(request),
        )
        .await
        .unwrap();

        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[tokio::test]
    async fn registration_credential_query_rejects_record_without_access_marker() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let resource_did = "did:oan:SKLG:no-access-marker-query";
        let controller_did = "did:oan:AGUS:NoAccessMarkerController";
        write_resource_record(
            &state,
            &json!({
                "resourceDid": resource_did,
                "resourceType": "skill",
                "registrationCredential": {
                    "proof": {
                        "proofValue": "secret-proof"
                    }
                }
            }),
        )
        .await
        .unwrap();
        let request = controller_query_request(
            &state,
            resource_did,
            controller_did,
            "query-nonce-no-marker",
        );

        let err = api_registration_credential(
            State(state),
            AxumPath(resource_did.to_owned()),
            Json(request),
        )
        .await
        .unwrap_err();

        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.message, "registration_credential_access_denied");
    }

    #[tokio::test]
    async fn registration_credential_query_rejects_controller_mismatch_and_replay() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let resource_did = "did:oan:SKLG:query-replay";
        let controller_did = "did:oan:AGUS:ExpectedController";
        let request =
            controller_query_request(&state, resource_did, controller_did, "query-nonce-replay");
        write_resource_record(
            &state,
            &json!({
                "resourceDid": resource_did,
                "resourceType": "skill",
                "registrationCredential": {
                    "proof": {
                        "proofValue": "secret-proof"
                    }
                },
                "registrationCredentialAccess": credential_access_marker(&state, &request)
            }),
        )
        .await
        .unwrap();

        let wrong_controller_request = controller_query_request(
            &state,
            resource_did,
            "did:oan:AGUS:WrongController",
            "query-nonce-wrong-controller",
        );
        let err = api_registration_credential(
            State(state.clone()),
            AxumPath(resource_did.to_owned()),
            Json(wrong_controller_request),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        api_registration_credential(
            State(state.clone()),
            AxumPath(resource_did.to_owned()),
            Json(request.clone()),
        )
        .await
        .unwrap();
        let err = api_registration_credential(
            State(state),
            AxumPath(resource_did.to_owned()),
            Json(request),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.message, "registration_credential_query_replay");
    }

    #[tokio::test]
    async fn registration_credential_query_rejects_tampered_challenge_binding() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let resource_did = "did:oan:SKLG:query-tamper";
        let controller_did = "did:oan:AGUS:TamperController";
        let mut request =
            controller_query_request(&state, resource_did, controller_did, "query-nonce-tamper");
        write_resource_record(
            &state,
            &json!({
                "resourceDid": resource_did,
                "resourceType": "skill",
                "registrationCredential": {
                    "proof": {
                        "proofValue": "secret-proof"
                    }
                },
                "registrationCredentialAccess": credential_access_marker(&state, &request)
            }),
        )
        .await
        .unwrap();
        request.challenge.path = "/resources/wrong/registration-credential".to_owned();

        let err = api_registration_credential(
            State(state),
            AxumPath(resource_did.to_owned()),
            Json(request),
        )
        .await
        .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.message, "invalid_registration_credential_query");
    }

    #[tokio::test]
    async fn registration_credential_query_rejects_expired_challenge() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let resource_did = "did:oan:SKLG:query-expired";
        let controller_did = "did:oan:AGUS:ExpiredController";
        let mut request =
            controller_query_request(&state, resource_did, controller_did, "query-nonce-expired");
        write_resource_record(
            &state,
            &json!({
                "resourceDid": resource_did,
                "resourceType": "skill",
                "registrationCredential": {
                    "proof": {
                        "proofValue": "secret-proof"
                    }
                },
                "registrationCredentialAccess": credential_access_marker(&state, &request)
            }),
        )
        .await
        .unwrap();
        request.challenge.request_timestamp = Utc::now()
            - Duration::seconds(REGISTRATION_CREDENTIAL_QUERY_MAX_CLOCK_SKEW_SECONDS + 1);

        let err = api_registration_credential(
            State(state),
            AxumPath(resource_did.to_owned()),
            Json(request),
        )
        .await
        .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.message, "registration_credential_query_expired");
    }

    #[tokio::test]
    async fn registration_credential_query_rejects_controller_method_hash_mismatch() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let resource_did = "did:oan:SKLG:query-method-hash-mismatch";
        let controller_did = "did:oan:AGUS:MethodHashMismatchController";
        let request = controller_query_request(
            &state,
            resource_did,
            controller_did,
            "query-nonce-method-hash-mismatch",
        );
        let mut access_marker = credential_access_marker(&state, &request);
        access_marker["verifiedControllerMethodHash"] = json!("sha256:mismatch");
        write_resource_record(
            &state,
            &json!({
                "resourceDid": resource_did,
                "resourceType": "skill",
                "registrationCredential": {
                    "proof": {
                        "proofValue": "secret-proof"
                    }
                },
                "registrationCredentialAccess": access_marker
            }),
        )
        .await
        .unwrap();

        let err = api_registration_credential(
            State(state),
            AxumPath(resource_did.to_owned()),
            Json(request),
        )
        .await
        .unwrap_err();

        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.message, "registration_credential_access_denied");
    }

    #[tokio::test]
    async fn register_resource_posts_to_root_and_records_resource() {
        async fn handler(Json(request): Json<ResourceVerifyAndPublishRequest>) -> Json<Value> {
            assert!(request.submission.registration_credential.is_null());
            Json(json!({
                "status": "resource-verified-and-queued",
                "resourceDid": request.submission.resource_did
            }))
        }
        let app = Router::new().route(PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH, post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        write_registrar_document(&state, vec!["legal".to_owned()]);
        state.config.upstream.root_endpoint = format!("http://{addr}");
        let submission = sample_submission();
        let response = register_resource(State(state.clone()), Json(submission.clone()))
            .await
            .unwrap();
        assert_eq!(response.0["status"], "submitted");
        assert_eq!(response.0["resourceDid"], submission.resource_did);
        assert_eq!(
            response.0["registrationCredential"]["issuer"],
            state.did.clone()
        );
        assert_eq!(
            response.0["registrationCredential"]["credentialSubject"]["resourceDid"],
            submission.resource_did
        );
        assert_eq!(
            response.0["registrationCredential"]["credentialSubject"]["authorizedDomains"],
            json!(["legal"])
        );
        assert!(response.0["registrationCredential"]["proof"]["proofValue"].is_string());
        let stored = read_resource_record(&state, &submission.resource_did)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored["resourceDid"], submission.resource_did);
        assert_eq!(stored["authorizedDomains"], json!(["legal"]));
        assert!(stored["registrationCredential"]["proof"]["proofValue"].is_string());
        assert!(stored.get("registrationCredentialAccess").is_none());
    }

    #[tokio::test]
    async fn register_resource_rejects_external_controller_without_proof() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        write_registrar_document(&state, vec!["legal".to_owned()]);
        state.config.upstream.root_endpoint = "http://127.0.0.1:1".to_owned();
        let mut submission = sample_submission();
        submission
            .did_document
            .oan_metadata
            .as_mut()
            .unwrap()
            .controller_did = Some("did:oan:AGUS:ControllerMissingProof".to_owned());

        let err = register_resource(State(state), Json(submission))
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.message, "controller_authorization_proof_required");
    }

    #[tokio::test]
    async fn register_resource_accepts_external_controller_proof_and_forwards_it() {
        async fn handler(Json(request): Json<ResourceVerifyAndPublishRequest>) -> Json<Value> {
            assert!(request.submission.controller_authorization_proof.is_some());
            Json(json!({
                "status": "resource-verified-and-queued",
                "resourceDid": request.submission.resource_did
            }))
        }
        let app = Router::new().route(PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH, post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        write_registrar_document(&state, vec!["legal".to_owned()]);
        state.config.upstream.root_endpoint = format!("http://{addr}");
        let mut submission = sample_submission();
        attach_external_controller_proof(&mut submission, "did:oan:AGUS:9ControllerProofAccepted");

        let response = register_resource(State(state.clone()), Json(submission.clone()))
            .await
            .unwrap();

        assert_eq!(response.0["status"], "submitted");
        let stored = read_resource_record(&state, &submission.resource_did)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored["registrationCredentialAccess"]["enabled"],
            json!(true)
        );
        assert_eq!(
            stored["registrationCredentialAccess"]["controllerDid"],
            "did:oan:AGUS:9ControllerProofAccepted"
        );
        assert!(stored["registrationCredentialAccess"]["verifiedVerificationMethod"].is_string());
        assert!(stored["registrationCredentialAccess"]["verifiedControllerMethodHash"].is_string());
        assert!(stored["registrationCredentialAccess"]["verifiedAuthorityBindingHash"].is_string());
        let public_detail =
            api_resource_detail(State(state), AxumPath(submission.resource_did.clone()))
                .await
                .unwrap()
                .0;
        assert!(public_detail["record"]
            .get("registrationCredentialAccess")
            .is_none());
    }

    #[tokio::test]
    async fn register_resource_rejects_replayed_external_controller_proof() {
        async fn handler(Json(request): Json<ResourceVerifyAndPublishRequest>) -> Json<Value> {
            Json(json!({
                "status": "resource-verified-and-queued",
                "resourceDid": request.submission.resource_did
            }))
        }
        let app = Router::new().route(PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH, post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        write_registrar_document(&state, vec!["legal".to_owned()]);
        state.config.upstream.root_endpoint = format!("http://{addr}");
        let mut submission = sample_submission();
        attach_external_controller_proof(&mut submission, "did:oan:AGUS:9ControllerReplay");

        let _ = register_resource(State(state.clone()), Json(submission.clone()))
            .await
            .unwrap();
        let err = register_resource(State(state), Json(submission))
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.message, "controller_authorization_nonce_replayed");
    }

    #[tokio::test]
    async fn register_resource_rejects_tampered_external_controller_proof() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        write_registrar_document(&state, vec!["legal".to_owned()]);
        state.config.upstream.root_endpoint = "http://127.0.0.1:1".to_owned();
        let mut submission = sample_submission();
        attach_external_controller_proof(&mut submission, "did:oan:AGUS:9ControllerProofTampered");
        submission
            .controller_authorization_proof
            .as_mut()
            .unwrap()
            .proof
            .proof_value = "tampered".to_owned();

        let err = register_resource(State(state), Json(submission))
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.message, "controller_authorization_proof_invalid");
    }

    #[tokio::test]
    async fn register_resource_rejects_domains_outside_registrar_grant_before_root_call() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        write_registrar_document(&state, vec!["legal".to_owned()]);
        state.config.upstream.root_endpoint = "http://127.0.0.1:1".to_owned();
        let mut submission = sample_submission();
        set_submission_domains(&mut submission, vec!["finance".to_owned()]);

        let err = register_resource(State(state), Json(submission))
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.message, "unauthorized_domains");
    }

    #[tokio::test]
    async fn register_resource_rejects_missing_resource_domains_before_root_call() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        write_registrar_document(&state, vec!["*".to_owned()]);
        state.config.upstream.root_endpoint = "http://127.0.0.1:1".to_owned();
        let mut submission = sample_submission();
        set_submission_domains(&mut submission, vec![]);

        let err = register_resource(State(state), Json(submission))
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.message, "resource_domains_required");
    }

    #[tokio::test]
    async fn register_resource_rejects_metadata_authorized_domains_mismatch() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        write_registrar_document(&state, vec!["*".to_owned()]);
        state.config.upstream.root_endpoint = "http://127.0.0.1:1".to_owned();
        let mut submission = sample_submission();
        submission.metadata = json!({
            "name": "Contract Skill",
            "description": "Review contracts",
            "authorizedDomains": ["finance"]
        });

        let err = register_resource(State(state), Json(submission))
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.message, "authorized_domains_mismatch");
    }

    #[tokio::test]
    async fn wildcard_registrar_accepts_concrete_resource_domains() {
        async fn handler(Json(request): Json<ResourceVerifyAndPublishRequest>) -> Json<Value> {
            Json(json!({
                "status": "resource-verified-and-queued",
                "resourceDid": request.submission.resource_did
            }))
        }
        let app = Router::new().route(PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH, post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        write_registrar_document(&state, vec!["*".to_owned()]);
        state.config.upstream.root_endpoint = format!("http://{addr}");
        let mut submission = sample_submission();
        set_submission_domains(&mut submission, vec!["finance.payments".to_owned()]);

        let response = register_resource(State(state), Json(submission))
            .await
            .unwrap();

        assert_eq!(
            response.0["registrationCredential"]["credentialSubject"]["authorizedDomains"],
            json!(["finance.payments"])
        );
    }

    #[tokio::test]
    async fn register_resource_rejects_did_ans_resource() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let mut submission = sample_submission();
        submission.resource_did = "did:ans:SKLG:7HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned();
        submission.did_document.id = submission.resource_did.clone();
        let err = register_resource(State(state), Json(submission))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }
}
