// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use anyhow::{anyhow, Result};
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Datelike, Utc};
use oan_core::{CapabilityTagTree, CryptoSuite, DidDocument};
use oan_credentials::sign_credential;
use oan_crypto::{hash_json_with_suite, signing_key_from_bytes, SigningKey};
use oan_protocol::{
    HealthResponse, ResourceRegistrationSubmission, ResourceVerifyAndPublishRequest,
    OAN_RESOURCE_PROTOCOL_VERSION, PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
    PURPOSE_CONTROLLER_AUTHORIZATION_REGISTRATION, PURPOSE_VERIFY_AND_PUBLISH,
};
use oan_semantic_recommender::{
    normalize_capability_tags, RegistrationSuggestionContext, RegistrationSuggestionInput,
    SemanticRecommender,
};
use oan_service_security::{
    create_signed_request_envelope, request_id, request_nonce,
    verify_controller_authorization_proof, ControllerAuthorizationVerificationContext,
    SignedRequestEnvelopeInput,
};
use oan_storage::{
    did_to_file_name, DatabaseBackend, DatabaseConfig, JsonStore, PostgresJsonStore,
    SqliteJsonStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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
    #[serde(default)]
    database_url: Option<String>,
}

fn default_records_dir() -> PathBuf {
    PathBuf::from("../../data/registrar/resource-records")
}

fn default_keys_dir() -> PathBuf {
    PathBuf::from("../../data/registrar/keys")
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
    let record = json!({
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
    let expected_publisher_did = metadata
        .publisher_did
        .as_deref()
        .filter(|publisher_did| *publisher_did == controller_did);
    verify_controller_authorization_proof(
        bundle,
        &ControllerAuthorizationVerificationContext {
            expected_resource_did: &submission.resource_did,
            expected_controller_did: controller_did,
            expected_publisher_did,
            expected_did_document_hash: &submission.did_document_hash,
            expected_metadata_hash: &submission.metadata_hash,
            expected_registrar_did: &state.did,
            expected_purpose: PURPOSE_CONTROLLER_AUTHORIZATION_REGISTRATION,
            now: Utc::now(),
        },
    )
    .map(Some)
    .map_err(|err| {
        let message = err.to_string();
        eprintln!(
            "controller authorization proof rejected for resource {} controlled by {}: {}",
            submission.resource_did, controller_did, message
        );
        message
    })
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

async fn api_status(State(state): State<AppState>) -> ApiResult<Value> {
    let records = read_resource_records(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "registrarDid": state.did,
        "rootEndpoint": state.config.upstream.root_endpoint,
        "resourceRecordCount": records.len(),
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
    let records = read_resource_records(&state).await?;
    let generated_at = Utc::now();
    let today = generated_at.date_naive();
    let week_start = today - chrono::Duration::days(today.weekday().num_days_from_monday() as i64);
    let month_start = today.with_day(1).unwrap_or(today);
    let mut counts = json!({
        "agentServiceCount": 0,
        "skillCount": 0,
        "mcpServerCount": 0,
        "toolApiCount": 0,
        "todayRegistrationCount": 0,
        "weekRegistrationCount": 0,
        "monthRegistrationCount": 0,
        "resourceRecordCount": records.len(),
    });
    for record in &records {
        if let Some(resource_type) = record.get("resourceType").and_then(Value::as_str) {
            let key = match resource_type {
                "agent_service" => "agentServiceCount",
                "skill" => "skillCount",
                "mcp_server" => "mcpServerCount",
                "tool_api" => "toolApiCount",
                _ => "",
            };
            if !key.is_empty() {
                counts[key] = json!(counts[key].as_i64().unwrap_or(0) + 1);
            }
        }
        let Some(submitted_at) = record.get("submittedAt").and_then(Value::as_str) else {
            continue;
        };
        let Ok(submitted_at) = DateTime::parse_from_rfc3339(submitted_at) else {
            continue;
        };
        let submitted_day = submitted_at.with_timezone(&Utc).date_naive();
        if submitted_day == today {
            counts["todayRegistrationCount"] =
                json!(counts["todayRegistrationCount"].as_i64().unwrap_or(0) + 1);
        }
        if submitted_day >= week_start {
            counts["weekRegistrationCount"] =
                json!(counts["weekRegistrationCount"].as_i64().unwrap_or(0) + 1);
        }
        if submitted_day >= month_start {
            counts["monthRegistrationCount"] =
                json!(counts["monthRegistrationCount"].as_i64().unwrap_or(0) + 1);
        }
    }
    Ok(json!({
        "registrarDid": state.did,
        "generatedAt": generated_at.to_rfc3339(),
        "windowTimezone": "UTC",
        "resourceRecordCount": counts["resourceRecordCount"],
        "agentServiceCount": counts["agentServiceCount"],
        "skillCount": counts["skillCount"],
        "mcpServerCount": counts["mcpServerCount"],
        "toolApiCount": counts["toolApiCount"],
        "todayRegistrationCount": counts["todayRegistrationCount"],
        "weekRegistrationCount": counts["weekRegistrationCount"],
        "monthRegistrationCount": counts["monthRegistrationCount"],
    }))
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

async fn api_resources(State(state): State<AppState>) -> ApiResult<Value> {
    let records = read_resource_records(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": records, "count": records.len() })))
}

async fn api_resource_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let record = read_resource_record(&state, &did)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "resourceDid": did, "record": record })))
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
        SubjectControlProofBundle,
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

        let response = register_resource(State(state), Json(submission))
            .await
            .unwrap();

        assert_eq!(response.0["status"], "submitted");
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
