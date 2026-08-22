//! Supervised bounded HTTPS transport for team-memory replication.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use futures::StreamExt as _;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperConnectionBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    ServerConfig, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use super::replication::{
    PullRequest, PullResponse, PushRequest, PushResponse, TeamReplica, TeamReplicationError,
    TeamReplicationFailureClass, TeamSyncReport, MAX_TEAM_REPLICATION_CERTIFICATE_BYTES,
    MAX_TEAM_REPLICATION_MESSAGE_BYTES, TEAM_REPLICATION_SCHEMA_VERSION,
};
use crate::runtime::ContentDigest;

const MAX_SERVICE_CONNECTIONS: usize = 32;
const MAX_CONCURRENT_SERVICE_OPERATIONS: usize = 8;
const MAX_WORKER_COMMANDS: usize = 8;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_LIFETIME: Duration = Duration::from_secs(30);
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const WORKER_IDLE_INTERVAL: Duration = Duration::from_secs(30);
const EXPLICIT_SYNC_TIMEOUT: Duration = Duration::from_secs(24);
const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_TEAM_REPLICATION_PRIVATE_KEY_BYTES: usize = 128 * 1_024;

/// `WebPKI` verification plus an exact end-entity certificate match. A pinned
/// certificate may itself be a trust anchor, so relying on a single-entry root
/// store alone would still accept a different leaf signed by that certificate.
/// The equality check runs during the TLS handshake, before any HTTP request
/// body can be transmitted.
#[derive(Debug)]
struct ExactPinnedServerVerifier {
    pinned_end_entity: CertificateDer<'static>,
    webpki: Arc<dyn ServerCertVerifier>,
}

impl ServerCertVerifier for ExactPinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if end_entity.as_ref() != self.pinned_end_entity.as_ref() {
            return Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        self.webpki
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProtocolFailureCode {
    InvalidRequest,
    Unauthorized,
    CapacityExceeded,
    Conflict,
    Corrupt,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolFailure {
    schema_version: u32,
    code: ProtocolFailureCode,
    retryable: bool,
}

impl ProtocolFailure {
    const fn new(code: ProtocolFailureCode, retryable: bool) -> Self {
        Self {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
            code,
            retryable,
        }
    }
}

struct ServiceState {
    replica: Arc<TeamReplica>,
    operations: Arc<Semaphore>,
}

/// A bound TLS listener whose certificate and private key were validated
/// before any service descriptor is published.
pub struct TeamMemoryTlsServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl fmt::Debug for TeamMemoryTlsServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TeamMemoryTlsServer")
            .field("local_addr", &self.listener.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl TeamMemoryTlsServer {
    /// Bind a socket and validate the exact TLS identity before declaring the
    /// replication service ready.
    ///
    /// # Errors
    ///
    /// Returns a typed socket, certificate, private-key, or capacity error when
    /// the listener cannot be prepared safely.
    pub async fn bind(
        listen: SocketAddr,
        certificate_der: Vec<u8>,
        private_key_der: Zeroizing<Vec<u8>>,
    ) -> Result<Self, TeamReplicationError> {
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|error| TeamReplicationError::Store(anyhow::Error::new(error)))?;
        Self::from_listener(listener, certificate_der, &private_key_der)
    }

    fn from_listener(
        listener: TcpListener,
        certificate_der: Vec<u8>,
        private_key_der: &Zeroizing<Vec<u8>>,
    ) -> Result<Self, TeamReplicationError> {
        let acceptor = tls_acceptor(certificate_der, private_key_der)?;
        Ok(Self { listener, acceptor })
    }

    /// Return the socket address reserved by this prepared server.
    ///
    /// # Errors
    /// Returns an I/O-backed typed error if the bound socket address cannot be
    /// inspected.
    pub fn local_addr(&self) -> Result<SocketAddr, TeamReplicationError> {
        self.listener
            .local_addr()
            .map_err(|error| TeamReplicationError::Store(anyhow::Error::new(error)))
    }

    /// Serve the authenticated replica protocol until `shutdown` resolves.
    ///
    /// # Errors
    ///
    /// Returns a typed listener or transport error if the prepared service
    /// cannot accept or supervise connections.
    pub async fn serve<F>(
        self,
        replica: Arc<TeamReplica>,
        shutdown: F,
    ) -> Result<(), TeamReplicationError>
    where
        F: Future<Output = ()> + Send,
    {
        serve_prepared_team_memory_tls(replica, self.listener, self.acceptor, shutdown).await
    }
}

/// Serve the authenticated replica protocol over TLS until `shutdown`
/// resolves.
///
/// The supplied key must be PKCS#8 DER. All accepted connections, request
/// bodies, operation concurrency, and shutdown work are bounded.
///
/// # Errors
///
/// Returns a typed bind, TLS identity, transport, or capacity error if the
/// service cannot be prepared or run safely.
pub async fn serve_team_memory_tls<F>(
    replica: Arc<TeamReplica>,
    listen: SocketAddr,
    certificate_der: Vec<u8>,
    private_key_der: Zeroizing<Vec<u8>>,
    shutdown: F,
) -> Result<(), TeamReplicationError>
where
    F: Future<Output = ()> + Send,
{
    TeamMemoryTlsServer::bind(listen, certificate_der, private_key_der)
        .await?
        .serve(replica, shutdown)
        .await
}

#[cfg(test)]
async fn serve_team_memory_tls_on_listener<F>(
    replica: Arc<TeamReplica>,
    listener: TcpListener,
    certificate_der: Vec<u8>,
    private_key_der: Zeroizing<Vec<u8>>,
    shutdown: F,
) -> Result<(), TeamReplicationError>
where
    F: Future<Output = ()> + Send,
{
    TeamMemoryTlsServer::from_listener(listener, certificate_der, &private_key_der)?
        .serve(replica, shutdown)
        .await
}

fn tls_acceptor(
    certificate_der: Vec<u8>,
    private_key_der: &Zeroizing<Vec<u8>>,
) -> Result<TlsAcceptor, TeamReplicationError> {
    if certificate_der.is_empty()
        || certificate_der.len() > MAX_TEAM_REPLICATION_CERTIFICATE_BYTES
        || private_key_der.is_empty()
        || private_key_der.len() > MAX_TEAM_REPLICATION_PRIVATE_KEY_BYTES
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    let certificate = CertificateDer::from(certificate_der);
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der.as_slice()));
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key)
        .map_err(|error| TeamReplicationError::Store(anyhow::Error::new(error)))?;
    let certified_key = CertifiedKey::new(vec![certificate], signing_key);
    certified_key
        .keys_match()
        .map_err(|error| TeamReplicationError::Store(anyhow::Error::new(error)))?;
    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)));
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

async fn serve_prepared_team_memory_tls<F>(
    replica: Arc<TeamReplica>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    shutdown: F,
) -> Result<(), TeamReplicationError>
where
    F: Future<Output = ()> + Send,
{
    let application = Router::new()
        .route("/v1/push", post(push_handler))
        .route("/v1/pull", post(pull_handler))
        .layer(DefaultBodyLimit::max(MAX_TEAM_REPLICATION_MESSAGE_BYTES))
        .with_state(Arc::new(ServiceState {
            replica,
            operations: Arc::new(Semaphore::new(MAX_CONCURRENT_SERVICE_OPERATIONS)),
        }));
    let connections = Arc::new(Semaphore::new(MAX_SERVICE_CONNECTIONS));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => {
                let (socket, _) = accepted
                    .map_err(|error| TeamReplicationError::Store(anyhow::Error::new(error)))?;
                let Ok(connection_permit) = Arc::clone(&connections).try_acquire_owned() else {
                    drop(socket);
                    continue;
                };
                let acceptor = acceptor.clone();
                let service = application.clone();
                tasks.spawn(async move {
                    let _connection_permit = connection_permit;
                    let Ok(Ok(tls)) = tokio::time::timeout(
                        TLS_HANDSHAKE_TIMEOUT,
                        acceptor.accept(socket),
                    )
                    .await
                    else {
                        return;
                    };
                    let service = TowerToHyperService::new(service);
                    let builder = HyperConnectionBuilder::new(TokioExecutor::new());
                    let result = tokio::time::timeout(
                        CONNECTION_LIFETIME,
                        builder.serve_connection(TokioIo::new(tls), service),
                    )
                    .await;
                    if matches!(result, Ok(Err(_))) {
                        tracing::debug!("team-memory TLS connection ended with a protocol error");
                    }
                });
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if matches!(completed, Some(Err(_))) {
                    tracing::warn!("team-memory TLS connection task panicked or was cancelled");
                }
            }
        }
    }

    let drained = tokio::time::timeout(WORKER_SHUTDOWN_TIMEOUT, async {
        while let Some(result) = tasks.join_next().await {
            if result.is_err() {
                tracing::warn!("team-memory TLS connection task failed during shutdown");
            }
        }
    })
    .await;
    if drained.is_err() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(())
}

async fn push_handler(
    State(state): State<Arc<ServiceState>>,
    request: Result<Json<PushRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(request)) = request else {
        return failure_response(&TeamReplicationError::InvalidProtocol);
    };
    let Ok(operation_permit) = Arc::clone(&state.operations).try_acquire_owned() else {
        return failure_response(&TeamReplicationError::CapacityExceeded {
            resource: "service operations",
        });
    };
    let replica = Arc::clone(&state.replica);
    match tokio::task::spawn_blocking(move || {
        let _operation_permit = operation_permit;
        replica.handle_push(&request)
    })
    .await
    {
        Ok(Ok(response)) => (StatusCode::OK, Json(response)).into_response(),
        Ok(Err(error)) => failure_response(&error),
        Err(_) => failure_response(&TeamReplicationError::ServiceUnavailable),
    }
}

async fn pull_handler(
    State(state): State<Arc<ServiceState>>,
    request: Result<Json<PullRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(request)) = request else {
        return failure_response(&TeamReplicationError::InvalidProtocol);
    };
    let Ok(operation_permit) = Arc::clone(&state.operations).try_acquire_owned() else {
        return failure_response(&TeamReplicationError::CapacityExceeded {
            resource: "service operations",
        });
    };
    let replica = Arc::clone(&state.replica);
    match tokio::task::spawn_blocking(move || {
        let _operation_permit = operation_permit;
        replica.handle_pull(&request)
    })
    .await
    {
        Ok(Ok(response)) => (StatusCode::OK, Json(response)).into_response(),
        Ok(Err(error)) => failure_response(&error),
        Err(_) => failure_response(&TeamReplicationError::ServiceUnavailable),
    }
}

fn failure_response(error: &TeamReplicationError) -> Response {
    let (status, failure) = match error.failure_class() {
        TeamReplicationFailureClass::AuthorizationDenied => (
            StatusCode::UNAUTHORIZED,
            ProtocolFailure::new(ProtocolFailureCode::Unauthorized, false),
        ),
        TeamReplicationFailureClass::CapacityExceeded => (
            StatusCode::TOO_MANY_REQUESTS,
            ProtocolFailure::new(ProtocolFailureCode::CapacityExceeded, true),
        ),
        TeamReplicationFailureClass::ConcurrentUpdate => (
            StatusCode::CONFLICT,
            ProtocolFailure::new(ProtocolFailureCode::Conflict, true),
        ),
        TeamReplicationFailureClass::IntegrityFailure => (
            StatusCode::SERVICE_UNAVAILABLE,
            ProtocolFailure::new(ProtocolFailureCode::Corrupt, false),
        ),
        TeamReplicationFailureClass::Unavailable | TeamReplicationFailureClass::Unconfigured => (
            StatusCode::SERVICE_UNAVAILABLE,
            ProtocolFailure::new(ProtocolFailureCode::Unavailable, true),
        ),
        TeamReplicationFailureClass::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            ProtocolFailure::new(ProtocolFailureCode::InvalidRequest, false),
        ),
    };
    (status, Json(failure)).into_response()
}

enum WorkerCommand {
    Synchronize(mpsc::Sender<Result<TeamSyncReport, TeamReplicationError>>),
    Wake,
    Shutdown,
}

/// Owner for the dedicated replication worker thread. The worker performs no
/// prompt or transcript processing: it only pushes/pulls typed immutable
/// technical-memory revisions through the pinned service.
pub struct TeamReplicationSupervisor {
    sender: SyncSender<WorkerCommand>,
    shutdown_requested: Arc<AtomicBool>,
    join: Mutex<Option<thread::JoinHandle<()>>>,
}

impl fmt::Debug for TeamReplicationSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TeamReplicationSupervisor")
            .finish_non_exhaustive()
    }
}

impl TeamReplicationSupervisor {
    /// Start one bounded single-threaded transport owner.
    ///
    /// # Errors
    ///
    /// Returns a typed operating-system error if the owned worker thread cannot
    /// be started.
    pub fn start(replica: Arc<TeamReplica>) -> Result<Self, TeamReplicationError> {
        Self::spawn(replica, true)
    }

    /// Start a bounded transport owner without an implicit cycle. This is used
    /// by the host CLI when it will immediately submit and observe one exact
    /// synchronization request.
    ///
    /// # Errors
    ///
    /// Returns a typed operating-system error if the owned worker thread cannot
    /// be started.
    pub fn start_for_explicit_sync(
        replica: Arc<TeamReplica>,
    ) -> Result<Self, TeamReplicationError> {
        Self::spawn(replica, false)
    }

    fn spawn(
        replica: Arc<TeamReplica>,
        synchronize_at_startup: bool,
    ) -> Result<Self, TeamReplicationError> {
        let (sender, receiver) = mpsc::sync_channel(MAX_WORKER_COMMANDS);
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown_requested);
        let join = thread::Builder::new()
            .name("openclaudia-team-memory".to_string())
            .spawn(move || {
                worker_main(
                    replica.as_ref(),
                    &receiver,
                    synchronize_at_startup,
                    worker_shutdown.as_ref(),
                );
            })
            .map_err(|error| TeamReplicationError::Store(anyhow::Error::new(error)))?;
        Ok(Self {
            sender,
            shutdown_requested,
            join: Mutex::new(Some(join)),
        })
    }

    /// Queue one synchronization cycle without blocking a tool call.
    ///
    /// # Errors
    ///
    /// Returns a typed availability error if the supervisor is shutting down
    /// or its worker has exited.
    pub fn request_sync(&self) -> Result<bool, TeamReplicationError> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(TeamReplicationError::ServiceUnavailable);
        }
        match self.sender.try_send(WorkerCommand::Wake) {
            Ok(()) => Ok(true),
            Err(TrySendError::Full(_)) => Ok(false),
            Err(TrySendError::Disconnected(_)) => Err(TeamReplicationError::ServiceUnavailable),
        }
    }

    /// Run and observe one synchronization cycle with a fixed wait budget.
    ///
    /// # Errors
    ///
    /// Returns a typed capacity, availability, authority, protocol, or
    /// persistence error when the cycle cannot complete and be observed.
    pub fn synchronize_now(&self) -> Result<TeamSyncReport, TeamReplicationError> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(TeamReplicationError::ServiceUnavailable);
        }
        let (reply, result) = mpsc::channel();
        self.sender
            .try_send(WorkerCommand::Synchronize(reply))
            .map_err(|error| match error {
                TrySendError::Full(_) => TeamReplicationError::CapacityExceeded {
                    resource: "worker commands",
                },
                TrySendError::Disconnected(_) => TeamReplicationError::ServiceUnavailable,
            })?;
        result
            .recv_timeout(EXPLICIT_SYNC_TIMEOUT)
            .map_err(|_| TeamReplicationError::ServiceUnavailable)?
    }

    /// Stop and join the worker. Every network request already has its own
    /// timeout, so shutdown cannot wait on an unbounded socket operation.
    ///
    /// # Errors
    ///
    /// Returns a typed recovery error if the worker handle was poisoned or the
    /// owned worker panicked.
    pub fn shutdown(&self) -> Result<(), TeamReplicationError> {
        self.shutdown_requested.store(true, Ordering::Release);
        let _ = self.sender.try_send(WorkerCommand::Shutdown);
        let join = self
            .join
            .lock()
            .map_err(|_| TeamReplicationError::RecoveryRequired {
                reason: "replication worker handle is poisoned",
            })?
            .take();
        if let Some(join) = join {
            join.join()
                .map_err(|_| TeamReplicationError::RecoveryRequired {
                    reason: "replication worker panicked",
                })?;
        }
        Ok(())
    }
}

impl Drop for TeamReplicationSupervisor {
    fn drop(&mut self) {
        self.shutdown_requested.store(true, Ordering::Release);
        let _ = self.sender.try_send(WorkerCommand::Shutdown);
        if let Ok(join) = self.join.get_mut() {
            if let Some(join) = join.take() {
                let _ = join.join();
            }
        }
    }
}

fn worker_main(
    replica: &TeamReplica,
    receiver: &Receiver<WorkerCommand>,
    synchronize_at_startup: bool,
    shutdown_requested: &AtomicBool,
) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        let _ = replica.mark_sync_failure(&TeamReplicationError::ServiceUnavailable);
        return;
    };
    let mut run_immediately = synchronize_at_startup;
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            break;
        }
        let command = if run_immediately {
            run_immediately = false;
            Some(WorkerCommand::Wake)
        } else {
            match receiver.recv_timeout(WORKER_IDLE_INTERVAL) {
                Ok(command) => Some(command),
                Err(mpsc::RecvTimeoutError::Timeout) => Some(WorkerCommand::Wake),
                Err(mpsc::RecvTimeoutError::Disconnected) => None,
            }
        };
        let Some(command) = command else {
            break;
        };
        match command {
            WorkerCommand::Shutdown => break,
            WorkerCommand::Wake => {
                let result = runtime.block_on(synchronize_cycle(replica));
                if let Err(error) = &result {
                    let _ = replica.mark_sync_failure(error);
                } else if result
                    .as_ref()
                    .is_ok_and(|report| report.more_available || report.remaining_outbox > 0)
                {
                    run_immediately = true;
                }
            }
            WorkerCommand::Synchronize(reply) => {
                let result = runtime.block_on(synchronize_cycle(replica));
                if let Err(error) = &result {
                    let _ = replica.mark_sync_failure(error);
                }
                let schedule_more = result
                    .as_ref()
                    .is_ok_and(|report| report.more_available || report.remaining_outbox > 0);
                let _ = reply.send(result);
                run_immediately = schedule_more;
            }
        }
    }
}

async fn synchronize_cycle(replica: &TeamReplica) -> Result<TeamSyncReport, TeamReplicationError> {
    let service = replica.pinned_service()?;
    let certificate = base64::engine::general_purpose::STANDARD
        .decode(&service.certificate_der_base64)
        .map_err(|_| TeamReplicationError::CorruptReplica)?;
    if certificate.is_empty() || certificate.len() > MAX_TEAM_REPLICATION_CERTIFICATE_BYTES {
        return Err(TeamReplicationError::CorruptReplica);
    }
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate.clone()))
        .map_err(|_| TeamReplicationError::CorruptReplica)?;
    let webpki = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| TeamReplicationError::CorruptReplica)?;
    let verifier = ExactPinnedServerVerifier {
        pinned_end_entity: CertificateDer::from(certificate),
        webpki,
    };
    let mut tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .tls_info(true)
        .build()
        .map_err(|error| TeamReplicationError::Store(anyhow::Error::new(error)))?;

    let pushed = if let Some(request) = replica.prepare_push()? {
        let response: PushResponse =
            post_json_pinned(&client, &service, "v1/push", &request).await?;
        replica.apply_push_ack(&request, &response)?
    } else {
        0
    };

    let request = replica.prepare_pull()?;
    let response: PullResponse = post_json_pinned(&client, &service, "v1/pull", &request).await?;
    let mut report = replica.apply_pull_ack(&request, &response, chrono::Utc::now().timestamp())?;
    report.pushed_revisions = pushed;
    let (remaining, cursor, freshness) = replica.synchronization_progress()?;
    report.remaining_outbox = remaining;
    report.pull_cursor = cursor;
    report.freshness = freshness;
    Ok(report)
}

async fn post_json_pinned<Request, Reply>(
    client: &reqwest::Client,
    service: &super::replication::PinnedTeamService,
    path: &str,
    request: &Request,
) -> Result<Reply, TeamReplicationError>
where
    Request: Serialize + Sync + ?Sized,
    Reply: DeserializeOwned,
{
    let body = serde_json::to_vec(request).map_err(|_| TeamReplicationError::InvalidProtocol)?;
    if body.len() > MAX_TEAM_REPLICATION_MESSAGE_BYTES {
        return Err(TeamReplicationError::CapacityExceeded {
            resource: "request bytes",
        });
    }
    let endpoint = format!("{}/{}", service.endpoint.trim_end_matches('/'), path);
    let response = client
        .post(endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|error| {
            tracing::debug!(error = ?error, "team-memory pinned TLS request failed");
            TeamReplicationError::ServiceUnavailable
        })?;
    let peer = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(reqwest::tls::TlsInfo::peer_certificate)
        .ok_or(TeamReplicationError::ServiceIdentityMismatch)?;
    if ContentDigest::sha256(peer) != service.certificate_digest {
        return Err(TeamReplicationError::ServiceIdentityMismatch);
    }
    let status = response.status();
    let bytes = read_bounded_response(response).await?;
    if !status.is_success() {
        return Err(decode_protocol_failure(&bytes));
    }
    serde_json::from_slice(&bytes).map_err(|_| TeamReplicationError::InvalidProtocol)
}

fn decode_protocol_failure(bytes: &[u8]) -> TeamReplicationError {
    let Ok(failure) = serde_json::from_slice::<ProtocolFailure>(bytes) else {
        return TeamReplicationError::InvalidProtocol;
    };
    if failure.schema_version != TEAM_REPLICATION_SCHEMA_VERSION {
        return TeamReplicationError::InvalidProtocol;
    }
    let expected_retryable = matches!(
        failure.code,
        ProtocolFailureCode::CapacityExceeded
            | ProtocolFailureCode::Conflict
            | ProtocolFailureCode::Unavailable
    );
    if failure.retryable != expected_retryable {
        return TeamReplicationError::InvalidProtocol;
    }
    match failure.code {
        ProtocolFailureCode::Unauthorized => TeamReplicationError::Unauthorized,
        ProtocolFailureCode::CapacityExceeded => TeamReplicationError::CapacityExceeded {
            resource: "remote service",
        },
        ProtocolFailureCode::Conflict => TeamReplicationError::ConcurrentUpdate,
        ProtocolFailureCode::Corrupt => TeamReplicationError::CorruptReplica,
        ProtocolFailureCode::Unavailable => TeamReplicationError::ServiceUnavailable,
        ProtocolFailureCode::InvalidRequest => TeamReplicationError::InvalidProtocol,
    }
}

async fn read_bounded_response(
    response: reqwest::Response,
) -> Result<Vec<u8>, TeamReplicationError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_TEAM_REPLICATION_MESSAGE_BYTES as u64)
    {
        return Err(TeamReplicationError::CapacityExceeded {
            resource: "response bytes",
        });
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| TeamReplicationError::ServiceUnavailable)?;
        if body.len().saturating_add(chunk.len()) > MAX_TEAM_REPLICATION_MESSAGE_BYTES {
            return Err(TeamReplicationError::CapacityExceeded {
                resource: "response bytes",
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::missing_panics_doc)]

    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use tempfile::TempDir;
    use tokio::sync::oneshot;

    use super::*;
    use crate::memory::{
        LessonApplicability, LessonCitation, LessonCitationKind, LessonRetention, MemoryDigest,
        MemorySourceEvidence, MemorySourceKind, TechnicalLessonConfidence, TechnicalLessonDraft,
        TechnicalLessonKind, TechnicalLessonSensitivity,
    };
    use crate::team_memory::{PrincipalId, TeamAuthorityStore, TeamReplicaFreshness};

    const CERTIFICATE_DER_BASE64: &str = "MIIBvTCCAWOgAwIBAgIUfUWeyDgo5yP5nWXotTF/TOMi/OEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgyMjAxMDYwNFoXDTM2MDgxOTAxMDYwNFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXGgdHsWaQlfJxe8pg6dK0IdFetzHDo/SwISNqf7oammUDXRmMWSdBbpeNHNoN10ICpWELUjCycVlyEEx+eo7CaOBkjCBjzAdBgNVHQ4EFgQUxTjb982X3PKPSoxPLX0WtOGedIcwHwYDVR0jBBgwFoAUxTjb982X3PKPSoxPLX0WtOGedIcwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoGCCqGSM49BAMCA0gAMEUCIF8+FLOhGMMka9yLeQcqHBeDxiaECrfSphs96q/nauA5AiEA9Z9m0FsKG7+5c2B/TF+NJGmHAmJU35o4Tn+KYZPiM8g=";
    const PRIVATE_KEY_DER_BASE64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg58C+xFdeqHGqODQTRkayehwW28s3HJyivpOhztEorjOhRANCAARcaB0exZpCV8nF7ymDp0rQh0V63McOj9LAhI2p/uhqaZQNdGYxZJ0Ful40c2g3XQgKlYQtSMLJxWXIQTH56jsJ";
    const UNPINNED_CERTIFICATE_DER_BASE64: &str = "MIIBmDCCAT+gAwIBAgIUWvvhdxCG6RBaIMQqH5o1FBg5SlAwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgyMjAxMDEzNFoXDTM2MDgxOTAxMDEzNFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1MgCW7ui8BAwG5fbqzL2qtgqiTnlGS86ecLPIM3cCRbDK6weI3caZ8OcUZHZB9EBQ/uvZNPP9UxM+yu6IV9JdKNvMG0wHQYDVR0OBBYEFLEktKC0h4cHevnp45h3KKfjocTZMB8GA1UdIwQYMBaAFLEktKC0h4cHevnp45h3KKfjocTZMA8GA1UdEwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0cAMEQCICdSLz6lttdLMgriWGMgwqXLr14ptcVWNuj/F1GNWAvxAiAIhngdirhHuDYWJLgE46+t8CsLGnMBebyBlHoXTUXjBw==";
    const UNPINNED_PRIVATE_KEY_DER_BASE64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4oTpfjf15PJlyaiJTEf2iJFZyHlrZ11hIaDe5mDYHIahRANCAATUyAJbu6LwEDAbl9urMvaq2CqJOeUZLzp5ws8gzdwJFsMrrB4jdxpnw5xRkdkH0QFD+69k08/1TEz7K7ohX0l0";

    struct Fixture {
        _home: TempDir,
        _workspace: TempDir,
        authority: TeamAuthorityStore,
    }

    fn fixture() -> Fixture {
        let home = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("workspace");
        let principal: PrincipalId = "owner".parse().expect("principal");
        let authority =
            TeamAuthorityStore::bootstrap(home.path(), workspace.path(), principal, 31_536_000)
                .expect("authority");
        Fixture {
            _home: home,
            _workspace: workspace,
            authority,
        }
    }

    fn lesson() -> TechnicalLessonDraft {
        TechnicalLessonDraft {
            title: "TLS replication boundary".to_string(),
            kind: TechnicalLessonKind::Security,
            observation: "The replica client pins the exact service certificate.".to_string(),
            guidance: "Retain certificate and signed service identity validation.".to_string(),
            applicability: LessonApplicability {
                paths: vec!["src/team_memory/transport.rs".to_string()],
                symbols: vec!["post_json_pinned".to_string()],
                ..LessonApplicability::default()
            },
            citations: vec![LessonCitation {
                kind: LessonCitationKind::Test,
                locator: "src/team_memory/transport.rs".to_string(),
                source_version: "git:s104-test".to_string(),
                digest: MemoryDigest::for_fields(b"openclaudia.s104.tls-test.v1", &[b"lesson"]),
                line_start: Some(1),
                line_end: Some(1),
            }],
            confidence: TechnicalLessonConfidence::VerifiedByTest,
            sensitivity: TechnicalLessonSensitivity::Internal,
            retention: LessonRetention::Indefinite,
        }
    }

    fn source() -> MemorySourceEvidence {
        MemorySourceEvidence::new(
            MemorySourceKind::ToolOutcome,
            "test:tls".to_string(),
            "generation:test".to_string(),
            MemoryDigest::for_fields(b"openclaudia.s104.tls-source.v1", &[b"source"]),
        )
    }

    #[test]
    fn full_command_queue_cannot_prevent_supervisor_drop_from_stopping_worker() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        sender.try_send(WorkerCommand::Wake).expect("fill queue");
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown_requested);
        let join = thread::spawn(move || {
            while !worker_shutdown.load(Ordering::Acquire) {
                thread::park_timeout(Duration::from_millis(1));
            }
        });
        let supervisor = TeamReplicationSupervisor {
            sender,
            shutdown_requested,
            join: Mutex::new(Some(join)),
        };

        drop(supervisor);
    }

    #[test]
    fn stopped_supervisor_rejects_new_work() {
        let fixture = fixture();
        let client = Arc::new(TeamReplica::open_client(fixture.authority).expect("client replica"));
        let supervisor =
            TeamReplicationSupervisor::start_for_explicit_sync(client).expect("supervisor");
        supervisor.shutdown().expect("shutdown");

        assert!(matches!(
            supervisor.request_sync(),
            Err(TeamReplicationError::ServiceUnavailable)
        ));
        assert!(matches!(
            supervisor.synchronize_now(),
            Err(TeamReplicationError::ServiceUnavailable)
        ));
    }

    #[test]
    fn downgraded_or_malformed_remote_failure_is_not_accepted() {
        let downgraded = serde_json::to_vec(&ProtocolFailure {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION - 1,
            code: ProtocolFailureCode::Unavailable,
            retryable: true,
        })
        .expect("failure fixture");
        assert!(matches!(
            decode_protocol_failure(&downgraded),
            TeamReplicationError::InvalidProtocol
        ));
        assert!(matches!(
            decode_protocol_failure(b"not-json"),
            TeamReplicationError::InvalidProtocol
        ));
        let false_retryability = serde_json::to_vec(&ProtocolFailure {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
            code: ProtocolFailureCode::Unauthorized,
            retryable: true,
        })
        .expect("failure fixture");
        assert!(matches!(
            decode_protocol_failure(&false_retryability),
            TeamReplicationError::InvalidProtocol
        ));
    }

    #[test]
    fn nonidentical_leaf_is_rejected_before_chain_validation() {
        let pinned = BASE64_STANDARD
            .decode(CERTIFICATE_DER_BASE64)
            .expect("pinned certificate fixture");
        let other_leaf = BASE64_STANDARD
            .decode(UNPINNED_CERTIFICATE_DER_BASE64)
            .expect("different leaf fixture");
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(pinned.clone()))
            .expect("pinned root");
        let webpki = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .expect("WebPKI verifier");
        let verifier = ExactPinnedServerVerifier {
            pinned_end_entity: CertificateDer::from(pinned),
            webpki,
        };
        let server_name = ServerName::try_from("localhost").expect("server name");

        let error = verifier
            .verify_server_cert(
                &CertificateDer::from(other_leaf),
                &[],
                &server_name,
                &[],
                UnixTime::since_unix_epoch(Duration::ZERO),
            )
            .expect_err("a non-identical leaf must fail before chain validation");
        assert!(matches!(
            error,
            RustlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        ));
    }

    #[tokio::test]
    async fn prepared_server_rejects_a_certificate_key_mismatch() {
        let certificate = BASE64_STANDARD
            .decode(CERTIFICATE_DER_BASE64)
            .expect("certificate fixture");
        let mismatched_key = Zeroizing::new(
            BASE64_STANDARD
                .decode(UNPINNED_PRIVATE_KEY_DER_BASE64)
                .expect("mismatched key fixture"),
        );
        assert!(TeamMemoryTlsServer::bind(
            "127.0.0.1:0".parse().expect("listen address"),
            certificate,
            mismatched_key,
        )
        .await
        .is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls_supervisor_syncs_through_the_pinned_service_and_reports_interruption() {
        let fixture = fixture();
        let certificate = BASE64_STANDARD
            .decode(CERTIFICATE_DER_BASE64)
            .expect("certificate fixture");
        let private_key = Zeroizing::new(
            BASE64_STANDARD
                .decode(PRIVATE_KEY_DER_BASE64)
                .expect("private key fixture"),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener");
        let listen = listener.local_addr().expect("listener address");
        let endpoint = format!("https://127.0.0.1:{}", listen.port());
        let service = Arc::new(
            TeamReplica::open_service(fixture.authority.clone()).expect("service replica"),
        );
        let client =
            Arc::new(TeamReplica::open_client(fixture.authority.clone()).expect("client replica"));
        let descriptor = service
            .service_descriptor(&endpoint, &certificate)
            .expect("descriptor");
        client
            .configure_service(&descriptor, false)
            .expect("pin descriptor");
        client
            .save_technical_lesson_candidate(
                &lesson(),
                source(),
                "agent:test".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("queue lesson");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(serve_team_memory_tls_on_listener(
            Arc::clone(&service),
            listener,
            certificate,
            private_key,
            async move {
                let _ = shutdown_rx.await;
            },
        ));
        let supervisor = TeamReplicationSupervisor::start_for_explicit_sync(Arc::clone(&client))
            .expect("supervisor");
        let (report, worker_shutdown) = tokio::task::spawn_blocking(move || {
            let report = supervisor.synchronize_now();
            let shutdown = supervisor.shutdown();
            (report, shutdown)
        })
        .await
        .expect("worker join");
        let report = report.expect("TLS sync");
        worker_shutdown.expect("worker shutdown");
        assert_eq!(report.pushed_revisions, 1);
        assert_eq!(report.pulled_revisions, 1);
        assert_eq!(report.remaining_outbox, 0);
        assert_eq!(report.freshness, TeamReplicaFreshness::Current);
        let query = client
            .query_technical_lessons(Some("certificate"), 5, chrono::Utc::now().timestamp())
            .expect("local synchronized query");
        assert_eq!(query.result.records.len(), 1);

        shutdown_tx.send(()).expect("server shutdown signal");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("bounded server shutdown")
            .expect("server task")
            .expect("server result");

        let offline = TeamReplicationSupervisor::start_for_explicit_sync(Arc::clone(&client))
            .expect("offline supervisor");
        let (failure, worker_shutdown) = tokio::task::spawn_blocking(move || {
            let report = offline.synchronize_now();
            let shutdown = offline.shutdown();
            (report, shutdown)
        })
        .await
        .expect("offline worker join");
        assert!(matches!(
            failure,
            Err(TeamReplicationError::ServiceUnavailable)
        ));
        worker_shutdown.expect("offline worker shutdown");
        assert_eq!(
            client.status().expect("stale status").freshness,
            TeamReplicaFreshness::Stale
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unpinned_but_well_formed_tls_identity_receives_no_replication_payload() {
        let fixture = fixture();
        let pinned_certificate = BASE64_STANDARD
            .decode(CERTIFICATE_DER_BASE64)
            .expect("pinned certificate");
        let unpinned_certificate = BASE64_STANDARD
            .decode(UNPINNED_CERTIFICATE_DER_BASE64)
            .expect("unpinned certificate");
        let unpinned_private_key = Zeroizing::new(
            BASE64_STANDARD
                .decode(UNPINNED_PRIVATE_KEY_DER_BASE64)
                .expect("unpinned key"),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener");
        let endpoint = format!(
            "https://127.0.0.1:{}",
            listener.local_addr().expect("listener address").port()
        );
        let service = Arc::new(
            TeamReplica::open_service(fixture.authority.clone()).expect("service replica"),
        );
        let client =
            Arc::new(TeamReplica::open_client(fixture.authority.clone()).expect("client replica"));
        let descriptor = service
            .service_descriptor(&endpoint, &pinned_certificate)
            .expect("pinned descriptor");
        client
            .configure_service(&descriptor, false)
            .expect("pin descriptor");
        client
            .save_technical_lesson_candidate(
                &lesson(),
                source(),
                "agent:test".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("queue lesson");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(serve_team_memory_tls_on_listener(
            Arc::clone(&service),
            listener,
            unpinned_certificate,
            unpinned_private_key,
            async move {
                let _ = shutdown_rx.await;
            },
        ));
        assert!(matches!(
            synchronize_cycle(client.as_ref()).await,
            Err(TeamReplicationError::ServiceUnavailable
                | TeamReplicationError::ServiceIdentityMismatch)
        ));
        assert_eq!(service.status().expect("service status").revisions, 0);

        shutdown_tx.send(()).expect("server shutdown signal");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("bounded server shutdown")
            .expect("server task")
            .expect("server result");
    }
}
