use crate::{
    get_private_key, get_public_key, log, log_cv_in, log_cv_out, log_err, log_in,
    server::{omikron_manager, short_link::add_short_link},
    sql::{
        connection_status::UserStatus,
        sql::{self, get_by_user_id, get_by_username, get_iota_by_id, get_omikron_by_id},
        user_online_tracker::{self},
    },
    util::{crypto_helper::encrypt, file_util::load_file_vec, logger::PrintType},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use dashmap::DashMap;
use epsilon_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use epsilon_native::{Host, Receiver, Sender};
use rand::{Rng, distributions::Alphanumeric};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, RwLock},
    time::interval,
};
use x448::PublicKey;

// ============================================================================
// Configuration
// ============================================================================

const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const MAX_WAITING_AGE: Duration = Duration::from_secs(60);

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum OmikronError {
    #[error("Not connected")]
    NotConnected,
    #[error("Not authenticated")]
    NotAuthenticated,
    #[error("Invalid response")]
    InvalidResponse,
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("SQL error: {0}")]
    Sql(String),
    #[error("Send error: {0}")]
    Send(String),
}

pub type OmikronResult<T> = Result<T, OmikronError>;

// ============================================================================
// Waiting Task System (Preserved from original)
// ============================================================================

pub struct WaitingTask {
    pub task: Box<dyn Fn(Arc<OmikronConnection>, CommunicationValue) -> bool + Send + Sync>,
    pub inserted_at: Instant,
}

// ============================================================================
// Connection State
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthState {
    Unauthenticated,
    Identified { omikron_id: i64 },
    Authenticated { omikron_id: i64 },
}

impl AuthState {
    fn is_authenticated(&self) -> bool {
        match self {
            AuthState::Authenticated { omikron_id } => true,
            _ => false,
        }
    }

    fn omikron_id(&self) -> Option<i64> {
        match self {
            AuthState::Identified { omikron_id } | AuthState::Authenticated { omikron_id } => {
                Some(*omikron_id)
            }
            _ => None,
        }
    }
}

// ============================================================================
// Omikron Connection (Epsilon/QUIC-based)
// ============================================================================

pub struct OmikronConnection {
    id: u64,
    sender: Mutex<Option<Sender>>,
    state: RwLock<AuthState>,
    challenge: RwLock<String>,
    pub_key: RwLock<Option<Vec<u8>>>,
    pub ping: RwLock<i64>,
    waiting_tasks: DashMap<u32, WaitingTask>,
    cleanup_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl OmikronConnection {
    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    pub fn new(sender: Sender) -> Arc<Self> {
        let conn = Arc::new(Self {
            id: rand::random(),
            sender: Mutex::new(Some(sender)),
            state: RwLock::new(AuthState::Unauthenticated),
            challenge: RwLock::new(String::new()),
            pub_key: RwLock::new(None),
            ping: RwLock::new(-1),
            waiting_tasks: DashMap::new(),
            cleanup_handle: Mutex::new(None),
        });

        // Start cleanup task for waiting tasks
        let cleanup_conn = conn.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = interval(CLEANUP_INTERVAL);
            loop {
                ticker.tick().await;
                cleanup_conn
                    .waiting_tasks
                    .retain(|_, v| v.inserted_at.elapsed() < MAX_WAITING_AGE);
            }
        });

        // Store handle (would need block_in_place or similar to set this immediately)
        // For now, we'll handle this differently in handle()

        conn
    }

    // -------------------------------------------------------------------------
    // Main Handler Loop
    // -------------------------------------------------------------------------

    pub async fn handle(self: Arc<Self>, receiver: Receiver) {
        log_in!(
            self.id as i64,
            PrintType::Omega,
            "Omikron connection started"
        );

        // Start cleanup task
        let cleanup_conn = self.clone();
        let _cleanup_handle = tokio::spawn(async move {
            let mut ticker = interval(CLEANUP_INTERVAL);
            loop {
                ticker.tick().await;
                cleanup_conn
                    .waiting_tasks
                    .retain(|_, v| v.inserted_at.elapsed() < MAX_WAITING_AGE);
            }
        });

        while let Ok(cv) = receiver.receive().await {
            if let Err(e) = self.clone().process_message(cv).await {
                log_err!(0, PrintType::Omega, "Error processing message: {}", e);
                // Don't break on error unless critical - match original WebSocket behavior
                if matches!(e, OmikronError::NotConnected) {
                    break;
                }
            }
        }

        // Connection closed
        self.clone().cleanup().await;
        log_in!(
            self.id as i64,
            PrintType::Omega,
            "Omikron connection  closed"
        );
    }

    // -------------------------------------------------------------------------
    // Message Processing
    // -------------------------------------------------------------------------

    async fn process_message(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        // Log incoming
        log_cv_in!(PrintType::Omikron, &cv);

        let msg_id = cv.get_id();

        // Check waiting tasks first (response to previous request)
        if let Some((_, task)) = self.waiting_tasks.remove(&msg_id) {
            let _ = (task.task)(self.clone(), cv);
            return Ok(());
        }

        // Handle ping regardless of auth state
        if cv.is_type(CommunicationType::ping) {
            return self.handle_ping(cv).await;
        }

        // Route based on authentication state
        match *self.state.read().await {
            AuthState::Unauthenticated => self.clone().handle_unauthenticated(cv).await,
            AuthState::Identified { .. } => self.clone().handle_identified(cv).await,
            AuthState::Authenticated { omikron_id } => {
                self.clone().handle_authenticated(cv, omikron_id).await
            }
        }
    }

    // -------------------------------------------------------------------------
    // Authentication Handlers
    // -------------------------------------------------------------------------

    async fn handle_unauthenticated(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        if !cv.is_type(CommunicationType::identification) {
            let _ = self
                .send_error_response(cv.get_id(), CommunicationType::error_not_authenticated)
                .await;
            return Err(OmikronError::NotAuthenticated);
        }

        // Extract omikron ID
        let omikron_id = cv
            .get_data(DataTypes::omikron)
            .as_number()
            .ok_or(OmikronError::InvalidResponse)?;

        // Lookup omikron in database
        let (public_key, _) = get_omikron_by_id(omikron_id)
            .await
            .map_err(|e| OmikronError::Sql(e.to_string()))?;

        let pub_key_bytes = STANDARD
            .decode(&public_key)
            .map_err(|_| OmikronError::AuthenticationFailed)?;

        let omikron_pub_key =
            PublicKey::from_bytes(&pub_key_bytes).ok_or(OmikronError::AuthenticationFailed)?;

        // Generate challenge
        let challenge: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // Store state
        *self.challenge.write().await = challenge.clone();
        *self.pub_key.write().await = Some(pub_key_bytes);
        *self.state.write().await = AuthState::Identified { omikron_id };

        // Encrypt challenge
        let encrypted = encrypt(get_private_key(), omikron_pub_key, &challenge)
            .map_err(|_| OmikronError::AuthenticationFailed)?;

        // Send challenge response
        let response = CommunicationValue::new(CommunicationType::challenge)
            .with_id(cv.get_id())
            .add_data(
                DataTypes::public_key,
                DataValue::Str(STANDARD.encode(get_public_key().as_bytes())),
            )
            .add_data(DataTypes::challenge, DataValue::Str(encrypted));

        self.send(&response).await
    }

    async fn handle_identified(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        if !cv.is_type(CommunicationType::challenge_response) {
            let _ = self
                .send_error_response(cv.get_id(), CommunicationType::error_not_authenticated)
                .await;
            return Err(OmikronError::NotAuthenticated);
        }

        let client_response = cv
            .get_data(DataTypes::challenge)
            .as_str()
            .ok_or(OmikronError::InvalidResponse)?;

        let expected_challenge = self.challenge.read().await.clone();

        if client_response == expected_challenge {
            let omikron_id = self.state.read().await.omikron_id().unwrap_or(0);
            *self.state.write().await = AuthState::Authenticated { omikron_id };

            omikron_manager::add_omikron(self.clone()).await;

            let response = CommunicationValue::new(CommunicationType::identification_response)
                .with_id(cv.get_id())
                .add_data(DataTypes::accepted, DataValue::Bool(true));

            self.clone().send(&response).await?;
            log_in!(omikron_id, PrintType::Omega, "Omikron authenticated");
            Ok(())
        } else {
            let _ = self
                .send_error_response(cv.get_id(), CommunicationType::error_invalid_challenge)
                .await;
            Err(OmikronError::AuthenticationFailed)
        }
    }

    // -------------------------------------------------------------------------
    // Authenticated Message Handlers
    // -------------------------------------------------------------------------

    async fn handle_authenticated(
        self: Arc<Self>,
        cv: CommunicationValue,
        omikron_id: i64,
    ) -> OmikronResult<()> {
        match cv.get_type() {
            // Link shortening
            CommunicationType::shorten_link => self.handle_shorten_link(cv).await,

            // Online status tracking
            CommunicationType::user_connected => {
                self.handle_user_connected(cv, omikron_id).await;
                Ok(())
            }
            CommunicationType::user_disconnected => {
                self.handle_user_disconnected(cv, omikron_id).await;
                Ok(())
            }
            CommunicationType::iota_connected => {
                self.handle_iota_connected(cv, omikron_id).await;
                Ok(())
            }
            CommunicationType::iota_disconnected => {
                self.handle_iota_disconnected(cv, omikron_id).await;
                Ok(())
            }
            CommunicationType::sync_client_iota_status => {
                self.handle_sync_status(cv, omikron_id).await;
                Ok(())
            }

            CommunicationType::get_user_data => self.handle_get_user_data(cv).await,
            CommunicationType::get_iota_data => self.handle_get_iota_data(cv).await,

            CommunicationType::get_register => self.handle_get_register(cv).await,
            CommunicationType::complete_register_iota => {
                self.handle_complete_register_iota(cv).await
            }
            CommunicationType::complete_register_user => {
                self.handle_complete_register_user(cv).await
            }

            CommunicationType::change_user_data => self.handle_change_user_data(cv).await,
            CommunicationType::change_iota_data => self.handle_change_iota_data(cv).await,
            CommunicationType::delete_user => self.handle_delete_user(cv).await,
            CommunicationType::delete_iota => self.handle_delete_iota(cv).await,

            CommunicationType::get_notifications => self.handle_get_notifications(cv).await,
            CommunicationType::read_notification => self.handle_read_notification(cv).await,
            CommunicationType::push_notification => self.handle_push_notification(cv).await,

            _ => {
                log_err!(
                    0,
                    PrintType::Omega,
                    "Unknown message type: {:?}",
                    cv.get_type()
                );
                Ok(())
            }
        }
    }

    // -------------------------------------------------------------------------
    // Specific Handlers (ported from original WebSocket implementation)
    // -------------------------------------------------------------------------

    async fn handle_shorten_link(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        let link = cv
            .get_data(DataTypes::link)
            .as_str()
            .ok_or(OmikronError::InvalidResponse)?;

        let short = add_short_link(link)
            .await
            .map_err(|_| OmikronError::Sql("Shortend link Error".to_string()))?;

        let response = CommunicationValue::new(CommunicationType::shorten_link)
            .with_id(cv.get_id())
            .add_data(DataTypes::link, DataValue::Str(short));

        self.send(&response).await
    }

    async fn handle_user_connected(self: Arc<Self>, cv: CommunicationValue, omikron_id: i64) {
        log_in!(PrintType::Omega, "User connected");
        if let Some(user_id) = cv.get_data(DataTypes::user_id).as_number() {
            user_online_tracker::track_user_status(
                user_id as i64,
                UserStatus::user_online,
                omikron_id,
            );
        }
    }

    async fn handle_user_disconnected(self: Arc<Self>, cv: CommunicationValue, _omikron_id: i64) {
        log_in!(PrintType::Omega, "User disconnected");
        if let Some(user_id) = cv.get_data(DataTypes::user_id).as_number() {
            if let Some(status) = user_online_tracker::get_user_status(user_id as i64) {
                user_online_tracker::track_user_status(
                    user_id as i64,
                    UserStatus::user_offline,
                    status.omikron_id,
                );
            }
        }
    }

    async fn handle_iota_connected(self: Arc<Self>, cv: CommunicationValue, omikron_id: i64) {
        log_in!(PrintType::Omega, "IOTA connected");
        if let Some(iota_id) = cv.get_data(DataTypes::iota_id).as_number() {
            let iota_id = iota_id as i64;
            user_online_tracker::track_iota_connection(iota_id, omikron_id, true);

            let mut user_ids = Vec::new();
            if let Ok(users) = sql::get_users_by_iota_id(iota_id).await {
                for (user_id, _, _, _, _, _, _, _, _, _, _, _) in users {
                    user_ids.push(DataValue::Number(user_id));
                    user_online_tracker::track_user_status(
                        user_id,
                        UserStatus::user_offline,
                        omikron_id,
                    );
                }
            } else {
                log_in!(PrintType::General, "SQL error loading users for IOTA");
            }

            let response = CommunicationValue::new(CommunicationType::iota_user_data)
                .with_id(cv.get_id())
                .add_data(DataTypes::user_ids, DataValue::Array(user_ids));

            let _ = self.send(&response).await;
        } else {
            log_in!(PrintType::General, "No IOTA ID found");
        }
    }

    async fn handle_iota_disconnected(self: Arc<Self>, cv: CommunicationValue, omikron_id: i64) {
        log_in!(PrintType::Omega, "IOTA disconnected");
        if let Some(iota_id) = cv.get_data(DataTypes::iota_id).as_number() {
            let iota_id = iota_id as i64;
            let iota_offline = user_online_tracker::untrack_iota_connection(iota_id, omikron_id);
            if iota_offline {
                if let Ok(users) = sql::get_users_by_iota_id(iota_id).await {
                    let user_ids: Vec<i64> = users.iter().map(|u| u.0).collect();
                    user_online_tracker::untrack_many_users(&user_ids);
                }
            }
        }
    }

    async fn handle_sync_status(self: Arc<Self>, cv: CommunicationValue, omikron_id: i64) {
        if let DataValue::Array(user_ids) = cv.get_data(DataTypes::user_ids) {
            for user_id_val in user_ids {
                if let DataValue::Number(user_id) = user_id_val {
                    user_online_tracker::track_user_status(
                        *user_id,
                        UserStatus::user_online,
                        omikron_id,
                    );
                }
            }
        }

        if let DataValue::Array(iota_ids) = cv.get_data(DataTypes::iota_ids) {
            for iota_id_val in iota_ids {
                if let DataValue::Number(iota_id) = iota_id_val {
                    user_online_tracker::track_iota_connection(*iota_id, omikron_id, true);
                }
            }
        }
    }

    async fn handle_get_user_data(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        // Try by user_id first
        if let Some(user_id) = cv.get_data(DataTypes::user_id).as_number() {
            if let Ok(user_data) = get_by_user_id(user_id as i64).await {
                let response = self
                    .clone()
                    .build_user_data_response(cv.get_id(), user_data)
                    .await;
                return self.send(&response).await;
            }
        }

        // Try by username
        if let Some(username) = cv.get_data(DataTypes::username).as_str() {
            if let Ok(user_data) = get_by_username(username).await {
                let response = self
                    .clone()
                    .build_user_data_response(cv.get_id(), user_data)
                    .await;
                return self.send(&response).await;
            }
        }

        // Not found
        let response =
            CommunicationValue::new(CommunicationType::error_not_found).with_id(cv.get_id());
        self.send(&response).await
    }

    async fn build_user_data_response(
        self: Arc<Self>,
        msg_id: u32,
        user: (
            i64,
            i64,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<Vec<u8>>,
            i32,
            i64,
            String,
            String,
            String,
        ),
    ) -> CommunicationValue {
        let (
            id,
            iota_id,
            username,
            display,
            status,
            about,
            avatar,
            sub_level,
            sub_end,
            public_key,
            _,
            _,
        ) = user;

        let mut response = CommunicationValue::new(CommunicationType::get_user_data)
            .with_id(msg_id)
            .add_data(DataTypes::username, DataValue::Str(username.clone()))
            .add_data(DataTypes::public_key, DataValue::Str(public_key))
            .add_data(DataTypes::user_id, DataValue::Number(id))
            .add_data(DataTypes::iota_id, DataValue::Number(iota_id))
            .add_data(DataTypes::sub_level, DataValue::Number(sub_level as i64))
            .add_data(DataTypes::sub_end, DataValue::Number(sub_end));

        // Display name (fallback to username)
        let display_name = display.filter(|d| !d.is_empty()).unwrap_or(username);
        response = response.add_data(DataTypes::display, DataValue::Str(display_name));

        // Optional fields
        if let Some(s) = status.filter(|s| !s.is_empty()) {
            response = response.add_data(DataTypes::status, DataValue::Str(s));
        }
        if let Some(a) = about.filter(|a| !a.is_empty()) {
            response = response.add_data(DataTypes::about, DataValue::Str(a));
        }
        if let Some(av) = avatar {
            response = response.add_data(DataTypes::avatar, DataValue::Str(STANDARD.encode(av)));
        }

        // Online status
        let user_status = user_online_tracker::get_user_status(id);
        let iota_connections =
            user_online_tracker::get_iota_omikron_connections(iota_id).unwrap_or_default();

        if let Some(us) = user_status {
            response = response.add_data(
                DataTypes::online_status,
                DataValue::Str(us.connection_type.to_string()),
            );
            response = response.add_data(DataTypes::omikron_id, DataValue::Number(us.omikron_id));
        } else {
            response = response.add_data(
                DataTypes::online_status,
                DataValue::Str(UserStatus::iota_offline.to_string()),
            );
        }

        response = response.add_data(
            DataTypes::omikron_connections,
            DataValue::Array(
                iota_connections
                    .into_iter()
                    .map(DataValue::Number)
                    .collect(),
            ),
        );

        response
    }

    async fn handle_get_iota_data(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        // Try by iota_id
        if let Some(iota_id) = cv.get_data(DataTypes::iota_id).as_number() {
            if let Ok((iota_id, public_key)) = get_iota_by_id(iota_id as i64).await {
                let response = self
                    .clone()
                    .build_iota_data_response(cv.get_id(), iota_id, public_key, None, None)
                    .await;
                return self.send(&response).await;
            }
        }

        // Try by user_id
        if let Some(user_id) = cv.get_data(DataTypes::user_id).as_number() {
            if let Ok((_, iota_id, _, _, _, _, _, _, _, _, _, _)) =
                get_by_user_id(user_id as i64).await
            {
                if let Ok((iota_id, public_key)) = get_iota_by_id(iota_id).await {
                    let response = self
                        .clone()
                        .build_iota_data_response(
                            cv.get_id(),
                            iota_id,
                            public_key,
                            Some(user_id as i64),
                            None,
                        )
                        .await;
                    return self.send(&response).await;
                }
            }
        }

        // Try by username
        if let Some(username) = cv.get_data(DataTypes::username).as_str() {
            if let Ok((user_id, iota_id, _, _, _, _, _, _, _, _, _, _)) =
                get_by_username(username).await
            {
                if let Ok((iota_id, public_key)) = get_iota_by_id(iota_id).await {
                    let response = self
                        .clone()
                        .build_iota_data_response(
                            cv.get_id(),
                            iota_id,
                            public_key,
                            Some(user_id),
                            Some(username.to_string()),
                        )
                        .await;
                    return self.send(&response).await;
                }
            }
        }

        let response =
            CommunicationValue::new(CommunicationType::error_not_found).with_id(cv.get_id());
        self.send(&response).await
    }

    async fn build_iota_data_response(
        self: Arc<Self>,
        msg_id: u32,
        iota_id: i64,
        public_key: String,
        user_id: Option<i64>,
        username: Option<String>,
    ) -> CommunicationValue {
        let mut response = CommunicationValue::new(CommunicationType::get_iota_data)
            .with_id(msg_id)
            .add_data(DataTypes::public_key, DataValue::Str(public_key))
            .add_data(DataTypes::iota_id, DataValue::Number(iota_id));

        if let Some(uid) = user_id {
            response = response.add_data(DataTypes::user_id, DataValue::Number(uid));
        }
        if let Some(uname) = username {
            response = response.add_data(DataTypes::username, DataValue::Str(uname));
        }

        let iota_connections =
            user_online_tracker::get_iota_omikron_connections(iota_id).unwrap_or_default();

        response.add_data(
            DataTypes::omikron_connections,
            DataValue::Array(
                iota_connections
                    .into_iter()
                    .map(DataValue::Number)
                    .collect(),
            ),
        )
    }

    async fn handle_get_register(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        let register_id = sql::get_register_id().await;
        let response = CommunicationValue::new(CommunicationType::get_register)
            .with_id(cv.get_id())
            .add_data(DataTypes::user_id, DataValue::Number(register_id as i64));
        self.send(&response).await
    }

    async fn handle_complete_register_iota(
        self: Arc<Self>,
        cv: CommunicationValue,
    ) -> OmikronResult<()> {
        let iota_id_opt = cv
            .get_data(DataTypes::iota_id)
            .as_number()
            .map(|n| n as i64);

        if let Some(public_key) = cv.get_data(DataTypes::public_key).as_str() {
            if let Some(iota_id) = iota_id_opt {
                // Register existing IOTA
                match sql::register_complete_iota(iota_id, public_key.to_string()).await {
                    Ok(_) => {
                        let response = CommunicationValue::new(CommunicationType::success)
                            .with_id(cv.get_id());
                        self.send(&response).await
                    }
                    Err(e) => {
                        let response = CommunicationValue::new(CommunicationType::error)
                            .with_id(cv.get_id())
                            .add_data(DataTypes::error_type, DataValue::Str(e.to_string()));
                        self.send(&response).await
                    }
                }
            } else {
                // Create new IOTA
                match sql::create_new_iota(public_key.to_string()).await {
                    Ok(new_iota_id) => {
                        let response =
                            CommunicationValue::new(CommunicationType::complete_register_iota)
                                .with_id(cv.get_id())
                                .add_data(DataTypes::iota_id, DataValue::Number(new_iota_id));
                        self.send(&response).await
                    }
                    Err(e) => {
                        let response = CommunicationValue::new(CommunicationType::error)
                            .with_id(cv.get_id())
                            .add_data(DataTypes::error_type, DataValue::Str(e.to_string()));
                        self.send(&response).await
                    }
                }
            }
        } else {
            self.send_error_response(cv.get_id(), CommunicationType::error_invalid_data)
                .await
        }
    }

    async fn handle_complete_register_user(
        self: Arc<Self>,
        cv: CommunicationValue,
    ) -> OmikronResult<()> {
        let user_id = cv
            .get_data(DataTypes::user_id)
            .as_number()
            .map(|n| n as i64);
        let username = cv
            .get_data(DataTypes::username)
            .as_str()
            .map(|s| s.to_string());
        let public_key = cv
            .get_data(DataTypes::public_key)
            .as_str()
            .map(|s| s.to_string());
        let iota_id = cv
            .get_data(DataTypes::iota_id)
            .as_number()
            .map(|n| n as i64);
        let reset_token = cv
            .get_data(DataTypes::reset_token)
            .as_str()
            .map(|s| s.to_string());

        if let (Some(uid), Some(uname), Some(pk), Some(iid), Some(rt)) =
            (user_id, username, public_key, iota_id, reset_token)
        {
            match sql::register_complete_user(uid, uname, pk, iid, rt).await {
                Ok(_) => {
                    let response =
                        CommunicationValue::new(CommunicationType::success).with_id(cv.get_id());
                    self.send(&response).await
                }
                Err(e) => {
                    let response = CommunicationValue::new(CommunicationType::error)
                        .with_id(cv.get_id())
                        .add_data(DataTypes::error_type, DataValue::Str(e.to_string()));
                    self.send(&response).await
                }
            }
        } else {
            self.send_error_response(cv.get_id(), CommunicationType::error_invalid_data)
                .await
        }
    }

    async fn handle_change_user_data(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        let user_id = cv.get_sender() as i64;
        let mut success = true;
        let mut error_message = String::new();

        // Process each field
        if let Some(username) = cv.get_data(DataTypes::username).as_str() {
            if let Err(e) = sql::change_username(user_id, username.to_string()).await {
                success = false;
                error_message = e.to_string();
            }
        }
        if let Some(display) = cv.get_data(DataTypes::display).as_str() {
            if let Err(e) = sql::change_display_name(user_id, display.to_string()).await {
                success = false;
                error_message = e.to_string();
            }
        }
        if let Some(avatar) = cv.get_data(DataTypes::avatar).as_str() {
            if let Err(e) = sql::change_avatar(user_id, avatar.to_string()).await {
                success = false;
                error_message = e.to_string();
            }
        }
        if let Some(about) = cv.get_data(DataTypes::about).as_str() {
            if let Err(e) = sql::change_about(user_id, about.to_string()).await {
                success = false;
                error_message = e.to_string();
            }
        }
        if let Some(status) = cv.get_data(DataTypes::status).as_str() {
            if let Err(e) = sql::change_status(user_id, status.to_string()).await {
                success = false;
                error_message = e.to_string();
            }
        }
        if let (Some(public_key), Some(private_key_hash)) = (
            cv.get_data(DataTypes::public_key).as_str(),
            cv.get_data(DataTypes::private_key_hash).as_str(),
        ) {
            if let Err(e) = sql::change_keys(
                user_id,
                public_key.to_string(),
                private_key_hash.to_string(),
            )
            .await
            {
                success = false;
                error_message = e.to_string();
            }
        }

        if success {
            let response = CommunicationValue::new(CommunicationType::success).with_id(cv.get_id());
            self.send(&response).await
        } else {
            let response = CommunicationValue::new(CommunicationType::error)
                .with_id(cv.get_id())
                .add_data(DataTypes::error_type, DataValue::Str(error_message));
            self.send(&response).await
        }
    }

    async fn handle_change_iota_data(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        let user_id = cv.get_sender() as i64;

        if let (Some(iota_id), Some(reset_token), Some(new_token)) = (
            cv.get_data(DataTypes::iota_id)
                .as_number()
                .map(|n| n as i64),
            cv.get_data(DataTypes::reset_token).as_str(),
            cv.get_data(DataTypes::new_token).as_str(),
        ) {
            match sql::get_by_user_id(user_id).await {
                Ok(user) => {
                    let current_token = user.11; // reset_token field
                    if current_token == reset_token {
                        let mut success = true;
                        let mut error_message = String::new();

                        if let Err(e) = sql::change_iota_id(user_id, iota_id).await {
                            success = false;
                            error_message = e.to_string();
                        }
                        if success {
                            if let Err(e) = sql::change_token(user_id, new_token.to_string()).await
                            {
                                success = false;
                                error_message = e.to_string();
                            }
                        }

                        if success {
                            let response = CommunicationValue::new(CommunicationType::success)
                                .with_id(cv.get_id());
                            self.send(&response).await
                        } else {
                            let response = CommunicationValue::new(CommunicationType::error)
                                .with_id(cv.get_id())
                                .add_data(DataTypes::error_type, DataValue::Str(error_message));
                            self.send(&response).await
                        }
                    } else {
                        self.send_error_response(
                            cv.get_id(),
                            CommunicationType::error_invalid_challenge,
                        )
                        .await
                    }
                }
                Err(_) => {
                    self.send_error_response(cv.get_id(), CommunicationType::error_not_found)
                        .await
                }
            }
        } else {
            self.send_error_response(cv.get_id(), CommunicationType::error_invalid_data)
                .await
        }
    }

    async fn handle_delete_user(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        let user_id = cv.get_sender() as i64;
        match sql::delete_user(user_id).await {
            Ok(_) => {
                let response =
                    CommunicationValue::new(CommunicationType::success).with_id(cv.get_id());
                self.send(&response).await
            }
            Err(e) => {
                let response = CommunicationValue::new(CommunicationType::error)
                    .with_id(cv.get_id())
                    .add_data(DataTypes::error_type, DataValue::Str(e.to_string()));
                self.send(&response).await
            }
        }
    }

    async fn handle_delete_iota(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        if let Some(iota_id) = cv
            .get_data(DataTypes::iota_id)
            .as_number()
            .map(|n| n as i64)
        {
            match sql::delete_iota(iota_id).await {
                Ok(_) => {
                    let response =
                        CommunicationValue::new(CommunicationType::success).with_id(cv.get_id());
                    self.send(&response).await
                }
                Err(e) => {
                    let response = CommunicationValue::new(CommunicationType::error)
                        .with_id(cv.get_id())
                        .add_data(DataTypes::error_type, DataValue::Str(e.to_string()));
                    self.send(&response).await
                }
            }
        } else {
            self.send_error_response(cv.get_id(), CommunicationType::error_invalid_data)
                .await
        }
    }

    async fn handle_get_notifications(
        self: Arc<Self>,
        cv: CommunicationValue,
    ) -> OmikronResult<()> {
        let user_id = cv.get_sender() as i64;
        if let Ok(notifications) = sql::get_notifications(user_id).await {
            let json_array: Vec<DataValue> = notifications
                .into_iter()
                .map(|(sender, amount)| {
                    DataValue::Container(vec![
                        (DataTypes::sender_id, DataValue::Number(sender)),
                        (DataTypes::amount, DataValue::Number(amount)),
                    ])
                })
                .collect();

            let response = CommunicationValue::new(CommunicationType::get_notifications)
                .with_id(cv.get_id())
                .add_data(DataTypes::notifications, DataValue::Array(json_array));
            self.send(&response).await
        } else {
            Ok(())
        }
    }

    async fn handle_read_notification(
        self: Arc<Self>,
        cv: CommunicationValue,
    ) -> OmikronResult<()> {
        let user_id = cv.get_sender() as i64;
        if let Some(other_id) = cv
            .get_data(DataTypes::sender_id)
            .as_number()
            .map(|n| n as i64)
        {
            if sql::read_notification(user_id, other_id).await.is_ok() {
                let response = CommunicationValue::new(CommunicationType::read_notification)
                    .with_id(cv.get_id());
                self.send(&response).await
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    async fn handle_push_notification(
        self: Arc<Self>,
        cv: CommunicationValue,
    ) -> OmikronResult<()> {
        let user_id = cv.get_sender() as i64;
        if let Some(other_id) = cv
            .get_data(DataTypes::sender_id)
            .as_number()
            .map(|n| n as i64)
        {
            if sql::add_notification(user_id, other_id).await.is_ok() {
                let response = CommunicationValue::new(CommunicationType::push_notification)
                    .with_id(cv.get_id());
                self.send(&response).await
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    async fn handle_ping(self: Arc<Self>, cv: CommunicationValue) -> OmikronResult<()> {
        if let DataValue::Number(last_ping) = cv.get_data(DataTypes::last_ping) {
            *self.ping.write().await = *last_ping;
        }

        let response = CommunicationValue::new(CommunicationType::pong).with_id(cv.get_id());
        self.send(&response).await
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    async fn send(self: Arc<Self>, cv: &CommunicationValue) -> OmikronResult<()> {
        log_cv_out!(PrintType::Omikron, cv);

        let guard = self.sender.lock().await;
        let sender = guard.as_ref().ok_or(OmikronError::NotConnected)?;

        sender
            .send(cv)
            .await
            .map_err(|e| OmikronError::Send(e.to_string()))
    }

    async fn send_error_response(
        self: Arc<Self>,
        message_id: u32,
        error_type: CommunicationType,
    ) -> OmikronResult<()> {
        let error = CommunicationValue::new(error_type).with_id(message_id);
        self.send(&error).await
    }

    pub async fn close(self: Arc<Self>) {}

    async fn cleanup(self: Arc<Self>) {
        if let Some(omikron_id) = self.state.read().await.omikron_id() {
            if omikron_id != 0 {
                log_in!(omikron_id, PrintType::Omega, "Omikron disconnected");
                omikron_manager::remove_omikron(omikron_id).await;
                user_online_tracker::untrack_omikron(omikron_id).await;
            }
        }

        // Cancel cleanup task
        if let Some(handle) = self.cleanup_handle.lock().await.take() {
            handle.abort();
        }
    }

    // Public API for external use
    pub async fn is_authenticated(self: Arc<Self>) -> bool {
        self.state.read().await.is_authenticated()
    }

    pub async fn get_omikron_id(self: Arc<Self>) -> Option<i64> {
        self.state.read().await.omikron_id()
    }

    pub async fn send_message(self: Arc<Self>, cv: &CommunicationValue) -> OmikronResult<()> {
        self.send(cv).await
    }
}

// ============================================================================
// Server Startup
// ============================================================================

pub async fn start(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = load_file_vec("certs", "cert.pem")
        .map_err(|e| format!("Failed to load certificate: {}", e))?;
    let key_pem = load_file_vec("certs", "key.pem")
        .map_err(|e| format!("Failed to load private key: {}", e))?;

    let cert_pem = load_file_vec("certs", "cert.pem").expect("Error loading Pemfile");

    let key_pem = load_file_vec("certs", "key.pem").expect("Error loading Keyfile");

    let mut host: Host = epsilon_native::host(port, cert_pem, key_pem).await?;
    log!("OmikronServer listening on port {}", port);

    while let Some((sender, receiver)) = host.next().await {
        tokio::spawn(async move {
            let conn = OmikronConnection::new(sender);
            conn.handle(receiver).await;
        });
    }

    Ok(())
}
