use crate::server::{omikron_manager, short_link::add_short_link};
use crate::sql::{sql, sql::get_omikron_by_id, user_online_tracker};
use crate::util::file_util::load_file_vec;
use crate::util::{crypto_helper::encrypt, logger::PrintType};
use crate::{get_private_key, get_public_key, log_cv_in, log_cv_out, log_in};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use dashmap::DashMap;
use epsilon_core::{CommunicationType, CommunicationValue, DataTypes, DataValue};
use epsilon_native::{Receiver, Sender, host};
use quinn::ServerConfig;
use quinn::crypto::rustls::QuicServerConfig;
use rand::{Rng, distributions::Alphanumeric};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::sync::RwLock;
use x448::PublicKey;

pub struct OmikronServer;

impl OmikronServer {
    pub async fn start(port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let tls_cfg = OmikronServer::load_tls().expect("TLS config failed");
        let server_crypto =
            QuicServerConfig::try_from(tls_cfg).expect("Failed to convert to QuicServerConfig");
        let mut host = host(port, ServerConfig::with_crypto(Arc::new(server_crypto))).await?;
        tokio::spawn(async move {
            while let Some((sender, receiver)) = host.next().await {
                let connection = OmikronConnection::new(sender);
                tokio::spawn(Self::connection_loop(connection, receiver));
            }
        });

        Ok(())
    }
    fn load_tls() -> Option<rustls::ServerConfig> {
        let cert_bytes = load_file_vec("certs", "cert.der").ok()?;
        let key_bytes = load_file_vec("certs", "key.der").ok()?;

        let cert_chain = vec![CertificateDer::from(cert_bytes)];
        let private_key = PrivateKeyDer::try_from(key_bytes).ok()?;

        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .ok()?;

        Some(cfg)
    }

    async fn connection_loop(conn: Arc<OmikronConnection>, receiver: Receiver) {
        while let Ok(cv) = receiver.receive().await {
            log_cv_in!(PrintType::Omikron, cv);
            conn.clone().handle_message(cv).await;
        }

        conn.handle_close().await;
    }
}

pub struct OmikronConnection {
    sender: Arc<RwLock<Option<Sender>>>,
    omikron_id: Arc<RwLock<i64>>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,

    identified: Arc<RwLock<bool>>,
    challenged: Arc<RwLock<bool>>,
    challenge: Arc<RwLock<String>>,

    ping: Arc<RwLock<i64>>,

    waiting_tasks:
        DashMap<u32, Box<dyn Fn(Arc<OmikronConnection>, CommunicationValue) -> bool + Send + Sync>>,
}

impl OmikronConnection {
    pub fn new(sender: Sender) -> Arc<Self> {
        Arc::new(Self {
            sender: Arc::new(RwLock::new(Some(sender))),
            omikron_id: Arc::new(RwLock::new(0)),
            pub_key: Arc::new(RwLock::new(None)),
            identified: Arc::new(RwLock::new(false)),
            challenged: Arc::new(RwLock::new(false)),
            challenge: Arc::new(RwLock::new(String::new())),
            ping: Arc::new(RwLock::new(-1)),
            waiting_tasks: DashMap::new(),
        })
    }

    async fn send(&self, cv: &CommunicationValue) {
        log_cv_out!(PrintType::Omikron, cv);

        if let Some(sender) = self.sender.read().await.as_ref() {
            if sender.send(cv).await.is_err() {
                self.handle_close().await;
            }
        }
    }

    async fn send_error_response(&self, id: u32, comm_type: CommunicationType) {
        let response = CommunicationValue::new(comm_type).with_id(id);
        self.send(&response).await;
    }

    pub async fn get_omikron_id(&self) -> i64 {
        *self.omikron_id.read().await
    }

    async fn is_identified(&self) -> bool {
        *self.identified.read().await && *self.challenged.read().await
    }

    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        if cv.is_type(CommunicationType::ping) {
            self.handle_ping(cv).await;
            return;
        }

        if let Some((_, task)) = self.waiting_tasks.remove(&cv.get_id()) {
            let _ = task(self.clone(), cv.clone());
            return;
        }

        if !self.is_identified().await {
            self.handle_identification(cv).await;
            return;
        }

        self.handle_authenticated(cv).await;
    }

    async fn handle_identification(self: &Arc<Self>, cv: CommunicationValue) {
        let identified = *self.identified.read().await;
        let challenged = *self.challenged.read().await;

        if !identified && cv.is_type(CommunicationType::identification) {
            let omikron_id = cv.get_data(DataTypes::omikron).as_number().unwrap_or(0);

            let (public_key, _) = match get_omikron_by_id(omikron_id).await {
                Ok(v) => v,
                Err(_) => {
                    let _ = self
                        .send(
                            &CommunicationValue::new(CommunicationType::error_not_authenticated)
                                .with_id(cv.get_id()),
                        )
                        .await;
                    return;
                }
            };

            let pub_key_bytes = match STANDARD.decode(&public_key) {
                Ok(b) => b,
                Err(_) => {
                    let _ = self
                        .send(
                            &CommunicationValue::new(CommunicationType::error_invalid_omikron_id)
                                .with_id(cv.get_id()),
                        )
                        .await;
                    return;
                }
            };

            let omikron_pub_key = match PublicKey::from_bytes(&pub_key_bytes) {
                Some(k) => k,
                _ => {
                    let _ = self
                        .send(
                            &CommunicationValue::new(CommunicationType::error_invalid_public_key)
                                .with_id(cv.get_id()),
                        )
                        .await;
                    return;
                }
            };

            let challenge: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();

            *self.omikron_id.write().await = omikron_id;
            *self.challenge.write().await = challenge.clone();
            *self.pub_key.write().await = Some(pub_key_bytes);
            *self.identified.write().await = true;

            let encrypted =
                encrypt(get_private_key(), omikron_pub_key, &challenge).unwrap_or_default();

            let response = CommunicationValue::new(CommunicationType::challenge)
                .with_id(cv.get_id())
                .add_data(
                    DataTypes::public_key,
                    DataValue::Str(STANDARD.encode(get_public_key().as_bytes())),
                )
                .add_data(DataTypes::challenge, DataValue::Str(encrypted));

            let _ = self.send(&response).await;
            return;
        }

        if identified && !challenged && cv.is_type(CommunicationType::challenge_response) {
            let client_response = cv.get_data(DataTypes::challenge).as_str().unwrap_or("");

            if client_response == *self.challenge.read().await {
                *self.challenged.write().await = true;

                omikron_manager::add_omikron(self.clone()).await;

                let _ = self
                    .send(
                        &CommunicationValue::new(CommunicationType::identification_response)
                            .with_id(cv.get_id())
                            .add_data(DataTypes::accepted, DataValue::BoolTrue),
                    )
                    .await;

                log_in!(PrintType::Omega, "Omikron Connected");
            } else {
                let _ = self
                    .send(
                        &CommunicationValue::new(CommunicationType::error_invalid_challenge)
                            .with_id(cv.get_id()),
                    )
                    .await;
            }
        }
    }

    async fn handle_authenticated(self: &Arc<Self>, cv: CommunicationValue) {
        if cv.is_type(CommunicationType::shorten_link) {
            if let Some(link) = cv.get_data(DataTypes::link).as_str() {
                if let Ok(short) = add_short_link(link).await {
                    let _ = self
                        .send(
                            &CommunicationValue::new(CommunicationType::shorten_link)
                                .with_id(cv.get_id())
                                .add_data(DataTypes::link, DataValue::Str(short)),
                        )
                        .await;
                }
            }
            return;
        }

        if cv.is_type(CommunicationType::get_register) {
            let register_id = sql::get_register_id().await;
            let _ = self
                .send(
                    &CommunicationValue::new(CommunicationType::get_register)
                        .with_id(cv.get_id())
                        .add_data(DataTypes::user_id, DataValue::Number(register_id as i64)),
                )
                .await;
            return;
        }

        if cv.is_type(CommunicationType::delete_user) {
            let user_id = cv.get_sender();
            match sql::delete_user(user_id as i64).await {
                Ok(_) => {
                    let _ = self
                        .send(
                            &CommunicationValue::new(CommunicationType::success)
                                .with_id(cv.get_id()),
                        )
                        .await;
                }
                Err(e) => {
                    let _ = self
                        .send(
                            &CommunicationValue::new(CommunicationType::error)
                                .with_id(cv.get_id())
                                .add_data(DataTypes::error_type, DataValue::Str(e.to_string())),
                        )
                        .await;
                }
            }
            return;
        }

        if cv.is_type(CommunicationType::delete_iota) {
            if let DataValue::Number(iota_id) = cv.get_data(DataTypes::iota_id) {
                match sql::delete_iota(*iota_id).await {
                    Ok(_) => {
                        let response = CommunicationValue::new(CommunicationType::success)
                            .with_id(cv.get_id());
                        self.send(&response).await;
                    }
                    Err(e) => {
                        self.send(
                            &CommunicationValue::new(CommunicationType::error)
                                .with_id(cv.get_id())
                                .add_data(DataTypes::error_type, DataValue::Str(e.to_string())),
                        )
                        .await;
                    }
                }
            } else {
                self.send_error_response(cv.get_id(), CommunicationType::error_invalid_data)
                    .await;
            }
            return;
        }

        // NOTIFICATIONS
        if cv.is_type(CommunicationType::get_notifications) {
            let user_id = cv.get_sender();
            if let Ok(notifications) = sql::get_notifications(user_id as i64).await {
                let mut json_array = Vec::new();
                for (sender, amount) in notifications {
                    let mut obj = Vec::new();
                    let _ = obj.push((DataTypes::sender_id, DataValue::Number(sender)));
                    let _ = obj.push((DataTypes::amount, DataValue::Number(amount)));
                    json_array.push(DataValue::Container(obj));
                }
                let response = CommunicationValue::new(CommunicationType::get_notifications)
                    .with_id(cv.get_id())
                    .add_data(DataTypes::notifications, DataValue::Array(json_array));
                self.send(&response).await;
            }
        }
        if cv.is_type(CommunicationType::read_notification) {
            if let (user_id, Some(other_id)) = (
                cv.get_sender(),
                cv.get_data(DataTypes::sender_id).as_number(),
            ) {
                if let Ok(_) = sql::read_notification(user_id as i64, other_id).await {
                    let response = CommunicationValue::new(CommunicationType::read_notification)
                        .with_id(cv.get_id());
                    self.send(&response).await;
                }
            }
        }
        if cv.is_type(CommunicationType::push_notification) {
            if let (user_id, Some(other_id)) = (
                cv.get_sender(),
                cv.get_data(DataTypes::sender_id).as_number(),
            ) {
                if let Ok(_) = sql::add_notification(user_id as i64, other_id).await {
                    let response = CommunicationValue::new(CommunicationType::push_notification)
                        .with_id(cv.get_id());
                    self.send(&response).await;
                }
            }
        }
    }

    async fn handle_ping(&self, cv: CommunicationValue) {
        if let DataValue::Number(last_ping) = cv.get_data(DataTypes::last_ping) {
            if let Ok(val) = last_ping.to_string().parse::<i64>() {
                *self.ping.write().await = val;
            }
        }

        let _ = self
            .send(&CommunicationValue::new(CommunicationType::pong).with_id(cv.get_id()))
            .await;
    }

    pub async fn handle_close(&self) {
        if self.is_identified().await {
            let omikron_id = self.get_omikron_id().await;

            if omikron_id != 0 {
                log_in!(PrintType::Omega, "Omikron Disconnected");

                omikron_manager::remove_omikron(omikron_id).await;
                user_online_tracker::untrack_omikron(omikron_id).await;
            }
        }
    }
}
