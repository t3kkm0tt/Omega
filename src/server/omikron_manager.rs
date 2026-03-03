use crate::server::omikron_connection::OmikronConnection;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use rand::prelude::IteratorRandom;
use std::sync::Arc;

pub static OMIKRON_CONNECTIONS: Lazy<DashMap<i64, Arc<OmikronConnection>>> =
    Lazy::new(|| DashMap::new());

pub async fn add_omikron(conn: Arc<OmikronConnection>) {
    let id = match conn.get_omikron_id().await {
        Some(id) => id,
        _ => {
            conn.close().await;
            return;
        }
    };

    if let Some(old) = OMIKRON_CONNECTIONS.insert(id, conn.clone()) {
        old.close().await;
    }
}

pub async fn remove_omikron(omikron_id: i64) {
    OMIKRON_CONNECTIONS.remove(&omikron_id);
}
pub async fn get_random_omikron() -> Result<Arc<OmikronConnection>, ()> {
    let mut rng = rand::thread_rng();

    let keys: Vec<_> = OMIKRON_CONNECTIONS.iter().map(|e| *e.key()).collect();

    if let Some(key) = keys.into_iter().choose(&mut rng) {
        if let Some(entry) = OMIKRON_CONNECTIONS.get(&key) {
            return Ok(entry.clone());
        }
    }

    Err(())
}
