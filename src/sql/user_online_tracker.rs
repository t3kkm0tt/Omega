use crate::sql;
use crate::sql::connection_status::UserStatus;
use dashmap::DashMap;
use once_cell::sync::Lazy;

#[derive(Debug, Clone)]
pub struct UserConnection {
    pub connection_type: UserStatus,
    pub omikron_id: i64,
}

// IotaID -> Primary OmikronID
static IOTA_PRIMARY_OMIKRON_CONNECTION: Lazy<DashMap<i64, i64>> = Lazy::new(DashMap::new);

// IotaID -> Vec<OmikronID>
static IOTA_OMIKRON_CONNECTIONS: Lazy<DashMap<i64, Vec<i64>>> = Lazy::new(DashMap::new);

// UserID -> UserStatus
static USER_STATUS_MAP: Lazy<DashMap<i64, UserConnection>> = Lazy::new(DashMap::new);

pub fn track_iota_connection(iota_id: i64, omikron_id: i64, primary: bool) {
    let mut entry = IOTA_OMIKRON_CONNECTIONS
        .entry(iota_id)
        .or_insert_with(Vec::new);

    if !entry.contains(&omikron_id) {
        entry.push(omikron_id);
    }

    if primary {
        IOTA_PRIMARY_OMIKRON_CONNECTION.insert(iota_id, omikron_id);
    }
}

pub fn untrack_iota_connection(iota_id: i64, omikron_id: i64) -> bool {
    let connections_empty = if let Some(r) = IOTA_OMIKRON_CONNECTIONS.get(&iota_id) {
        let mut vec = r.value().clone();
        vec.retain(|&id| id != omikron_id);
        let empty = vec.is_empty();
        drop(r);
        IOTA_OMIKRON_CONNECTIONS.insert(iota_id, vec);
        empty
    } else {
        false
    };

    if let Some(primary_ref) = IOTA_PRIMARY_OMIKRON_CONNECTION.get(&iota_id) {
        let primary_id = *primary_ref.value();
        drop(primary_ref);
        if primary_id == omikron_id {
            IOTA_PRIMARY_OMIKRON_CONNECTION.remove(&iota_id);
        }
    }

    if connections_empty {
        IOTA_OMIKRON_CONNECTIONS.remove(&iota_id);
    }

    connections_empty
}

pub fn get_iota_primary_omikron_connection(iota_id: i64) -> Option<i64> {
    IOTA_PRIMARY_OMIKRON_CONNECTION.get(&iota_id).map(|v| *v)
}

pub fn get_iota_omikron_connections(iota_id: i64) -> Option<Vec<i64>> {
    IOTA_OMIKRON_CONNECTIONS.get(&iota_id).map(|v| v.clone())
}

pub fn track_user_status(user_id: i64, status: UserStatus, omikron_id: i64) {
    USER_STATUS_MAP.insert(
        user_id,
        UserConnection {
            connection_type: status,
            omikron_id,
        },
    );
}

pub fn get_user_status(user_id: i64) -> Option<UserConnection> {
    USER_STATUS_MAP.get(&user_id).map(|v| v.clone())
}

pub fn untrack_many_users(user_ids: &[i64]) {
    for user_id in user_ids {
        USER_STATUS_MAP.remove(user_id);
    }
}

pub async fn untrack_omikron(omikron_id: i64) {
    let primary_keys_to_remove: Vec<i64> = IOTA_PRIMARY_OMIKRON_CONNECTION
        .iter()
        .filter(|entry| *entry.value() == omikron_id)
        .map(|entry| *entry.key())
        .collect();

    for key in primary_keys_to_remove {
        IOTA_PRIMARY_OMIKRON_CONNECTION.remove(&key);
    }

    let mut offline_iotas = Vec::new();
    let mut primary_to_remove = Vec::new();

    // Collect iotas and primary info first
    for r in IOTA_OMIKRON_CONNECTIONS.iter() {
        let iota_id = *r.key();
        let mut connections = r.value().clone();
        connections.retain(|&id| id != omikron_id);

        if connections.is_empty() {
            offline_iotas.push(iota_id);
        }

        if IOTA_PRIMARY_OMIKRON_CONNECTION
            .get(&iota_id)
            .map(|p| *p == omikron_id)
            .unwrap_or(false)
        {
            primary_to_remove.push(iota_id);
        }

        // Update the connections vector after filtering
        IOTA_OMIKRON_CONNECTIONS.insert(iota_id, connections);
    }

    // Step 2: Remove primary connections safely
    for iota_id in primary_to_remove {
        IOTA_PRIMARY_OMIKRON_CONNECTION.remove(&iota_id);
    }

    // Step 3: Remove users that were on this omikron
    USER_STATUS_MAP.retain(|_, status| status.omikron_id != omikron_id);

    // Step 4: For offline iotas, remove associated users from USER_STATUS_MAP
    for iota_id in offline_iotas {
        if let Ok(users) = sql::sql::get_users_by_iota_id(iota_id).await {
            for user in users {
                USER_STATUS_MAP.remove(&user.0);
            }
        }
        // Finally remove the empty connections vector
        IOTA_OMIKRON_CONNECTIONS.remove(&iota_id);
    }
}
