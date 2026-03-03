use crate::get_public_key;
use crate::server::omikron_manager::get_random_omikron;
use crate::sql::sql;
use crate::sql::user_online_tracker::get_iota_primary_omikron_connection;
use crate::{
    sql::sql::{get_by_user_id, get_omikron_by_id},
    util::crypto_helper::public_key_to_base64,
};
use actix_web::HttpResponse;
use actix_web::http::{StatusCode, header};
use base64::Engine as _;
use json::JsonValue;

pub async fn handle(path: &str, body_string: Option<String>) -> HttpResponse {
    if path == "OPTIONS" {
        return HttpResponse::Ok()
            .insert_header(("Access-Control-Allow-Origin", "*"))
            .insert_header(("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
            .insert_header(("Access-Control-Allow-Headers", "*"))
            .finish();
    }

    let path_parts: Vec<&str> = path.split("/").filter(|s| !s.is_empty()).collect();

    let _body: Option<JsonValue> = if body_string.is_some() {
        if let Ok(body_json) = json::parse(&body_string.unwrap()) {
            Some(body_json)
        } else {
            None
        }
    } else {
        None
    };

    let (status, body_text) = match path_parts.as_slice() {
        // ==================================================
        // DOWNLOAD IOTA FRONTEND
        // ==================================================
        ["api", "download", "iota_frontend"] => {
            let file_path = "downloads/[iota_frontend].zip";

            match std::fs::read(file_path) {
                Ok(file_bytes) => {
                    return HttpResponse::Ok()
                        .insert_header(("Access-Control-Allow-Origin", "*"))
                        .insert_header(("Content-Type", "application/zip"))
                        .insert_header((
                            "Content-Disposition",
                            "attachment; filename=\"iota_frontend.zip\"",
                        ))
                        .body(file_bytes);
                }
                Err(_) => {
                    let mut res = JsonValue::new_object();
                    res["status"] = "error_not_found".into();
                    return HttpResponse::NotFound()
                        .insert_header(("Access-Control-Allow-Origin", "*"))
                        .body(res.dump());
                }
            }
        }

        // ==================================================
        // GET RANDOM OMIKRON
        // ==================================================
        ["api", "get", "omikron"] => {
            if let Ok(omikron_conn) = get_random_omikron().await {
                if let Some(id) = omikron_conn.get_omikron_id().await {
                    if let Ok((public_key, ip_address)) = sql::get_omikron_by_id(id).await {
                        let mut res = JsonValue::new_object();
                        res["status"] = "success".into();
                        res["id"] = id.into();
                        res["public_key"] = public_key.into();
                        res["ip_address"] = ip_address.into();

                        (StatusCode::OK, res.dump())
                    } else {
                        let mut res = JsonValue::new_object();
                        res["status"] = "error".into();
                        (StatusCode::INTERNAL_SERVER_ERROR, res.dump())
                    }
                } else {
                    let mut res = JsonValue::new_object();
                    res["status"] = "error".into();
                    (StatusCode::INTERNAL_SERVER_ERROR, res.dump())
                }
            } else {
                let mut res = JsonValue::new_object();
                res["status"] = "error_not_found".into();
                (StatusCode::NOT_FOUND, res.dump())
            }
        }

        // ==================================================
        // GET OMIKRON BY ID
        // ==================================================
        ["api", "get", "omikron", id] => {
            let id = id.parse::<i64>().unwrap_or(0);

            if id == 0 {
                let mut res = JsonValue::new_object();
                res["status"] = "error_bad_request".into();
                (StatusCode::BAD_REQUEST, res.dump())
            } else if let Ok((public_key, ip_address)) = get_omikron_by_id(id).await {
                let mut res = JsonValue::new_object();
                res["status"] = "success".into();
                res["id"] = id.into();
                res["public_key"] = public_key.into();
                res["ip_address"] = ip_address.into();
                (StatusCode::OK, res.dump())
            } else if let Some(omikron_id) = get_iota_primary_omikron_connection(id) {
                if let Ok((public_key, ip_address)) = get_omikron_by_id(omikron_id).await {
                    let mut res = JsonValue::new_object();
                    res["status"] = "success".into();
                    res["id"] = omikron_id.into();
                    res["public_key"] = public_key.into();
                    res["ip_address"] = ip_address.into();
                    (StatusCode::OK, res.dump())
                } else {
                    let mut res = JsonValue::new_object();
                    res["status"] = "error_not_found".into();
                    (StatusCode::NOT_FOUND, res.dump())
                }
            } else if let Ok((_, iota_id, _, _, _, _, _, _, _, _, _, _)) = get_by_user_id(id).await
            {
                if let Some(omikron_id) = get_iota_primary_omikron_connection(iota_id) {
                    if let Ok((public_key, ip_address)) = get_omikron_by_id(omikron_id).await {
                        let mut res = JsonValue::new_object();
                        res["status"] = "success".into();
                        res["id"] = omikron_id.into();
                        res["public_key"] = public_key.into();
                        res["ip_address"] = ip_address.into();
                        (StatusCode::OK, res.dump())
                    } else {
                        let mut res = JsonValue::new_object();
                        res["status"] = "error_not_found".into();
                        (StatusCode::NOT_FOUND, res.dump())
                    }
                } else {
                    let mut res = JsonValue::new_object();
                    res["status"] = "error_not_found".into();
                    (StatusCode::NOT_FOUND, res.dump())
                }
            } else {
                let mut res = JsonValue::new_object();
                res["status"] = "error_not_found".into();
                (StatusCode::NOT_FOUND, res.dump())
            }
        }

        // ==================================================
        // GET ID BY USERNAME
        // ==================================================
        ["api", "get", "id", username] => {
            if username.is_empty() {
                let mut res = JsonValue::new_object();
                res["status"] = "error_bad_request".into();
                (StatusCode::BAD_REQUEST, res.dump())
            } else if let Ok((
                id,
                iota_id,
                username,
                _,
                _,
                _,
                _,
                sub_level,
                sub_end,
                public_key,
                _,
                _,
            )) = sql::get_by_username(username).await
            {
                let mut res = JsonValue::new_object();
                res["status"] = "success".into();
                res["username"] = username.into();
                res["public_key"] = public_key.into();
                res["user_id"] = id.into();
                res["iota_id"] = iota_id.into();
                res["sub_level"] = sub_level.into();
                res["sub_end"] = sub_end.into();

                (StatusCode::OK, res.dump())
            } else {
                let mut res = JsonValue::new_object();
                res["status"] = "error_not_found".into();
                (StatusCode::OK, res.dump())
            }
        }

        // ==================================================
        // GET SERVER PUBLIC KEY
        // ==================================================
        ["api", "get", "public_key"] => {
            let mut res = JsonValue::new_object();
            res["status"] = "success".into();
            res["public_key"] = public_key_to_base64(&get_public_key()).into();
            (StatusCode::OK, res.dump())
        }

        // ==================================================
        // GET USER BY ID
        // ==================================================
        ["api", "get", "user", id] => {
            let id: i64 = id.parse().unwrap_or(0);

            if id == 0 {
                let mut res = JsonValue::new_object();
                res["status"] = "error_bad_request".into();
                (StatusCode::BAD_REQUEST, res.dump())
            } else if let Ok((
                id,
                iota_id,
                username,
                display,
                status_msg,
                about,
                avatar,
                sub_level,
                sub_end,
                public_key,
                _,
                _,
            )) = sql::get_by_user_id(id).await
            {
                let mut res = JsonValue::new_object();
                res["status"] = "success".into();
                res["username"] = username.into();
                res["public_key"] = public_key.into();
                res["user_id"] = id.into();
                res["iota_id"] = iota_id.into();
                res["sub_level"] = sub_level.into();
                res["sub_end"] = sub_end.into();

                if let Some(display) = display {
                    res["display"] = display.into();
                }
                if let Some(status_msg) = status_msg {
                    res["status_message"] = status_msg.into();
                }
                if let Some(about) = about {
                    res["about"] = about.into();
                }
                if let Some(avatar) = avatar {
                    res["avatar"] = base64::engine::general_purpose::STANDARD
                        .encode(avatar)
                        .into();
                }

                (StatusCode::OK, res.dump())
            } else {
                let mut res = JsonValue::new_object();
                res["status"] = "error_not_found".into();
                (StatusCode::OK, res.dump())
            }
        }

        // ==================================================
        // DEFAULT
        // ==================================================
        _ => {
            let mut res = JsonValue::new_object();
            res["status"] = "error".into();
            (StatusCode::INTERNAL_SERVER_ERROR, res.dump())
        }
    };
    let body_bytes = body_text.into_bytes();

    HttpResponse::build(status)
        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
        .insert_header((header::ACCESS_CONTROL_ALLOW_HEADERS, "*"))
        .insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"))
        .body(body_bytes)
}

pub fn bad_request() -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, "400 Bad Request".to_string())
}
pub fn not_found() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, "404 Not Found".to_string())
}
