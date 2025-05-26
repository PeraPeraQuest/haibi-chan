// main.rs
// Copyright 2025 Patrick Meade
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use axum_server::tls_rustls::RustlsConfig;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde_json::{Value, json};
use sha2::Sha256;
use std::{net::SocketAddr, time::SystemTime};
use tokio::{process::Command, spawn};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct HaibiChanState {
    /// the URL we use to report our actions to our channel on Discord
    discord_webhook: String,
    /// the secret we use to verify that GitHub is calling our service and not some evil leet haxor
    github_secret: String,
}

#[tokio::main]
async fn main() {
    // Startup logging
    println!("[{:?}] Haibi-chan starting up...", SystemTime::now());

    // Load secrets from environment
    let discord_webhook =
        std::env::var("DISCORD_WEBHOOK_URL").expect("DISCORD_WEBHOOK_URL must be set");
    let github_secret =
        std::env::var("GITHUB_WEBHOOK_SECRET").expect("GITHUB_WEBHOOK_SECRET must be set");
    println!("[{:?}] Loaded environment secrets", SystemTime::now());
    let state = HaibiChanState {
        discord_webhook,
        github_secret,
    };

    // Load SSL certificate into TLS configuration
    let cert_path = std::env::var("SSL_CERT_PATH").expect("SSL_CERT_PATH must be set");
    let key_path = std::env::var("SSL_KEY_PATH").expect("SSL_KEY_PATH must be set");
    let tls = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .expect("Failed to load TLS certificates");
    println!("[{:?}] TLS configuration loaded", SystemTime::now());

    // Build the app
    let app = Router::new()
        .route("/webhook", post(handle_webhook))
        .with_state(state.clone());

    // Bind and serve
    let addr: SocketAddr = std::env::var("BIND_ADDRESS_AND_PORT")
        .unwrap()
        .parse()
        .unwrap();
    println!(
        "[{:?}] Listening for GitHub package webhooks on {}",
        SystemTime::now(),
        addr
    );

    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

/// Handle GitHub package webhooks, only deploying when `latest` tag is published
async fn handle_webhook(
    headers: HeaderMap,
    State(state): State<HaibiChanState>,
    payload: Bytes,
) -> impl IntoResponse {
    // log the full webhook payload to stderr to cut down on noise on stdout
    let now = SystemTime::now();
    eprintln!(
        "[{:?}] Received webhook payload: {}",
        now,
        String::from_utf8_lossy(&payload)
    );

    // Verify signature
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if signature.is_empty()
        || !verify_signature(state.github_secret.as_bytes(), &payload, signature)
    {
        eprintln!("[{:?}] Invalid or missing signature: {}", now, signature);
        return (StatusCode::UNAUTHORIZED, "Invalid or missing signature");
    }
    println!("[{:?}] Signature verified successfully", SystemTime::now());

    // Only handle package events
    let event_type = headers
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if event_type != "package" {
        println!(
            "[{:?}] Unsupported event type: {}",
            SystemTime::now(),
            event_type
        );
        return (StatusCode::BAD_REQUEST, "Unsupported event");
    }
    println!("[{:?}] Handling 'package' event", SystemTime::now());

    // Parse JSON payload
    let v: Value = match serde_json::from_slice(&payload) {
        Ok(val) => val,
        Err(err) => {
            eprintln!(
                "[{:?}] Failed to parse JSON payload: {:?}",
                SystemTime::now(),
                err
            );
            return (StatusCode::BAD_REQUEST, "Invalid JSON payload");
        }
    };
    println!("[{:?}] JSON payload parsed", SystemTime::now());

    // Check action is 'published'
    if v.get("action").and_then(Value::as_str) != Some("published") {
        println!(
            "[{:?}] Ignoring non-published action: {:?}",
            SystemTime::now(),
            v.get("action")
        );
        return (StatusCode::OK, "Ignoring non-published action");
    }
    println!("[{:?}] Action 'published' detected", SystemTime::now());

    // Check tag name == "latest"
    let tag_name = v
        .pointer("/package/package_version/container_metadata/tag/name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if tag_name != "latest" {
        println!(
            "[{:?}] Ignoring non-latest tag: {}",
            SystemTime::now(),
            tag_name
        );
        return (StatusCode::OK, "Ignoring non-latest tag");
    }
    println!(
        "[{:?}] 'latest' tag detected, triggering deploy",
        SystemTime::now()
    );

    // Spawn deploy + notify
    let webhook_url = state.discord_webhook.clone();
    spawn(async move {
        let start = SystemTime::now();
        println!("[{:?}] Starting deployment process...", start);

        // Deploy via docker-compose
        match Command::new("sh")
            .arg("-c")
            .arg("docker compose up -d --pull always --no-deps --force-recreate game")
            .current_dir("/home/linuxuser/vultr/infra")
            .status()
            .await
        {
            Ok(status) => println!(
                "[{:?}] Deploy command finished with status: {:?}",
                SystemTime::now(),
                status
            ),
            Err(err) => eprintln!("[{:?}] Deploy command failed: {:?}", SystemTime::now(), err),
        }

        // Notify Discord
        println!("[{:?}] Sending Discord notification...", SystemTime::now());
        match Client::new()
            .post(&webhook_url)
            .json(&json!({"content": "Haibi-chan has deployed a new version of PeraPera Quest!"}))
            .send()
            .await
        {
            Ok(resp) => println!("[{:?}] Discord notification sent with status: {}", SystemTime::now(), resp.status()),
            Err(err) => eprintln!("[{:?}] Failed to send Discord notification: {:?}", SystemTime::now(), err),
        }
    });

    (StatusCode::OK, "Latest deployment triggered")
}

/// Verifies HMAC-SHA256 signature against the payload
fn verify_signature(secret: &[u8], payload: &[u8], signature: &str) -> bool {
    let parts: Vec<&str> = signature.splitn(2, '=').collect();
    if parts.len() != 2 || parts[0] != "sha256" {
        return false;
    }
    let expected = hex::decode(parts[1]).unwrap_or_default();
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(payload);
    mac.verify_slice(&expected).is_ok()
}
