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
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde_json::json;
use sha2::Sha256;
use tokio::{process::Command, spawn};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct HaibiChanState {
    /// the secret we use to verify that GitHub is calling our service and not some evil leet haxor
    github_secret: String,
    /// the URL we use to report our actions to our channel on Discord
    discord_webhook: String,
}

#[tokio::main]
async fn main() {
    // Load secrets from environment
    let github_secret =
        std::env::var("GITHUB_WEBHOOK_SECRET").expect("GITHUB_WEBHOOK_SECRET must be set");
    let discord_webhook =
        std::env::var("DISCORD_WEBHOOK_URL").expect("DISCORD_WEBHOOK_URL must be set");
    let state = HaibiChanState {
        github_secret,
        discord_webhook,
    };

    // Build the app with a shared secret
    let app = Router::new()
        .route("/webhook", post(handle_webhook))
        .with_state(state);

    // Bind the port we want to listen on for webhook requests
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    println!("Listening for GitHub package webhooks on {}", addr);

    // Start the service
    axum::serve(listener, app).await.unwrap();
}

async fn handle_webhook(
    headers: HeaderMap,
    State(state): State<HaibiChanState>,
    payload: Bytes,
) -> impl IntoResponse {
    let secret = state.github_secret;
    let discord_webhook = state.discord_webhook;
    // 1) Verify signature header
    let signature = match headers.get("x-hub-signature-256") {
        Some(sig) => sig.to_str().unwrap_or_default(),
        None => return (StatusCode::UNAUTHORIZED, "Missing signature"),
    };

    if !verify_signature(secret.as_bytes(), &payload, signature) {
        return (StatusCode::UNAUTHORIZED, "Invalid signature");
    }

    // 2) Check GitHub event type
    if let Some(event) = headers.get("x-github-event").and_then(|v| v.to_str().ok()) {
        if event == "package" {
            let webhook_url = discord_webhook.clone();

            // Spawn deploy + notify task
            spawn(async move {
                // Deploy steps
                let _ = Command::new("sh")
                    .arg("-c")
                    .arg("docker compose up -d --pull always --no-deps --force-recreate game")
                    .current_dir("/home/linuxuser/vultr/infra")
                    .status()
                    .await;

                // Notify Discord
                let client = Client::new();
                let _ = client
                    .post(&webhook_url)
                    .json(&json!({
                        "content": "🚀 Haibi-chan has deployed a new version of PeraPera Quest!"
                    }))
                    .send()
                    .await;
            });

            return (StatusCode::OK, "Deploy and notification triggered");
        }
    }

    (StatusCode::BAD_REQUEST, "Unhandled event")
}

/// Verifies HMAC-SHA256 signature against the payload
fn verify_signature(secret: &[u8], payload: &[u8], signature: &str) -> bool {
    let parts: Vec<&str> = signature.splitn(2, '=').collect();
    if parts.len() != 2 || parts[0] != "sha256" {
        return false;
    }
    let expected = hex::decode(parts[1]).unwrap_or_default();
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(payload);
    mac.verify_slice(&expected).is_ok()
}
