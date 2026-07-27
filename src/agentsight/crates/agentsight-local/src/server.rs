//! HTTP API server + embedded frontend for local agent trajectory viewing.
//!
//! Simplified server: no AppState, no HealthChecker, no SQLite. Serves the
//! local-session discovery/conversion API and an embedded frontend dashboard.

mod agents;
mod local_sessions;
mod trajectories;

use actix_cors::Cors;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, get, web};
use agentsight_trajectory_collector::{CollectorConfig, TrajectoryStore, run_collector_loop};
use include_dir::{Dir, include_dir};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Embedded frontend static files (built from dashboard/ via `npm run build:embed`)
/// Output goes to the agentsight crate root's `frontend-dist/` directory.
/// When absent (e.g. first build before running npm), include_dir! embeds an
/// empty dir and the server prints a warning.
static FRONTEND: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../../frontend-dist");

// ─── Static file handler ─────────────────────────────────────────────────────

// ─── Stub endpoints for macOS ───────────────────────────────────────────────
//
// The main dashboard frontend calls many Linux-only endpoints (sessions,
// auth, interruptions, etc.) that have no data on macOS. These stubs return
// correctly-shaped empty responses so the frontend doesn't crash.

/// GET /api/auth/status — macOS has no auth gate
#[get("/api/auth/status")]
async fn auth_status() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"auth_enabled": false}))
}

/// GET /api/auth/verify — always authenticated on macOS
#[get("/api/auth/verify")]
async fn auth_verify() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"authenticated": true}))
}

/// GET /api/sessions — no eBPF sessions on macOS
#[get("/api/sessions")]
async fn list_sessions() -> impl Responder {
    HttpResponse::Ok().json(Vec::<serde_json::Value>::new())
}

/// GET /api/agent-names — empty on macOS
#[get("/api/agent-names")]
async fn list_agent_names() -> impl Responder {
    HttpResponse::Ok().json(Vec::<String>::new())
}

/// GET /api/timeseries — empty on macOS
#[get("/api/timeseries")]
async fn list_timeseries() -> impl Responder {
    HttpResponse::Ok().json(Vec::<serde_json::Value>::new())
}

/// GET /api/token-savings — null on macOS
#[get("/api/token-savings")]
async fn token_savings() -> impl Responder {
    HttpResponse::Ok().json(serde_json::Value::Null)
}

/// GET /api/interruptions — empty array on macOS
#[get("/api/interruptions")]
async fn list_interruptions() -> impl Responder {
    HttpResponse::Ok().json(Vec::<serde_json::Value>::new())
}

/// GET /api/interruptions/count — empty object on macOS
#[get("/api/interruptions/count")]
async fn interruption_count() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({}))
}

/// GET /api/interruptions/stats — empty array on macOS
#[get("/api/interruptions/stats")]
async fn interruption_stats() -> impl Responder {
    HttpResponse::Ok().json(Vec::<serde_json::Value>::new())
}

/// GET /api/interruptions/session-counts — empty array on macOS
#[get("/api/interruptions/session-counts")]
async fn interruption_session_counts() -> impl Responder {
    HttpResponse::Ok().json(Vec::<serde_json::Value>::new())
}

/// GET /api/interruptions/conversation-counts — empty array on macOS
#[get("/api/interruptions/conversation-counts")]
async fn interruption_conversation_counts() -> impl Responder {
    HttpResponse::Ok().json(Vec::<serde_json::Value>::new())
}

/// GET /api/security/status — empty on macOS
#[get("/api/security/status")]
async fn security_status() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({}))
}

/// GET /api/security/summary — empty on macOS
#[get("/api/security/summary")]
async fn security_summary() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({}))
}

/// GET /api/skill-metrics — empty array on macOS
#[get("/api/skill-metrics")]
async fn skill_metrics() -> impl Responder {
    HttpResponse::Ok().json(Vec::<serde_json::Value>::new())
}

/// GET /api/agent-health — empty array on macOS
#[get("/api/agent-health")]
async fn agent_health() -> impl Responder {
    HttpResponse::Ok().json(Vec::<serde_json::Value>::new())
}

/// Catch-all for any other unregistered /api/* path — returns empty array
/// to avoid breaking frontend list iteration.
#[get("/api/{tail:.*}")]
async fn api_fallback() -> impl Responder {
    HttpResponse::Ok().json(Vec::<serde_json::Value>::new())
}

/// Serve embedded frontend files.
/// Any path that doesn't start with /api is treated as a static asset;
/// unknown paths fall back to index.html (SPA client-side routing).
#[get("/{tail:.*}")]
async fn serve_frontend(req: HttpRequest) -> impl Responder {
    let path = req.match_info().get("tail").unwrap_or("");

    // Try exact match first
    let file = if path.is_empty() {
        FRONTEND.get_file("index.html")
    } else {
        FRONTEND.get_file(path)
    };

    match file {
        Some(f) => {
            let mime = if path.is_empty() {
                "text/html; charset=utf-8"
            } else {
                mime_for_path(path)
            };
            HttpResponse::Ok().content_type(mime).body(f.contents())
        }
        None => {
            // SPA fallback: return index.html for unmatched paths
            match FRONTEND.get_file("index.html") {
                Some(index) => HttpResponse::Ok()
                    .content_type("text/html; charset=utf-8")
                    .body(index.contents()),
                None => HttpResponse::NotFound()
                    .body("Frontend not embedded. Run `npm run build:embed` first."),
            }
        }
    }
}

fn mime_for_path(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else {
        "application/octet-stream"
    }
}

// ─── Server entry point ───────────────────────────────────────────────────────

/// Start the API server.
///
/// Binds to the given host:port and serves local-session API endpoints + the
/// embedded frontend. Blocks until the server is shut down.
pub async fn run_server(host: &str, port: u16) -> std::io::Result<()> {
    let has_frontend = FRONTEND.get_file("index.html").is_some();
    log::info!(
        "agentsight-local server listening on http://{}:{}",
        host,
        port
    );
    eprintln!(
        "agentsight-local server listening on http://{}:{}",
        host, port
    );
    if has_frontend {
        eprintln!("Dashboard UI: http://{}:{}/", host, port);
    } else {
        eprintln!(
            "[WARN] Frontend not embedded. Run `npm run build:embed` in dashboard/ then recompile."
        );
    }

    // Initialize trajectory store and run a collection scan
    let db_path = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("agentsight")
        .join("trajectories.db");
    let store = TrajectoryStore::new_with_path(&db_path).ok();

    if let Some(ref s) = store {
        let config = CollectorConfig {
            scan_interval_secs: 300,
            scan_dirs: None,
            db_path: db_path.clone(),
        };
        agentsight_trajectory_collector::scan_once(s, &config);
        eprintln!("Trajectory scan complete. DB: {}", db_path.display());

        // Background periodic scan
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        std::thread::spawn(move || {
            run_collector_loop(&config, &stop_clone);
        });
    }

    let store_data = web::Data::new(store);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "DELETE", "POST", "OPTIONS"])
            .allowed_headers(vec!["Content-Type"])
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(store_data.clone())
            // Trajectory collection API
            .service(trajectories::list_trajectories)
            .service(trajectories::trajectory_filters)
            .service(trajectories::get_trajectory_detail)
            // Local session discovery + ATIF conversion API
            .service(local_sessions::list_local_sessions)
            .service(local_sessions::convert_local_to_atif)
            .service(local_sessions::read_local_session_file)
            // Agent process discovery API
            .service(agents::list_agents)
            // macOS stubs (no eBPF data available)
            .service(auth_status)
            .service(auth_verify)
            .service(list_sessions)
            .service(list_agent_names)
            .service(list_timeseries)
            .service(token_savings)
            .service(list_interruptions)
            .service(interruption_count)
            .service(interruption_stats)
            .service(interruption_session_counts)
            .service(interruption_conversation_counts)
            .service(security_status)
            .service(security_summary)
            .service(skill_metrics)
            .service(agent_health)
            // Catch-all for unregistered API endpoints (returns empty array)
            .service(api_fallback)
            // Frontend static files (catch-all, must be last)
            .service(serve_frontend)
    })
    .bind((host, port))?
    .run()
    .await
}
