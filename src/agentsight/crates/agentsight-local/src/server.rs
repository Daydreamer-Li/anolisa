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
/// The directory `frontend-dist/` must exist at compile time; if it is absent
/// (e.g. first build before running npm), Rust will use an empty dir.
static FRONTEND: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/frontend-dist");

// ─── Static file handler ─────────────────────────────────────────────────────

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
            // Frontend static files (catch-all, must be last)
            .service(serve_frontend)
    })
    .bind((host, port))?
    .run()
    .await
}
