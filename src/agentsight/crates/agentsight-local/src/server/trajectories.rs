//! Trajectory collection endpoints for macOS local server.
//!
//! Mirrors the upstream `/api/trajectories` routes but backed by
//! `agentsight_trajectory_collector::TrajectoryStore` instead of the full
//! Linux-only `AppState`. On macOS the collector scans Qoder/QoderWork session
//! directories and stores ATIF v1.7 documents in `trajectories.db`.

use actix_web::{HttpResponse, Responder, get, web};
use agentsight_trajectory_collector::TrajectoryStore;
use serde::Deserialize;

/// Default and hard-cap for the trajectory list `limit` parameter.
const TRAJECTORY_DEFAULT_LIMIT: i64 = 200;
const TRAJECTORY_MAX_LIMIT: i64 = 1000;

#[derive(Deserialize)]
pub struct TrajectoryQuery {
    pub project: Option<String>,
    pub source: Option<String>,
    pub agent_name: Option<String>,
    pub limit: Option<i64>,
}

/// GET /api/trajectories
#[get("/api/trajectories")]
pub async fn list_trajectories(
    store: web::Data<Option<TrajectoryStore>>,
    query: web::Query<TrajectoryQuery>,
) -> impl Responder {
    let Some(ref tstore) = *store.into_inner() else {
        return HttpResponse::Ok().json(Vec::<serde_json::Value>::new());
    };
    let limit = match query.limit {
        Some(v) if v > 0 => v.min(TRAJECTORY_MAX_LIMIT),
        _ => TRAJECTORY_DEFAULT_LIMIT,
    };
    match tstore.list_summaries(
        query.project.as_deref(),
        query.source.as_deref(),
        query.agent_name.as_deref(),
        limit,
    ) {
        Ok(rows) => HttpResponse::Ok().json(rows),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// GET /api/trajectories/filters
#[get("/api/trajectories/filters")]
pub async fn trajectory_filters(
    store: web::Data<Option<TrajectoryStore>>,
) -> impl Responder {
    let Some(ref tstore) = *store.into_inner() else {
        return HttpResponse::Ok().json(serde_json::json!({
            "projects": [], "sources": [], "agent_names": []
        }));
    };
    match tstore.list_filters() {
        Ok(filters) => HttpResponse::Ok().json(filters),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// GET /api/trajectories/{session_id}
#[get("/api/trajectories/{session_id}")]
pub async fn get_trajectory_detail(
    store: web::Data<Option<TrajectoryStore>>,
    path: web::Path<String>,
) -> impl Responder {
    let Some(ref tstore) = *store.into_inner() else {
        return HttpResponse::NotFound().json(
            serde_json::json!({"error": "not_found", "message": "Trajectory store not available"}),
        );
    };
    let session_id = path.into_inner();

    match tstore.get_atif_json(&session_id) {
        Ok(Some(json_str)) => {
            let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap_or(
                serde_json::json!({"raw": json_str}),
            );
            let mut doc = parsed;

            // Embed subagent trajectories if any
            if let Ok(subagents) = tstore.get_subagent_atif_jsons(&session_id)
                && !subagents.is_empty()
            {
                let mut sub_docs = Vec::new();
                for sa_json in subagents {
                    if let Ok(sa) = serde_json::from_str::<serde_json::Value>(&sa_json) {
                        sub_docs.push(sa);
                    }
                }
                if !sub_docs.is_empty() {
                    doc["subagent_trajectories"] = serde_json::Value::Array(sub_docs);
                }
            }

            HttpResponse::Ok().json(doc)
        }
        Ok(None) => HttpResponse::NotFound().json(
            serde_json::json!({"error": "not_found", "message": "Trajectory not found"}),
        ),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": e.to_string()})),
    }
}
