//! JSONL → ATIF converter
//!
//! Parses QoderWork/Qoder/Claude Code JSONL session files and converts them
//! to ATIF v1.7 documents for trajectory display. These agents share a common
//! JSONL format with event types: `runtime-config`, `user`, `assistant`.
//!
//! Content blocks within messages:
//! - `assistant` content: `thinking`, `text`, `tool_use`
//! - `user` content: `text` (human input), `tool_result` (tool output)

use agentsight_atif::{
    Agent, AtifTrajectory, ATIF_SCHEMA_VERSION, FinalMetrics, Observation, ObservationResult, Step,
    StepSource, ToolCall,
};
use serde_json::Value;
use std::path::Path;

pub fn convert_jsonl_to_atif(path: &Path) -> anyhow::Result<AtifTrajectory> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path.display(), e))?;

    convert_jsonl_content_to_atif(&content)
}

pub fn convert_jsonl_content_to_atif(content: &str) -> anyhow::Result<AtifTrajectory> {
    let mut session_id = String::new();
    let mut model_name: Option<String> = None;
    let mut agent_version = String::new();
    let mut agent_name = String::new();
    let mut steps: Vec<Step> = Vec::new();
    let mut step_id: usize = 0;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let event: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match event_type {
            "runtime-config" => {
                if session_id.is_empty() {
                    session_id = event
                        .get("sessionId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                }
                if model_name.is_none() {
                    model_name = event
                        .get("model")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
                if agent_version.is_empty() {
                    agent_version = event
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                }
                if agent_name.is_empty() {
                    agent_name = event
                        .get("entrypoint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("agent")
                        .to_string();
                }
            }
            "session_meta" | "progress" | "last-prompt" => continue,
            "user" => {
                let timestamp = event
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let content_arr = event.pointer("/message/content").and_then(|c| c.as_array());

                if let Some(blocks) = content_arr {
                    let is_tool_result = blocks
                        .iter()
                        .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_result"));

                    if is_tool_result {
                        append_tool_results(&mut steps, blocks);
                    } else {
                        let mut message_text = String::new();
                        for block in blocks {
                            if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                                let text = block.get("text").and_then(|t| t.as_str()).unwrap_or("");
                                if !text.is_empty() {
                                    if !message_text.is_empty() {
                                        message_text.push('\n');
                                    }
                                    message_text.push_str(text);
                                }
                            }
                        }
                        if !message_text.is_empty() {
                            step_id += 1;
                            steps.push(Step {
                                step_id,
                                timestamp,
                                source: StepSource::User,
                                message: message_text,
                                model_name: None,
                                reasoning_effort: None,
                                reasoning_content: None,
                                tool_calls: None,
                                observation: None,
                                metrics: None,
                                extra: None,
                                llm_call_count: None,
                                is_copied_context: None,
                            });
                        }
                    }
                } else if let Some(content_str) =
                    event.pointer("/message/content").and_then(|c| c.as_str())
                {
                    step_id += 1;
                    steps.push(Step {
                        step_id,
                        timestamp,
                        source: StepSource::User,
                        message: content_str.to_string(),
                        model_name: None,
                        reasoning_effort: None,
                        reasoning_content: None,
                        tool_calls: None,
                        observation: None,
                        metrics: None,
                        extra: None,
                        llm_call_count: None,
                        is_copied_context: None,
                    });
                }
            }
            "assistant" => {
                let timestamp = event
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let step_model = event
                    .pointer("/message/model")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .or_else(|| model_name.clone());

                let content_arr = event.pointer("/message/content").and_then(|c| c.as_array());

                let mut message_text = String::new();
                let mut reasoning = String::new();
                let mut tool_calls: Vec<ToolCall> = Vec::new();

                if let Some(blocks) = content_arr {
                    for block in blocks {
                        let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        match block_type {
                            "thinking" => {
                                let text =
                                    block.get("thinking").and_then(|t| t.as_str()).unwrap_or("");
                                if !text.is_empty() {
                                    if !reasoning.is_empty() {
                                        reasoning.push('\n');
                                    }
                                    reasoning.push_str(text);
                                }
                            }
                            "text" => {
                                let text = block.get("text").and_then(|t| t.as_str()).unwrap_or("");
                                if !text.is_empty() {
                                    if !message_text.is_empty() {
                                        message_text.push('\n');
                                    }
                                    message_text.push_str(text);
                                }
                            }
                            "tool_use" => {
                                let id = block
                                    .get("id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let name = block
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let input = block.get("input").cloned().unwrap_or(Value::Null);
                                tool_calls.push(ToolCall {
                                    tool_call_id: id,
                                    function_name: name,
                                    arguments: input,
                                    extra: None,
                                });
                            }
                            _ => {}
                        }
                    }
                }

                step_id += 1;
                steps.push(Step {
                    step_id,
                    timestamp,
                    source: StepSource::Agent,
                    message: message_text,
                    model_name: step_model,
                    reasoning_effort: None,
                    reasoning_content: if reasoning.is_empty() {
                        None
                    } else {
                        Some(reasoning)
                    },
                    tool_calls: if tool_calls.is_empty() {
                        None
                    } else {
                        Some(tool_calls)
                    },
                    observation: None,
                    metrics: None,
                    extra: None,
                    llm_call_count: None,
                    is_copied_context: None,
                });
            }
            _ => {}
        }
    }

    let total_steps = steps.len();

    let agent = Agent {
        name: if agent_name.is_empty() {
            "unknown".to_string()
        } else {
            agent_name
        },
        version: if agent_version.is_empty() {
            "0".to_string()
        } else {
            agent_version
        },
        model_name,
        tool_definitions: None,
        extra: None,
    };

    let final_metrics = FinalMetrics {
        total_prompt_tokens: None,
        total_completion_tokens: None,
        total_cached_tokens: None,
        total_cost_usd: None,
        total_steps: Some(total_steps),
        extra: None,
    };

    Ok(AtifTrajectory {
        schema_version: ATIF_SCHEMA_VERSION.to_string(),
        session_id: Some(if session_id.is_empty() {
            "unknown".to_string()
        } else {
            session_id
        }),
        agent,
        steps,
        trajectory_id: None,
        notes: None,
        final_metrics: Some(final_metrics),
        continued_trajectory_ref: None,
        subagent_trajectories: None,
        extra: None,
    })
}

fn append_tool_results(steps: &mut [Step], blocks: &[Value]) {
    let last_agent_step = steps.iter_mut().rev().find(|s| s.source == StepSource::Agent);
    let step = match last_agent_step {
        Some(s) => s,
        None => return,
    };

    let observation = step.observation.get_or_insert(Observation {
        results: Vec::new(),
    });

    for block in blocks {
        let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if block_type != "tool_result" {
            continue;
        }
        let source_call_id = block
            .get("tool_use_id")
            .and_then(|v| v.as_str())
            .map(String::from);
        let content = block
            .get("content")
            .and_then(|v| v.as_str())
            .map(String::from);
        observation.results.push(ObservationResult {
            source_call_id,
            content: content.map(serde_json::Value::String),
            subagent_trajectory_ref: None,
            extra: None,
        });
    }
}
