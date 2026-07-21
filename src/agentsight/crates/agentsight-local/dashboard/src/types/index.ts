// ATIF v1.6 (Agent Trajectory Interchange Format) TypeScript types
// Mirrors the Rust types in the agentsight-atif crate (src/lib.rs)

export interface AtifToolCall {
  tool_call_id: string;
  function_name: string;
  arguments: any;
}

export interface AtifObservationResult {
  source_call_id?: string;
  content?: string;
}

export interface AtifObservation {
  results: AtifObservationResult[];
}

export interface AtifStepMetrics {
  prompt_tokens?: number;
  completion_tokens?: number;
  cached_tokens?: number;
  extra?: any;
}

export interface AtifStep {
  step_id: number;
  timestamp?: string;
  source: 'system' | 'user' | 'agent';
  message?: string;
  model_name?: string;
  reasoning_content?: string;
  tool_calls?: AtifToolCall[];
  observation?: AtifObservation;
  metrics?: AtifStepMetrics;
  extra?: any;
}

export interface AtifAgent {
  name: string;
  version: string;
  model_name?: string;
  tool_definitions?: any[];
  extra?: any;
}

export interface AtifFinalMetrics {
  total_prompt_tokens?: number;
  total_completion_tokens?: number;
  total_cached_tokens?: number;
  total_steps?: number;
  extra?: any;
}

export interface AtifDocument {
  schema_version: string;
  session_id: string;
  agent: AtifAgent;
  steps: AtifStep[];
  final_metrics?: AtifFinalMetrics;
  extra?: any;
}
