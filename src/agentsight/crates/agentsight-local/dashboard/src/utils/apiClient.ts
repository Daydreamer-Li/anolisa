/**
 * AgentSight Local backend API client (minimal)
 *
 * When the frontend is served by agentsight-local itself (embedded mode), the
 * API is on the same host/port as the page — use window.location.origin.
 * Otherwise fall back to localhost:7397 for local dev.
 */

const API_BASE: string = (() => {
  if (typeof process !== 'undefined' && (process.env as any).REACT_APP_API_BASE) {
    return (process.env as any).REACT_APP_API_BASE as string;
  }
  if (typeof window !== 'undefined' && window.location && window.location.origin) {
    return window.location.origin;
  }
  return 'http://localhost:7397';
})();

import type { AtifDocument } from '../types';

async function apiFetch<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API ${url} -> ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ─── Local Sessions (cross-platform, no eBPF) ───────────────────────────────

export interface LocalSession {
  session_id: string;
  agent_id: string;
  agent_name: string;
  agent_icon: string;
  project: string;
  message_count: number;
  first_message: string;
  file_path: string;
  file_size_kb: number;
  modified_ts: number;
}

export interface LocalSessionsResponse {
  sessions: LocalSession[];
  total: number;
  scanned_at: number;
}

export async function fetchLocalSessions(): Promise<LocalSessionsResponse> {
  return apiFetch<LocalSessionsResponse>(`${API_BASE}/api/local-sessions`);
}

export async function fetchLocalAtif(filePath: string): Promise<AtifDocument> {
  const params = new URLSearchParams({ path: filePath });
  return apiFetch<AtifDocument>(`${API_BASE}/api/local-session/atif?${params.toString()}`);
}

// ─── Agent Process Discovery (cross-platform via sysinfo) ──────────────────

export interface AgentInfo {
  id: string;
  name: string;
  icon: string;
  category: string;
  status: string;
  pids: number[];
  process_count: number;
  cpu_percent: number;
  mem_mb: number;
  uptime_secs: number;
  cmdline_preview: string;
  cwd: string;
}

export interface AgentsSummary {
  agents: AgentInfo[];
  total_running: number;
  scanned_at: number;
  hostname: string;
}

export async function fetchAgents(): Promise<AgentsSummary> {
  return apiFetch<AgentsSummary>(`${API_BASE}/api/agents`);
}

// ─── ATIF export APIs (session/conversation — not available on standalone server) ──

export async function fetchAtifBySession(sessionId: string): Promise<AtifDocument> {
  return apiFetch<AtifDocument>(
    `${API_BASE}/api/export/atif/session/${encodeURIComponent(sessionId)}`
  );
}

export async function fetchAtifByConversation(conversationId: string): Promise<AtifDocument> {
  return apiFetch<AtifDocument>(
    `${API_BASE}/api/export/atif/conversation/${encodeURIComponent(conversationId)}`
  );
}
