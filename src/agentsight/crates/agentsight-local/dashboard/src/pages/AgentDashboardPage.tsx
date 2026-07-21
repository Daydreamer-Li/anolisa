import React, { useEffect, useState, useCallback } from 'react';
import { fetchAgents, type AgentInfo, type AgentsSummary } from '../utils/apiClient';

function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${h}h ${m}m`;
}

function formatCwd(cwd: string): string {
  if (!cwd) return '-';
  const parts = cwd.split('/');
  if (parts.length <= 3) return cwd;
  return '…/' + parts.slice(-2).join('/');
}

export const AgentDashboardPage: React.FC = () => {
  const [data, setData] = useState<AgentsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchAgentsCb = useCallback(async () => {
    try {
      const json = await fetchAgents();
      setData(json);
      setError(null);
      setLastRefresh(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgentsCb();
  }, [fetchAgentsCb]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchAgentsCb, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchAgentsCb]);

  if (loading) {
    return (
      <div className="p-6 max-w-screen-xl mx-auto">
        <div className="flex items-center gap-3 text-gray-500">
          <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <span>正在扫描本机 Agent 进程...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 max-w-screen-xl mx-auto">
        <div className="bg-white border border-red-200 rounded-lg p-4">
          <p className="text-sm text-red-600 font-mono">扫描失败: {error}</p>
          <button
            onClick={fetchAgentsCb}
            className="mt-3 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
          >
            重试
          </button>
        </div>
      </div>
    );
  }

  const agents = data?.agents ?? [];
  const totalRunning = data?.total_running ?? 0;
  const hostname = data?.hostname ?? 'unknown';

  return (
    <div className="p-6 max-w-screen-xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold text-gray-900">🖥 Agent 看板</h1>
          <div className="flex items-center gap-3 text-sm text-gray-600">
            <span className="px-2 py-1 bg-gray-100 rounded font-mono">{hostname}</span>
            <span>
              {totalRunning > 0 ? (
                <>
                  <span className="font-semibold text-blue-700">{totalRunning}</span> 个 Agent 运行中
                </>
              ) : (
                '未检测到运行中的 Agent'
              )}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-sm text-gray-600 cursor-pointer">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded"
            />
            自动刷新
          </label>
          <button
            onClick={fetchAgentsCb}
            className="px-3 py-1.5 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 flex items-center gap-1.5"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="23 4 23 10 17 10" />
              <polyline points="1 20 1 14 7 14" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            刷新
          </button>
          {lastRefresh && (
            <span className="text-xs text-gray-400 font-mono">
              {lastRefresh.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Empty state */}
      {agents.length === 0 && (
        <div className="bg-white rounded-lg border border-gray-200 p-12 text-center">
          <div className="text-5xl mb-4">🔍</div>
          <h3 className="text-lg font-semibold text-gray-900 mb-2">未检测到 AI Agent 进程</h3>
          <p className="text-sm text-gray-500 mb-2">
            当前机器上没有发现正在运行的 AI 编码 Agent。
          </p>
          <p className="text-xs text-gray-400">
            支持: Claude Code · Codex · Gemini CLI · Cursor · Copilot · Aider · Amp · Windsurf · Zed · OpenHands · Cline · Qwen Code · DeepSeek · Kilo · Qoder · QoderWork · Roo Code
          </p>
        </div>
      )}

      {/* Agent cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {agents.map((agent: AgentInfo) => (
          <div
            key={agent.id}
            className="bg-white rounded-lg border border-gray-200 p-4 hover:shadow-md transition-shadow"
          >
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <span className="text-2xl">{agent.icon}</span>
                <div>
                  <div className="font-semibold text-gray-900">{agent.name}</div>
                  <div className="flex items-center gap-1.5 text-xs text-green-600">
                    <span className="w-1.5 h-1.5 rounded-full bg-green-500 inline-block" />
                    {agent.status}
                  </div>
                </div>
              </div>
              <span className="text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded">
                {agent.process_count} 进程
              </span>
            </div>

            {/* Stats row */}
            <div className="grid grid-cols-3 gap-2 mb-3">
              <div className="text-center">
                <div className="text-sm font-semibold text-gray-900">{agent.cpu_percent.toFixed(1)}%</div>
                <div className="text-xs text-gray-500">CPU</div>
              </div>
              <div className="text-center">
                <div className="text-sm font-semibold text-gray-900">{agent.mem_mb.toFixed(0)} MB</div>
                <div className="text-xs text-gray-500">内存</div>
              </div>
              <div className="text-center">
                <div className="text-sm font-semibold text-gray-900">{formatUptime(agent.uptime_secs)}</div>
                <div className="text-xs text-gray-500">运行时长</div>
              </div>
            </div>

            {/* Working directory */}
            {agent.cwd && (
              <div className="flex items-center gap-1.5 text-xs text-gray-600 mb-2 truncate">
                <span>📁</span>
                <span title={agent.cwd} className="truncate">{formatCwd(agent.cwd)}</span>
              </div>
            )}

            {/* PIDs */}
            <div className="text-xs text-gray-500 mb-2 font-mono">
              PID: {agent.pids.slice(0, 5).join(', ')}
              {agent.pids.length > 5 && <span> +{agent.pids.length - 5}</span>}
            </div>

            {/* Cmdline preview */}
            {agent.cmdline_preview && (
              <div
                className="text-xs text-gray-400 font-mono truncate"
                title={agent.cmdline_preview}
              >
                {agent.cmdline_preview.length > 80
                  ? agent.cmdline_preview.slice(0, 80) + '…'
                  : agent.cmdline_preview}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
