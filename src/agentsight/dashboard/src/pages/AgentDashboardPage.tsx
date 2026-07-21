import React, { useState, useEffect, useRef, useCallback } from 'react';
import { fetchAgentHealth, deleteAgentHealth, restartAgentHealth } from '../utils/apiClient';
import type { AgentHealthStatus } from '../types';

const STATUS_COLORS: Record<string, string> = {
  healthy: 'bg-green-500',
  unhealthy: 'bg-red-500',
  hung: 'bg-orange-500',
  unknown: 'bg-yellow-400',
  no_port: 'bg-gray-400',
  offline: 'bg-gray-500',
};

const STATUS_LABELS: Record<string, string> = {
  healthy: '正常',
  unhealthy: '端口无响应',
  hung: '响应卡住',
  unknown: '待检测',
  no_port: '客户端进程',
  offline: '异常退出',
};

const STATUS_TOOLTIPS: Record<string, string> = {
  healthy: '服务监听端口且 HTTP 探活成功',
  unhealthy: '端口不接受连接，可能需要重启',
  hung: '端口可连但 HTTP 探活超时，进程可能卡死',
  unknown: '首轮健康检查未完成',
  no_port: 'TUI / 子进程，本身不提供服务端口（正常）',
  offline: '进程异常退出，影响了进行中的 LLM 对话，5 分钟后自动移除',
};

function relativeTime(timestampMs: number): string {
  if (timestampMs === 0) return '—';
  const diff = Math.floor((Date.now() - timestampMs) / 1000);
  if (diff < 5) return '刚刚';
  if (diff < 60) return `${diff} 秒前`;
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
  return `${Math.floor(diff / 3600)} 小时前`;
}

interface Toast {
  id: number;
  message: string;
}

const OFFLINE_TTL_MS = 5 * 60 * 1000;

const AgentCard: React.FC<{
  agent: AgentHealthStatus;
  onDelete: (pid: number) => void;
  onRestart: (pid: number) => void;
  restarting: boolean;
}> = ({ agent, onDelete, onRestart, restarting }) => {
  const hasPorts = (agent.ports?.length ?? 0) > 0;
  const isRealGateway = agent.role === 'gateway' && hasPorts;
  const isPromotedGateway = agent.role === 'gateway' && !hasPorts;

  const useRunningStatus = isPromotedGateway && agent.status === 'no_port';
  const dotColor = useRunningStatus
    ? 'bg-green-500'
    : STATUS_COLORS[agent.status] || 'bg-gray-400';
  const label = useRunningStatus ? '运行中' : STATUS_LABELS[agent.status] || agent.status;
  const tooltip = useRunningStatus
    ? '单进程 agent，本身不提供服务端口，运行正常'
    : STATUS_TOOLTIPS[agent.status] || '';
  const isOffline = agent.status === 'offline';
  const isHung = agent.status === 'hung';
  const isUnhealthy = agent.status === 'unhealthy';
  const canRestart = isHung && !!agent.restart_cmd?.length;

  const offlineRemainSec =
    isOffline && agent.offline_since
      ? Math.max(0, Math.ceil((OFFLINE_TTL_MS - (Date.now() - agent.offline_since)) / 1000))
      : null;

  const cardBg = isHung ? 'bg-orange-50' : isUnhealthy ? 'bg-red-50' : 'bg-white';
  const borderColor = isHung
    ? 'border-orange-200'
    : isUnhealthy
    ? 'border-red-200'
    : 'border-gray-200';
  const nameColor = isOffline
    ? 'text-gray-500'
    : isHung
    ? 'text-orange-700'
    : isUnhealthy
    ? 'text-red-700'
    : 'text-gray-900';
  const labelColor = isOffline
    ? 'text-gray-400'
    : isHung
    ? 'text-orange-600 font-semibold'
    : isUnhealthy
    ? 'text-red-600 font-semibold'
    : 'text-gray-500';

  return (
    <div className={`rounded-lg border ${borderColor} ${cardBg} p-4 hover:shadow-md transition-shadow flex flex-col`} title={tooltip}>
      <div className="flex items-center gap-2 mb-3">
        <span className={`inline-block w-2.5 h-2.5 rounded-full flex-shrink-0 ${dotColor}`} />
        <span className={`font-semibold text-base truncate ${nameColor}`}>
          {agent.agent_name}
        </span>
        {isRealGateway && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-100 text-green-700 font-medium">
            Gateway
          </span>
        )}
        {agent.role === 'client' && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-500 font-medium">
            客户端
          </span>
        )}
        {agent.role === 'worker' && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-500 font-medium">
            Worker
          </span>
        )}
        <span className={`ml-auto text-sm flex-shrink-0 ${labelColor}`}>
          {label}
        </span>
      </div>

      {tooltip && (isHung || isUnhealthy) && (
        <div className="mb-2 text-xs leading-snug text-gray-500 italic">
          ℹ️ {tooltip}
        </div>
      )}

      <div className="grid grid-cols-2 gap-2 text-xs text-gray-600 mb-2">
        <div>
          <span className="text-gray-400">PID</span>{' '}
          <span className="font-mono font-medium">{agent.pid}</span>
        </div>
        {agent.latency_ms !== null && agent.status === 'healthy' && (
          <div>
            <span className="text-gray-400">延迟</span>{' '}
            <span className="text-green-600 font-medium">{agent.latency_ms}ms</span>
          </div>
        )}
        {hasPorts && (
          <div>
            <span className="text-gray-400">端口</span>{' '}
            <span className="font-mono">{agent.ports.join(', ')}</span>
          </div>
        )}
        <div>
          <span className="text-gray-400">检查</span>{' '}
          <span>{relativeTime(agent.last_check_time)}</span>
        </div>
      </div>

      {agent.error_message && !isOffline && (
        <div
          className={`text-xs truncate mb-2 ${isHung ? 'text-orange-500' : 'text-red-500'}`}
          title={agent.error_message}
        >
          {agent.error_message}
        </div>
      )}

      {isOffline && offlineRemainSec !== null && (
        <div className="text-xs text-gray-400 italic mb-2">
          {offlineRemainSec > 0
            ? `${offlineRemainSec >= 60 ? Math.ceil(offlineRemainSec / 60) + ' 分钟' : offlineRemainSec + ' 秒'}后自动移除`
            : '即将移除'}
        </div>
      )}

      <div className="mt-auto flex gap-3 pt-2">
        {isOffline && (
          <button
            onClick={() => onDelete(agent.pid)}
            className="text-xs text-gray-400 hover:text-gray-600 underline"
          >
            立即移除
          </button>
        )}
        {canRestart && (
          <button
            onClick={() => onRestart(agent.pid)}
            disabled={restarting}
            className="text-xs text-orange-500 hover:text-orange-700 underline disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {restarting ? '重启中...' : '重启进程'}
          </button>
        )}
      </div>
    </div>
  );
};

const RelatedProcesses: React.FC<{
  related: AgentHealthStatus[];
}> = ({ related }) => {
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-2">
      <button
        onClick={() => setOpen(o => !o)}
        className="text-xs text-gray-500 hover:text-gray-700 flex items-center gap-1"
      >
        <span className={`transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
        关联进程 ({related.length})
      </button>
      {open && (
        <div className="mt-1 ml-3 border-l-2 border-gray-200 pl-3 space-y-1">
          {related.map(ca => (
            <div key={ca.pid} className="text-xs text-gray-500 flex items-center gap-1.5">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-gray-300" />
              <span className="text-[10px] px-1 py-0.5 rounded bg-gray-100">
                {ca.role === 'worker' ? 'Worker' : '客户端'}
              </span>
              <span className="font-mono text-gray-400">PID {ca.pid}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export const AgentDashboardPage: React.FC = () => {
  const [agents, setAgents] = useState<AgentHealthStatus[]>([]);
  const [clientAgents, setClientAgents] = useState<AgentHealthStatus[]>([]);
  const [showClients, setShowClients] = useState(false);
  const [lastScan, setLastScan] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [restartingPids, setRestartingPids] = useState<Set<number>>(new Set());
  const toastIdRef = useRef(0);
  const notifiedOfflineRef = useRef<Set<number>>(new Set());

  const addToast = useCallback((message: string) => {
    const id = ++toastIdRef.current;
    setToasts(prev => [...prev, { id, message }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const data = await fetchAgentHealth({ includeClients: true });

      data.agents.forEach(a => {
        if (a.status === 'offline' && a.has_crash && !notifiedOfflineRef.current.has(a.pid)) {
          notifiedOfflineRef.current.add(a.pid);
          addToast(`⚠️ Agent "${a.agent_name}" (PID ${a.pid}) 异常退出，影响了进行中的对话`);
        }
        if (a.status === 'hung' && !notifiedOfflineRef.current.has(-a.pid)) {
          notifiedOfflineRef.current.add(-a.pid);
          addToast(`⏳ Agent "${a.agent_name}" (PID ${a.pid}) 响应超时，可能卡顿`);
        }
      });
      const currentPids = new Set(data.agents.map(a => a.pid));
      notifiedOfflineRef.current.forEach(pid => {
        const absPid = Math.abs(pid);
        if (!currentPids.has(absPid)) notifiedOfflineRef.current.delete(pid);
      });
      data.agents.forEach(a => {
        if (a.status !== 'hung') notifiedOfflineRef.current.delete(-a.pid);
      });

      setAgents(data.agents.filter(a => a.role === 'gateway'));
      setClientAgents(data.agents.filter(a => a.role !== 'gateway'));
      setLastScan(data.last_scan_time);
      setError(null);
    } catch (e: any) {
      if (agents.length === 0) {
        setError(e.message || '请求失败');
      }
    } finally {
      setLoading(false);
    }
  }, [addToast]);

  const handleDelete = async (pid: number) => {
    try {
      await deleteAgentHealth(pid);
      notifiedOfflineRef.current.delete(pid);
      setAgents(prev => prev.filter(a => a.pid !== pid));
    } catch (e: any) {
      addToast(`删除失败: ${e.message}`);
    }
  };

  const handleRestart = async (pid: number) => {
    setRestartingPids(prev => new Set(prev).add(pid));
    try {
      const result = await restartAgentHealth(pid);
      addToast(`✅ 重启成功，新 PID: ${result.new_pid}，等待进程上线...`);
      notifiedOfflineRef.current.delete(-pid);
      setAgents(prev => prev.filter(a => a.pid !== pid));
    } catch (e: any) {
      addToast(`重启失败: ${e.message}`);
    } finally {
      setRestartingPids(prev => {
        const next = new Set(prev);
        next.delete(pid);
        return next;
      });
    }
  };

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 10_000);
    return () => clearInterval(timer);
  }, [refresh]);

  const sorted = [...agents].sort((a, b) => {
    const order: Record<string, number> = { hung: 0, unhealthy: 1, healthy: 2, no_port: 3, unknown: 4, offline: 5 };
    return (order[a.status] ?? 6) - (order[b.status] ?? 6);
  });

  const healthyCount = agents.filter(a => a.status === 'healthy').length;
  const offlineCount = agents.filter(a => a.status === 'offline').length;
  const hungCount = agents.filter(a => a.status === 'hung').length;
  const totalCount = agents.length;

  const gatewayPids = new Set(sorted.map(a => a.pid));
  const orphans = clientAgents.filter(c =>
    c.status !== 'offline' &&
    (c.parent_pid === undefined || c.parent_pid === null || !gatewayPids.has(c.parent_pid))
  );

  return (
    <>
      <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map(t => (
          <div key={t.id}
            className="bg-red-600 text-white text-xs px-4 py-2 rounded shadow-lg animate-pulse pointer-events-auto">
            {t.message}
          </div>
        ))}
      </div>

      <main className="max-w-screen-xl mx-auto px-6 py-6 space-y-6">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-gray-900">🖥 Agent 看板</h1>
            <div className="flex items-center gap-1.5">
              {offlineCount > 0 && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-600 font-semibold">
                  {offlineCount} 崩溃
                </span>
              )}
              {hungCount > 0 && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-orange-100 text-orange-600 font-semibold">
                  {hungCount} 卡顿
                </span>
              )}
              {totalCount > 0 && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-gray-100 text-gray-600">
                  {healthyCount}/{totalCount}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={refresh}
              className="px-3 py-1.5 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 flex items-center gap-1.5"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="23 4 23 10 17 10" />
                <polyline points="1 20 1 14 7 14" />
                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
              </svg>
              刷新
            </button>
            {lastScan > 0 && (
              <span className="text-xs text-gray-400">上次扫描: {relativeTime(lastScan)}</span>
            )}
          </div>
        </div>

        {loading ? (
          <div className="text-center py-20 text-gray-400">加载中...</div>
        ) : error ? (
          <div className="text-center py-20 text-red-400">{error}</div>
        ) : sorted.length === 0 && orphans.length === 0 ? (
          <div className="bg-white rounded-lg border border-gray-200 p-12 text-center">
            <div className="text-5xl mb-4">🔍</div>
            <h3 className="text-lg font-semibold text-gray-900 mb-2">暂无已发现的 Agent</h3>
            <p className="text-sm text-gray-500">
              当前机器上没有发现正在运行的 AI Agent 进程。
            </p>
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {sorted.map(agent => {
                const related = clientAgents.filter(c => c.parent_pid === agent.pid);
                return (
                  <div key={agent.pid} className="flex flex-col">
                    <AgentCard
                      agent={agent}
                      onDelete={handleDelete}
                      onRestart={handleRestart}
                      restarting={restartingPids.has(agent.pid)}
                    />
                    {related.length > 0 && <RelatedProcesses related={related} />}
                  </div>
                );
              })}
            </div>

            {orphans.length > 0 && (
              <div className="bg-white rounded-lg border border-gray-200 p-4">
                <button
                  onClick={() => setShowClients(s => !s)}
                  className="text-sm text-gray-500 hover:text-gray-700 flex items-center gap-1"
                >
                  <span className={`transition-transform ${showClients ? 'rotate-90' : ''}`}>▶</span>
                  孤儿关联进程 ({orphans.length})
                </button>
                {showClients && (
                  <div className="mt-2 ml-3 border-l-2 border-gray-100 pl-3 space-y-1">
                    {orphans.map(ca => (
                      <div key={ca.pid} className="text-xs text-gray-500 flex items-center gap-1.5">
                        <span className="inline-block w-1.5 h-1.5 rounded-full bg-gray-300" />
                        <span className="font-medium">{ca.agent_name}</span>
                        <span className="text-[10px] px-1 py-0.5 rounded bg-gray-100">
                          {ca.role === 'worker' ? 'Worker' : '客户端'}
                        </span>
                        <span className="font-mono text-gray-400">PID {ca.pid}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </main>
    </>
  );
};
