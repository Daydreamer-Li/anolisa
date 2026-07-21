import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchLocalSessions, LocalSession } from '../utils/apiClient';

export const LocalSessions: React.FC = () => {
  const [sessions, setSessions] = useState<LocalSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const pageSize = 15;
  const navigate = useNavigate();

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetchLocalSessions();
      setSessions(resp.sessions);
    } catch (e: any) {
      setError(e.message ?? 'Failed to load sessions');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Get unique agent list for filter
  const agentIds = Array.from(new Set(sessions.map(s => s.agent_id))).sort();

  const filtered = sessions.filter(s => {
    if (filter && s.agent_id !== filter) return false;
    if (search) {
      const q = search.toLowerCase();
      return s.project.toLowerCase().includes(q)
        || s.first_message.toLowerCase().includes(q)
        || s.agent_name.toLowerCase().includes(q);
    }
    return true;
  });

  const totalPages = Math.ceil(filtered.length / pageSize);
  const pageItems = filtered.slice(page * pageSize, (page + 1) * pageSize);

  const handleAnalyze = (session: LocalSession) => {
    const params = new URLSearchParams({ type: 'local', path: session.file_path });
    navigate(`/atif?${params.toString()}`);
  };

  const fmtTime = (ts: number) => {
    return new Date(ts * 1000).toLocaleString('zh-CN', {
      month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    });
  };

  const fmtSize = (kb: number) => {
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    return `${(kb / 1024).toFixed(1)} MB`;
  };

  return (
    <div className="p-6 max-w-screen-xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">
          📁 本地会话
          {sessions.length > 0 && (
            <span className="ml-2 text-sm font-normal text-gray-500">
              {sessions.length} 个会话
            </span>
          )}
        </h1>
        <button
          onClick={load}
          disabled={loading}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? '刷新中…' : '🔄 刷新'}
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-4 mb-4">
        <select
          value={filter}
          onChange={(e) => { setFilter(e.target.value); setPage(0); }}
          className="px-3 py-2 border border-gray-300 rounded-lg text-sm bg-white"
        >
          <option value="">全部 Agent</option>
          {agentIds.map(id => {
            const agent = sessions.find(s => s.agent_id === id);
            return (
              <option key={id} value={id}>
                {agent?.agent_icon} {agent?.agent_name}
              </option>
            );
          })}
        </select>
        <input
          type="text"
          placeholder="搜索项目名或消息内容…"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(0); }}
          className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm"
        />
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          {error}
        </div>
      )}

      {/* Table */}
      {loading ? (
        <div className="text-center py-12 text-gray-400">加载中…</div>
      ) : pageItems.length === 0 ? (
        <div className="text-center py-12 text-gray-400">
          {sessions.length === 0
            ? '未发现本地 Agent 会话文件。请确认 ~/.qoder/projects、~/.claude/projects 等目录存在。'
            : '无匹配结果'}
        </div>
      ) : (
        <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-gray-600">
              <tr>
                <th className="px-4 py-3 text-left font-medium">Agent</th>
                <th className="px-4 py-3 text-left font-medium">项目</th>
                <th className="px-4 py-3 text-left font-medium">首条消息</th>
                <th className="px-4 py-3 text-right font-medium">消息数</th>
                <th className="px-4 py-3 text-right font-medium">大小</th>
                <th className="px-4 py-3 text-left font-medium">修改时间</th>
                <th className="px-4 py-3 text-center font-medium">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {pageItems.map((s, i) => (
                <tr key={`${s.file_path}-${i}`} className="hover:bg-gray-50">
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="mr-1">{s.agent_icon}</span>
                    <span className="text-gray-700">{s.agent_name}</span>
                  </td>
                  <td className="px-4 py-3 text-gray-600">{s.project}</td>
                  <td className="px-4 py-3 text-gray-500 max-w-md truncate">
                    {s.first_message}
                  </td>
                  <td className="px-4 py-3 text-right text-gray-600">{s.message_count}</td>
                  <td className="px-4 py-3 text-right text-gray-400">{fmtSize(s.file_size_kb)}</td>
                  <td className="px-4 py-3 text-gray-400 whitespace-nowrap">{fmtTime(s.modified_ts)}</td>
                  <td className="px-4 py-3 text-center">
                    <button
                      onClick={() => handleAnalyze(s)}
                      className="px-3 py-1 bg-blue-50 text-blue-600 rounded text-xs font-medium hover:bg-blue-100"
                    >
                      🔍 查看轨迹
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 mt-4">
          <button
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
            className="px-3 py-1 text-sm border border-gray-300 rounded disabled:opacity-50"
          >
            上一页
          </button>
          <span className="text-sm text-gray-500">
            {page + 1} / {totalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
            className="px-3 py-1 text-sm border border-gray-300 rounded disabled:opacity-50"
          >
            下一页
          </button>
        </div>
      )}
    </div>
  );
};
