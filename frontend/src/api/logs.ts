/**
 * 事件日志 API（真实后端契约：/api/logs 游标 + slim + 详情回源）
 */
import { shieldFetch } from '@/lib/shield-fetch'
import type { LogDetailResponse, LogModeState, LogsResponse } from '@/types/api'

export interface LogsParams {
  /** 游标：id > since（增量轮询） */
  since?: number
  limit?: number
  /** 事件类型（精确过滤，如下推 ERR / BLOCK / SCAN_WARN / MASK / RESTORE 等） */
  type?: string
  /** 隐藏 SKIP/PASS */
  sensitive?: boolean
  /** 搜索词（结构化列） */
  q?: string
  /** 全文搜索（扫 payload，性能重） */
  fulltext?: boolean
  /**
   * 入口维度过滤：`proxy`（CLI 代理链路）/ `ext`（浏览器扩展链路）。
   * 与词榜分组**同口径**——首页词条跳转必须带上它，否则「词条 ×N」与
   * 「点进去的日志条数」对不上，用户会判定统计坏了。
   */
  ingress?: 'proxy' | 'ext'
  /** 列表轻量模式（默认 true，明文只走详情回源） */
  slim?: boolean
  /**
   * 反向游标（§D3.1）：取比它更早的一页。与 `since` 互斥使用——
   * `since` 是向前拉新（实时轮询），`before_seq` 是往回看历史。
   * 筛选条件两边同源，所以同一筛选下翻页不会漏筛/漏重。
   */
  before_seq?: number
  /**
   * 时间游标（§D3.1）：只看 `ts < before_ts` 的记录（epoch 秒）。
   * 与 `before_seq` 同属反向通道，两者都给时取交集（id 与 ts 同序）。
   */
  before_ts?: number
}

export function getLogs(params: LogsParams, signal?: AbortSignal): Promise<LogsResponse> {
  const search = new URLSearchParams()
  if (params.since) search.set('since', String(params.since))
  if (params.limit) search.set('limit', String(params.limit))
  if (params.type) search.set('type', params.type)
  if (params.sensitive) search.set('sensitive', '1')
  if (params.q) search.set('q', params.q)
  if (params.fulltext) search.set('fulltext', '1')
  if (params.ingress) search.set('ingress', params.ingress)
  if (params.before_seq) search.set('before_seq', String(params.before_seq))
  // 0 是合法入参的“不限时间”哨兵，因此用 != null 而不是 truthy 判存在。
  if (params.before_ts != null) search.set('before_ts', String(params.before_ts))
  if (params.slim !== false) search.set('slim', '1')
  const qs = search.toString()
  return shieldFetch<LogsResponse>(`/api/logs${qs ? `?${qs}` : ''}`, { signal })
}

/** 单条事件全量（含 original/dialog 明文，仅详情弹窗调用） */
export function getLogDetail(seq: number): Promise<LogDetailResponse> {
  return shieldFetch<LogDetailResponse>(`/api/logs/detail?seq=${seq}`)
}

/** 导出（恒脱敏 JSON）；返回原始 Response 供落盘。
 *
 * 筛选必须与列表页**完全同口径**（§D3.2）：少传一个 ingress，用户勾着
 * 「只看浏览器扩展」也会导出全量，两边条数对不上就会判定导出坏了。
 * 截断状态读响应头 `X-Maskit-Truncated` / `X-Maskit-Exported` / `X-Maskit-Matched`：
 * 文件是下载走的，body 里的 truncated 用户根本看不到。
 */
export function exportLogs(params: {
  type?: string
  sensitive?: boolean
  q?: string
  fulltext?: boolean
  limit?: number
  ingress?: 'proxy' | 'ext'
}): Promise<Response> {
  const search = new URLSearchParams()
  if (params.type) search.set('type', params.type)
  if (params.sensitive) search.set('sensitive', '1')
  if (params.q) search.set('q', params.q)
  if (params.fulltext) search.set('fulltext', '1')
  if (params.ingress) search.set('ingress', params.ingress)
  if (params.limit) search.set('limit', String(params.limit))
  const qs = search.toString()
  return shieldFetch<Response>(`/api/logs/export${qs ? `?${qs}` : ''}`, { raw: true, timeoutMs: 0 })
}

/** 日志写入模式（§D1）：持久模式 + 限时排障窗口状态 */
export function getLogMode(): Promise<LogModeState> {
  return shieldFetch<LogModeState>('/api/logs/mode')
}

/** 切换持久模式：summary（最小记录）/ detailed（本地详细） */
export function setLogMode(mode: 'summary' | 'detailed'): Promise<LogModeState> {
  return shieldFetch<LogModeState>('/api/logs/mode', {
    method: 'POST',
    body: JSON.stringify({ mode }),
  })
}

/** 开启限时排障（trace）：默认 15 分钟、上限 60，到点自动回到持久模式 */
export function startLogTrace(minutes = 15): Promise<LogModeState> {
  return shieldFetch<LogModeState>('/api/logs/trace', {
    method: 'POST',
    body: JSON.stringify({ minutes }),
  })
}

/** 手动关闭限时排障 */
export function stopLogTrace(): Promise<LogModeState> {
  return shieldFetch<LogModeState>('/api/logs/trace', { method: 'DELETE' })
}

export function clearLogs(): Promise<{ ok: boolean; error?: string }> {
  return shieldFetch('/api/logs/clear', { method: 'POST' })
}
