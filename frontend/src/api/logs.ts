/**
 * 事件日志 API（真实后端契约：/api/logs 游标 + slim + 详情回源）
 */
import { shieldFetch } from '@/lib/shield-fetch'
import type { LogDetailResponse, LogsResponse } from '@/types/api'

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
  /** 列表轻量模式（默认 true，明文只走详情回源） */
  slim?: boolean
}

export function getLogs(params: LogsParams, signal?: AbortSignal): Promise<LogsResponse> {
  const search = new URLSearchParams()
  if (params.since) search.set('since', String(params.since))
  if (params.limit) search.set('limit', String(params.limit))
  if (params.type) search.set('type', params.type)
  if (params.sensitive) search.set('sensitive', '1')
  if (params.q) search.set('q', params.q)
  if (params.fulltext) search.set('fulltext', '1')
  if (params.slim !== false) search.set('slim', '1')
  const qs = search.toString()
  return shieldFetch<LogsResponse>(`/api/logs${qs ? `?${qs}` : ''}`, { signal })
}

/** 单条事件全量（含 original/dialog 明文，仅详情弹窗调用） */
export function getLogDetail(seq: number): Promise<LogDetailResponse> {
  return shieldFetch<LogDetailResponse>(`/api/logs/detail?seq=${seq}`)
}

/** 导出（恒脱敏 JSON）；返回原始 Response 供落盘 */
export function exportLogs(params: {
  type?: string
  sensitive?: boolean
  q?: string
  fulltext?: boolean
  limit?: number
}): Promise<Response> {
  const search = new URLSearchParams()
  if (params.type) search.set('type', params.type)
  if (params.sensitive) search.set('sensitive', '1')
  if (params.q) search.set('q', params.q)
  if (params.fulltext) search.set('fulltext', '1')
  if (params.limit) search.set('limit', String(params.limit))
  const qs = search.toString()
  return shieldFetch<Response>(`/api/logs/export${qs ? `?${qs}` : ''}`, { raw: true })
}

export function clearLogs(): Promise<{ ok: boolean; error?: string }> {
  return shieldFetch('/api/logs/clear', { method: 'POST' })
}
