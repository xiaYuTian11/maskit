/**
 * 配置与设置 API（真实后端契约：/api/config GET/POST + 配套接口）
 */
import { shieldFetch } from '@/lib/shield-fetch'
import type { ShieldConfig, TodayStats } from '@/types/api'

export function getConfig(): Promise<ShieldConfig> {
  return shieldFetch<ShieldConfig>('/api/config')
}

export interface SaveConfigResponse {
  ok: boolean
  config: ShieldConfig
  warnings: string[]
  proxy_restarted: boolean
  error?: string
}

export function saveConfig(cfg: Partial<ShieldConfig>): Promise<SaveConfigResponse> {
  return shieldFetch<SaveConfigResponse>('/api/config', {
    method: 'POST',
    body: JSON.stringify(cfg),
  })
}

export function emergencyDisableOriginCheck(customToken?: string): Promise<{ ok: boolean; message: string; config?: ShieldConfig }> {
  return shieldFetch<{ ok: boolean; message: string; config?: ShieldConfig }>('/api/config/disable_origin_check', {
    method: 'POST',
    headers: customToken ? { 'X-Shield-Token': customToken } : undefined,
  })
}

export function getTodayStats(range?: '7d' | '30d' | string): Promise<TodayStats> {
  const qs = range ? `?range=${range}` : ''
  return shieldFetch<TodayStats>(`/api/stats/today${qs}`)
}

export interface StatsHistoryPoint {
  ts: number
  label: string
  requests?: number
  mask_events?: number
  restored?: number
  alerts?: number
  tokens_prompt?: number
  tokens_completion?: number
  /** 审计信号事件数（注入审计/投毒检测） */
  audit_signals?: number
  /** 审计高危（HIGH/CRITICAL）信号数 */
  audit_high?: number
}
export interface StatsHistory {
  ok: boolean
  granularity: string
  days: number
  data: StatsHistoryPoint[]
}
export function getStatsHistory(days = 30, granularity: 'day' | 'hour' = 'day'): Promise<StatsHistory> {
  return shieldFetch<StatsHistory>(`/api/stats/history?days=${days}&granularity=${granularity}`)
}

export interface StatsModel {
  model: string
  requests: number
  prompt: number
  completion: number
  cost_usd: number
  priced: boolean
  errors?: number
}

export function getStatsModels(days = 7): Promise<{ ok: boolean; days: number; models: StatsModel[] }> {
  return shieldFetch(`/api/stats/models?days=${days}`)
}

export interface PriceSyncState {
  syncing: boolean
  last_error: string
  synced_at: number
  model_count: number
  source: string
  builtin_count: number
  ok?: boolean
}

export function getPriceSyncStatus(): Promise<PriceSyncState> {
  return shieldFetch<PriceSyncState>('/api/prices/status')
}

export function syncPricesNow(): Promise<{ ok: boolean; error?: string; state?: PriceSyncState }> {
  return shieldFetch('/api/prices/sync', { method: 'POST' })
}

export interface PriceEntry {
  model: string
  input: number
  output: number
  cache_read?: number
  cache_write?: number
}

export function getPriceList(): Promise<{ ok: boolean; count: number; models: PriceEntry[] }> {
  return shieldFetch('/api/prices/list')
}

export function getRestoreItems(limit = 200): Promise<{
  items: { label: string; preview: string; events: number; cred?: boolean; length?: number; original?: string }[]
}> {
  return shieldFetch(`/api/stats/today/restore-items?limit=${limit}`)
}

export function testUpstream(payload: {
  name?: string
  port?: number
  mode: 'port' | 'models' | 'chat'
  api_key?: string
  model?: string
  path_prefix?: string
  content?: string
}): Promise<{ ok: boolean; message?: string; error?: string; [k: string]: unknown }> {
  return shieldFetch('/api/upstream/test', { method: 'POST', body: JSON.stringify(payload) })
}

export function demoMask(text?: string): Promise<{
  ok: boolean
  masked?: string
  count?: number
  items?: { label: string; original_len: number; token: string }[]
  error?: string
}> {
  return shieldFetch('/api/demo/mask', { method: 'POST', body: JSON.stringify({ text: text ?? '' }) })
}

export function getAutostart(): Promise<{ enabled: boolean }> {
  return shieldFetch('/api/autostart')
}

export function setAutostart(enabled: boolean): Promise<{ ok: boolean; enabled: boolean }> {
  return shieldFetch('/api/autostart', { method: 'POST', body: JSON.stringify({ enabled }) })
}

export function installCert(scope: string): Promise<{ ok: boolean; error?: string; output?: string }> {
  return shieldFetch('/api/cert', { method: 'POST', body: JSON.stringify({ scope }) })
}

export function openDataDir(): Promise<{ ok: boolean }> {
  return shieldFetch('/api/open-data-dir', { method: 'POST' })
}

/** 一键恢复网络/系统代理（/api/restore） */
export function restoreNetwork(): Promise<{ ok: boolean; [k: string]: unknown }> {
  return shieldFetch('/api/restore', { method: 'POST' })
}

/** 健康检查（/api/health） */
export interface WriterStats {
  event_writer_alive?: boolean
  audit_writer_alive?: boolean
  event_queue_size?: number
  audit_queue_size?: number
  event_writer?: { drops?: number; dead_letters?: number; restarts?: number }
  audit_writer?: { drops?: number; dead_letters?: number; restarts?: number }
}
export function getHealth(): Promise<{ ok: boolean; writer_stats?: WriterStats; [k: string]: unknown }> {
  return shieldFetch('/api/health')
}

// ========== 配置备份与回滚（/api/config/backups · /api/config/restore） ==========
export interface ConfigBackup {
  file: string
  /** epoch 秒 */
  mtime: number
  size: number
  upstreams: number
  cats: number
  words: number
  domains: number
}

export interface ConfigBackupsResponse {
  ok: boolean
  backups: ConfigBackup[]
  current: { upstreams?: number; cats?: number; words?: number; domains?: number }
  error?: string
}

/** 列出可回滚的配置备份（含结构摘要，供用户判断回滚到哪一份） */
export function getConfigBackups(): Promise<ConfigBackupsResponse> {
  return shieldFetch<ConfigBackupsResponse>('/api/config/backups')
}

/** 从指定备份回滚配置；回滚本身也会先备份当前配置，滚错了还能滚回来 */
export function restoreConfigBackup(file: string): Promise<{
  ok: boolean
  warnings?: string[]
  proxy_restarted?: boolean
  restored_from?: string
  error?: string
}> {
  return shieldFetch('/api/config/restore', {
    method: 'POST',
    body: JSON.stringify({ file }),
  })
}
