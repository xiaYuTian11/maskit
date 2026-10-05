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

/** Update changed rules only; other tabs may have changed the remaining rules. */
export function saveBuiltinRules(changes: Record<string, boolean>): Promise<SaveConfigResponse> {
  return shieldFetch<SaveConfigResponse>('/api/config/builtin_rules', {
    method: 'POST',
    body: JSON.stringify(changes),
  })
}

/**
 * 配置增量操作。POST /api/config 只在顶层合并，凡是「值本身是容器」的字段
 * （audit / egress_proxy / sensitive / upstreams / target_domains …）提交整份
 * 快照都会覆盖掉并发写入；这里改为下发「路径 + 操作」，由服务端持锁局部修改。
 */
export type ConfigPatchOp =
  | 'set'          // 覆盖指定路径的值（path 省略 = 覆盖整个键）
  | 'merge'        // 目标是对象：批量更新其中的键
  | 'map_del'      // 目标是对象：删除 value 列出的键
  | 'list_add'     // 目标是数组：追加 value 中尚不存在的标量项
  | 'list_remove'  // 目标是数组：移除 value 中存在的标量项
  | 'list_upsert'  // 目标是对象数组：按 name 就地更新或追加（match 指定旧名）
  | 'list_del'     // 目标是对象数组：按 name 移除

export interface ConfigPatch {
  key: keyof ShieldConfig | string
  op: ConfigPatchOp
  /** 在 key 对应值内下钻的路径；省略或空数组表示操作该值本身 */
  path?: string[]
  value: unknown
  /** list_upsert 专用：要更新的条目原名（用于改名） */
  match?: string
}

export function patchConfig(patch: ConfigPatch): Promise<SaveConfigResponse> {
  return shieldFetch<SaveConfigResponse>('/api/config/patch', {
    method: 'POST',
    body: JSON.stringify(patch),
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
  return shieldFetch('/api/prices/sync', { method: 'POST', timeoutMs: 60000 })
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
  return shieldFetch('/api/upstream/test', { method: 'POST', body: JSON.stringify(payload), timeoutMs: 60000 })
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

/** 下载占位符 Skill 包（`GET /api/skill/bundle`，与 Release 资产同源）。
 *
 * `raw: true`：要的是二进制 zip 本身，不走 JSON 解析（与 `exportLogs` 同一写法）。
 * 必须由前端带 `X-Shield-Token` 拉取后再存盘 —— 直接给 `<a href>` 会漏掉
 * `api_guard` 的令牌校验（该端点在 `/api/` 前缀下，见 `AGENTS.md` §3.7）。
 * `timeoutMs: 0`：打包在引擎进程内完成，磁盘慢时可能超过默认 15s。
 */
export function downloadSkillBundle(): Promise<Response> {
  return shieldFetch<Response>('/api/skill/bundle', { raw: true, timeoutMs: 0 })
}

/** 本地试验台：脱敏 → 还原往返（`POST /api/demo/lab`）。
 *
 * 与 `demoMask`（上游探针，要 API Key）分开：本接口不碰上游、不要 key，
 * 回答的是「这段文本会被怎样脱敏、能不能原样还原」。样本只在本机内存里。
 */
export function demoLab(text: string): Promise<DemoLabResult> {
  return shieldFetch('/api/demo/lab', { method: 'POST', body: JSON.stringify({ text }), timeoutMs: 30000 })
}

export interface DemoLabHit {
  token: string
  label: string
  original_len: number
  occurrences: number
  reused: boolean
}

export interface DemoLabResult {
  ok: boolean
  input_len?: number
  masked?: string
  restored?: string
  roundtrip_ok?: boolean
  count?: number
  occurrences?: number
  by_label?: Record<string, number>
  items?: DemoLabHit[]
  changed?: boolean
  restored_count?: number
  unresolved?: number
  mask_ms?: number
  restore_ms?: number
  ner_skips?: unknown
  isolated?: boolean
  seeded_recent?: number
  error?: string
  hint?: string
  limit?: number
}

export function getAutostart(): Promise<{ enabled: boolean }> {
  return shieldFetch('/api/autostart')
}

export function setAutostart(enabled: boolean): Promise<{ ok: boolean; enabled: boolean }> {
  return shieldFetch('/api/autostart', { method: 'POST', body: JSON.stringify({ enabled }) })
}

export function installCert(scope: string): Promise<{ ok: boolean; error?: string; output?: string }> {
  return shieldFetch('/api/cert', { method: 'POST', body: JSON.stringify({ scope }), timeoutMs: 30000 })
}

export function openDataDir(): Promise<{ ok: boolean }> {
  return shieldFetch('/api/open-data-dir', { method: 'POST' })
}

/** 一键恢复网络/系统代理（/api/restore） */
export function restoreNetwork(): Promise<{ ok: boolean; [k: string]: unknown }> {
  return shieldFetch('/api/restore', { method: 'POST', timeoutMs: 30000 })
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

// ========== 内存映射（§D3.3：与清日志/清审计/清数字统计并列的独立动作） ==========

export interface MappingStats {
  ok: boolean
  /** 本进程（扩展桥接链路）的规模 */
  panel: { sessions?: number; recent_entries?: number; suffix_index?: number; custom_word_entries?: number }
  /** 引擎进程（代理链路）的规模，来自 engine-runtime.json 快照 */
  engine: { sessions?: number; recent_entries?: number; suffix_index?: number; custom_word_entries?: number }
  /** 引擎快照是否过期：过期必须如实标注，不能拿旧数据当现状 */
  engine_stale: boolean
  engine_generation?: number
  engine_generated_at?: number
}

/** 内存映射当前规模（按钮旁边显示「现在有多少东西可清」） */
export function getMappingStats(): Promise<MappingStats> {
  return shieldFetch<MappingStats>('/api/mappings/state')
}

/**
 * 清空内存里的「占位符 ↔ 原文」映射。**必须显式 confirm**：
 * 清掉之后当前对话里携带的历史占位符会全部还原不了，直到被重新扫描到。
 * `engine_applied` 恒为 'pending'——引擎是异步消费信号的，不能说成已生效。
 */
export function clearMappings(): Promise<{
  ok: boolean
  panel?: { sessions?: number; recent_entries?: number }
  engine_generation?: number
  engine_applied?: string
  hint?: string
  error?: string
}> {
  return shieldFetch('/api/mappings/clear?confirm=true', { method: 'POST' })
}
