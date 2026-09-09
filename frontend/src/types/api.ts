/**
 * Data Maskit API 类型定义
 * 与 panel.py / event_store.py 真实返回结构对齐（改动后端字段时同步更新）
 */

// ========== 代理状态（/api/status） ==========
export interface UpstreamStatus {
  name: string
  port: number
  listening: boolean
  url: string
  target: string
}

export interface UpstreamConfig {
  name: string
  port: number
  target: string
  base_path?: string
  paths?: string[]
  api_key_header?: string
  extra_headers?: Record<string, string>
  use_proxy?: boolean
}

export interface EgressProxy {
  enabled: boolean
  url: string
}

export interface ProxyStatus {
  version: string
  panel_pid: number
  proxy_running: boolean
  proxy_starting?: boolean
  proxy_stopping?: boolean
  proxy_pid: number | null
  passthrough: boolean
  /** 当前兜底形态："" / "passthrough" / "error" */
  fallback_mode: string
  upstream: string
  capture_mode: 'reverse' | 'explicit' | 'local'
  proxy_port: number
  proxy_url: string
  upstreams: UpstreamConfig[]
  upstream_ports: UpstreamStatus[]
  admin: boolean
  ca_cert_exists: boolean
  uptime: number
  auto_recovered_at: string | null
  auto_recover_fail: string
  data_root: string
  db_size_mib: number
  autostart: boolean
  filter_enabled: boolean
  fail_closed: boolean
  response_scan: boolean
  /** 敏感词统计是否记录明文（默认 true）。关闭后 daily_words 只存打码形态 */
  record_plaintext_words: boolean
  stream_response: boolean
  stream_exclude_hosts: string[]
  stop_mode: 'error' | 'passthrough' | 'block'
  egress_proxy: EgressProxy
  egress_proxy_users: string[]
  debug: boolean
  start_minimized: boolean
  auto_start_proxy: boolean
  audit: Record<string, unknown>
  needs_ca: boolean
  wizard_recommended: boolean
  last_error: string
}

// ========== 事件（/api/logs） ==========
export type EventType =
  | 'MASK'
  | 'RESTORE'
  | 'PASS'
  | 'BYPASS'
  | 'SKIP'
  | 'BLOCK'
  | 'ERR'
  | 'SCAN_WARN'
  | 'CANCEL'
  | 'DNS_ERROR'

/** slim 列表中的 items（无 original 明文） */
export interface SlimItem {
  label: string
  preview: string
}

/** 详情回源（/api/logs/detail）中的完整 item */
export interface EventItem extends SlimItem {
  original?: string
  tok?: string
  sha256?: string
  length?: number
}

export interface ShieldEvent {
  id: number
  /** epoch 秒 */
  ts: number
  type: EventType
  sid: string
  host: string
  method: string
  path: string
  status?: string
  http_status?: number
  count: number
  restored: number
  /**
   * 查不到原文、原样透传给客户端的占位符数（仅 RESTORE 事件）。
   * >0 多数意味着模型自造了一个我们从未生成过的占位符——它把
   * {{LABEL_hex6}} 的随机后缀当成可计算的数字改写了。这类占位符
   * 无法还原（对应的原文从不存在），只能如实告诉用户。
   */
  unresolved?: number
  /**
   * 靠宽松兜底修回来的占位符数（仅 RESTORE 事件）。模型把 {{}} 剥掉或写残时，
   * _LOOSE_PLACEHOLDER_RX 捞回来的那些。是成功路径，但值得看见——
   * 它说明模型在改写输出格式，是「哪天彻底还原不回来」的前兆。
   */
  degraded?: number
  items: SlimItem[] | EventItem[]
  dialog?: string
  dialog_req?: string
  dialog_resp?: string
  req_preview?: string
  resp_preview?: string
  stream_mode?: 'stream' | 'whole'
  stream_actual?: 'stream' | 'whole' | 'stream_error'
  mask_ms?: number
  first_byte_ms?: number
  upstream_ms?: number
  total_ms?: number
  /** 本次请求估算费用（USD，后端按 model×usage×价格表估算，仅 RESTORE 事件带） */
  cost_usd?: number
  model?: string
  client_app?: string | number
  upstream?: string
  reason?: string
  msg?: string
  seq: number
}

export interface LogsResponse {
  events: ShieldEvent[]
  tail: string[]
  retention_days: number
  store: string
  db: string
  sensitive_only: boolean
  total: number
}

export interface LogDetailResponse {
  ok: boolean
  event?: ShieldEvent
  error?: string
}

// ========== 今日统计（/api/stats/today） ==========
export interface TodayStats {
  requests: number
  alerts: number
  /** MASK 事件数（真实字段 mask_events） */
  mask_events: number
  /** 脱敏词项总数（真实字段 masked_items） */
  masked_items: number
  restored: number
  restore_ok: number
  restore_failed: number
  tokens: { prompt: number; completion: number }
  by_label: Record<string, number>
  top_words: { label: string; word: string; count: number }[]
  [key: string]: unknown
}

// ========== 配置（/api/config） ==========
export interface MaskRule {
  label: string
  pattern?: string
  enabled?: boolean
  type?: string
  [key: string]: unknown
}

export interface ShieldConfig {
  upstreams: UpstreamConfig[]
  fail_closed: boolean
  filter_enabled: boolean
  response_scan: boolean
  /** 敏感词统计是否记录明文（默认 true）。关闭后 daily_words 只存打码形态 */
  record_plaintext_words: boolean
  stream_response: boolean
  stream_exclude_hosts: string[]
  stop_mode: 'error' | 'passthrough' | 'block'
  egress_proxy: EgressProxy
  capture_mode: 'reverse' | 'explicit' | 'local'
  model_prices?: Record<string, { input: number; output: number }>
  price_sync_enabled?: boolean
  price_sync_url?: string
  autostart: boolean
  auto_start_proxy: boolean
  start_minimized: boolean
  debug: boolean
  log_retention_days?: number
  session_ttl?: number
  diagnostic_unmatched?: boolean
  http2?: boolean
  target_domains?: string[]
  api_paths?: string[]
  wizard_done?: boolean
  data_root?: string
  db_size_mib?: number
  sensitive?: Record<string, string[]>
  sensitive_disabled?: string[]
  sensitive_word_disabled?: Record<string, string[]>
  /** 整词匹配开关：开启后该词两侧加边界（审计规则专项 P2） */
  sensitive_word_whole?: string[]
  builtin_rules?: Record<string, boolean>
  secret_prefixes?: string[]
  audit?: Record<string, unknown>
  _meta?: {
    builtin_rule_meta: Record<string, unknown>
    version: string
  }
  [key: string]: unknown
}

// ========== 审计（/api/audit/*，与 panel.py/event_store.py 真实结构对齐） ==========
export type AuditSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface AuditEvent {
  seq: number
  /** epoch 秒 */
  ts: number
  sid?: string
  host?: string
  method?: string
  path?: string
  signal_type: string
  severity: AuditSeverity
  evidence?: string
  probe_id?: string
  request_hash?: string
  response_hash?: string
  [key: string]: unknown
}

export interface AuditEventsResponse {
  events: AuditEvent[]
  count: number
}

export interface AuditJob {
  running: boolean
  started_at?: number
  done?: number
  total?: number
  phase?: string
  error?: string
  result?: unknown
  [key: string]: unknown
}
