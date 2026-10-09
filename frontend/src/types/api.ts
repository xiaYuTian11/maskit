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

export interface ConnectionPolicy {
  reuse: 'default' | 'never'
  idle_ttl_s: number | null
  connect_timeout_s: number
  tls_handshake_timeout_s: number
}

export interface TransportCapabilities {
  supported?: boolean
  deadlines?: boolean
  http1_reuse_policy?: boolean
  observation?: boolean
  observation_reason?: string | null
  stream_cancellation?: boolean
  stream_cancellation_reason?: string | null
  version?: string
  reason?: string
}

export interface TransportEvidence {
  phase?: string
  reason?: string | null
  server_conn_id?: string | null
  reused?: boolean | null
  idle_s?: number | null
  connect_ms?: number | null
  tls_ms?: number | null
  protocol?: string
  via_proxy?: boolean | null
  evidence?: string
  evidence_complete?: boolean | null
  request_written?: boolean | null
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
  takeover?: boolean
  connection_policy?: ConnectionPolicy | null
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
  /**
   * 语义实体识别（NER）状态：enabled 是开关，available/initialized 是实际可用性。
   *
   * `skips` 是「开启了但这段没做识别」的原因计数（`too_long` / `budget_exhausted` /
   * `infer_failed` / `deadline` / `init_failed` / `model_missing`）。纯整数、不含原文。
   * 不透出它的话，「开了 NER，长文本全跳过」在界面上完全看不出（审计 M7）。
   */
  ner?: {
    enabled: boolean
    available: boolean
    initialized: boolean
    reason: string
    skips?: Record<string, number>
    /**
     * 单请求语义识别预算上限（秒，P0-a）：这是**配置值**。
     * 引擎侧实际生效值（环境变量可硬覆盖）见 `/api/engine/metrics` 的 `ner.req_budget_s`。
     */
    req_budget_s?: number
    /** `MASKIT_NER_REQ_BUDGET_S` 是否已设置（设置后配置项改不动，界面必须提示） */
    budget_env_override?: boolean
    /** 缓存冷热计数（本进程视角；代理链路真值在 engine-runtime.json） */
    cache?: { hit?: number; miss?: number; hit_rate?: number | null }
    /**
     * 治理器实际生效值（批次 8）：并发、预算容量与**单位**、可用核数、ONNX 线程数。
     * 单位是 `cpu_ms_per_s`（CPU 毫秒/秒），不是墙钟——旧口径按墙钟计，同样的
     * 数字实际能吃掉近两倍 CPU。用户问「为什么 CPU 跑满」时先看 `cpu_cores`
     * 与本机核数是否对得上（容器里旧版会按宿主核数配）。
     */
    governor?: {
      concurrency?: number
      budget_ms_per_s?: number
      budget_unit?: string
      cpu_cores?: number
      cpu_threads?: number
      bucket_tokens_ms?: number
      skipped_throttled?: number
      skipped_sem_timeout?: number
      wait_ms_total?: number
      wait_ms_max?: number
    }
  }
  /**
   * 敏感词表生效口径：`configured`/`regex_words` 来自配置，`engine_count`/`issues`
   * 来自**引擎进程**经 engine-runtime.json 外发的真值。
   *
   * 为什么要分开：2026-09-30 事故里整张词表因一个 `re:` 词编译失败而静默失效，
   * 面板只看配置的话显示一切正常，用户却什么都脱敏不了。
   * `issues` 是「词 -> 原因」，词本身是用户自己的配置内容，不含请求原文。
   */
  words?: {
    configured: number
    regex_words: number
    engine_count: number | null
    issues: Record<string, string>
    engine_stale: boolean
  }
  needs_ca: boolean
  wizard_recommended: boolean
  last_error: string
  /** MASKIT_PANEL_TOKEN 太短/非 ASCII 被忽略（面板改用随机 token），前端弹一次性提醒 */
  panel_token_env_rejected?: boolean
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
  transport?: TransportEvidence
  failure_phase?: string
  upstream_may_have_executed?: boolean
  ner_init_ms?: number
  ner_infer_ms?: number
  ner_budget_wait_ms?: number
  ner_calls?: number
  ner_windows?: number
  ner_cache_hits?: number
  ner_cache_misses?: number
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
  /** 未还原占位符样本（引擎侧外发；仅未还原时存在，用于区分模型改写与映射丢失） */
  unresolved_samples?: string[]
  /**
   * 靠宽松兜底修回来的占位符数（仅 RESTORE 事件）。模型把 {{}} 剥掉或写残时，
   * _LOOSE_PLACEHOLDER_RX 捞回来的那些。是成功路径，但值得看见——
   * 它说明模型在改写输出格式，是「哪天彻底还原不回来」的前兆。
   */
  degraded?: number
  /**
   * 本轮语义识别（NER）是否发生降级：true = 有字符串叶子没走语义识别。
   * **只在降级时后端才写这个键**（正常一轮没有它）；原因与条数见 ner_skip_reasons。
   * MASK 与 RESTORE 两条事件都带（详情弹窗按 _detailSeq 回源 RESTORE）。
   */
  ner_truncated?: boolean
  /** 降级明细：原因 → 本轮由此原因跳过的叶子数。键见 EventDetailDialog 的 NER_SKIP_LABELS。 */
  ner_skip_reasons?: Record<string, number>
  /**
   * 批次 2 统一检测口径：本次请求的处置结论。四种状态此前在列表里都表现为「0 命中」，
   * 现在分开：已脱敏 / 已扫描未命中 / 主动阻断 / 明确直通（未脱敏）。
   */
  decision?: 'masked' | 'scanned_clean' | 'blocked' | 'passthrough'
  /** 所配置的检测执行到什么程度；complete 只表示「已执行完」，不保证现实无漏检。 */
  completeness?: 'complete' | 'partial' | 'failed' | 'not_applicable' | 'unknown'
  /** 原因码计数（NER 降级 / 协议契约豁免 / 阻断原因），键见 EventDetailDialog 的标签表。 */
  reason_codes?: Record<string, number>
  /** 签名思考块整块未扫描的块数（协议契约豁免，属漏检路径故必须可见）。 */
  signed_blocks_skipped?: number
  items: SlimItem[] | EventItem[]
  dialog?: string
  dialog_req?: string
  dialog_resp?: string
  req_preview?: string
  resp_preview?: string
  stream_mode?: 'stream' | 'whole'
  stream_actual?: 'stream' | 'whole' | 'stream_error'
  /**
   * A-7：本次的 503/错误是**谁**造成的。
   * upstream = 上游/中转返回的（Maskit 只是如实记录）；engine = 本机 fail-closed 拦的；
   * fallback = 代理已停时兜底层占位回的。没有这个字段，用户只能靠猜。
   */
  block_source?: 'upstream' | 'engine' | 'fallback'
  /** 队列满被拒（engine_busy）时的现场数据，用于判断"是我并发太高还是机器太小" */
  engine_busy?: boolean
  engine_queue_depth?: number
  engine_queue_bytes?: number
  /** 语义识别因全局速率预算/信号量被跳过时的计数与等待时长 */
  ner_global_throttled?: number
  ner_sem_wait_ms?: number
  /** C-2：本该流式却走整包的原因（content_encoding:gzip / excluded_host / non_sse） */
  stream_degraded_reason?: string
  /** 脱敏池排队时长（毫秒）：只在本条真的排过队（≥1ms）时才带 */
  queue_wait_ms?: number
  /** 响应侧等待脱敏线程池的时长（毫秒）：只在本条等超过阈值（默认 2s）时才带 */
  aux_wait_ms?: number
  /**
   * 上游连续静默的秒数：`reason=upstream_idle` 的证据。
   * 只有「被本机连接空闲看门狗断开」这个结论而没有秒数时，用户分不清它和一次普通取消。
   */
  upstream_idle_s?: number
  mask_ms?: number
  first_byte_ms?: number
  upstream_ms?: number
  total_ms?: number
  /** 本次请求估算费用（USD，后端按 model×usage×价格表估算，仅 RESTORE 事件带） */
  cost_usd?: number
  model?: string
  client_app?: string | number
  upstream?: string
  /**
   * 入口维度：`proxy`=CLI 代理链路，`ext`=浏览器扩展链路。
   * **老数据/导入事件该列为空，读取时按 `proxy` 解读**（不要渲染成"—"）。
   */
  ingress?: 'proxy' | 'ext'
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
  /** Older engines may not include pagination metadata. */
  has_more?: boolean
  next_since?: number
  /** 游标重置（清空日志/库隔离重建后 id 从 1 重新开始）：丢弃旧游标从 0 重拉 */
  reset?: boolean
  /** 反向游标（§D3.1）：更早处还有符合当前筛选的行 */
  has_older?: boolean
  /** 下一页的 `before_seq`（本页最旧一条的 seq）；未反向翻页时为 0 */
  before_cursor?: number
  /** 当前**实际生效**的日志写入模式（§D1）：summary/detailed/trace */
  log_mode?: LogMode
  /** 限时排障窗口的截止时间戳（秒）；0 表示未开启 */
  trace_until?: number
}

/** 日志写入模式（§D1）：summary=最小记录；detailed=本地详细；trace=限时排障 */
export type LogMode = 'summary' | 'detailed' | 'trace'

/** /api/logs/mode */
export interface LogModeState {
  ok: boolean
  /** 持久模式（summary/detailed） */
  mode: 'summary' | 'detailed'
  /** 实际生效模式（排障窗口内为 trace） */
  effective: LogMode
  trace_active: boolean
  trace_until: number
}

export interface LogDetailResponse {
  ok: boolean
  event?: ShieldEvent
  error?: string
}

// ========== 今日统计（/api/stats/today） ==========
/**
 * 前缀保真度：MASK 事件三个诊断字段的聚合（engine/event_store._prefix_payload）。
 *
 * 回答「上游 Prompt Cache 命中率归零，是我们改了请求字节还是上游自己 miss」——
 * clean_rate 是请求体一个字节都没被改动的比例（分母 masks），reuse_rate 是
 * **在改写过的请求里**沿用复用表旧 token 的比例（分母 rewritten —— 零改写透传的
 * 请求没签发票据，算进来只会稀释），avg_first_diff 是回写后与客户端原始字节首个
 * 差异位置的平均值。
 */
export interface PrefixStats {
  /** 区间内 MASK 事件数（分母） */
  masks: number
  /** 其中回写过请求体的次数 */
  rewritten: number
  /** body_rewritten=false 的次数（零改写透传） */
  clean: number
  /** 零改写透传占比（0~1） */
  clean_rate: number
  /** 命中占位符沿用复用表旧 token 的次数 */
  suffix_reused: number
  /** 占位符复用占比（0~1，分母是 rewritten）；区间内无回写请求时为 null */
  reuse_rate: number | null
  /** 首个差异字节均值；样本全被上限挡掉时为 null */
  avg_first_diff: number | null
  /** 计入 avg_first_diff 的样本数（0 表示均值不可用） */
  diff_samples: number
}

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
  /**
   * 前缀保真度。**null = 本区间没有 MASK 事件样本**（空库 / 老库升级当天），
   * 与「有样本但零改写率为 0」是两回事，渲染时必须分开。
   */
  prefix?: PrefixStats | null
  by_label: Record<string, number>
  top_words: { label: string; word: string; count: number }[]
  /**
   * 词表**按入口分组**的同一份数据（key: `proxy` / `ext`）。分组同屏而非过滤：
   * 浏览器扩展链路的量级远大于 CLI，混算会把邮箱/电话这类高频词刷上榜，
   * 压掉用户真正关心的业务密钥词；分组后各组各取 Top N，两组都可见。
   */
  words_by_ingress?: Record<string, IngressWordGroup>
  [key: string]: unknown
}

/** 单个入口（proxy=CLI 代理链路 / ext=浏览器扩展链路）的词表视图。 */
export interface IngressWordGroup {
  by_label: Record<string, number>
  by_label_words: Record<string, { word: string; count: number }[]>
  top_words: { label: string; word: string; count: number }[]
  /** 该入口下的命中总数（组头计数；与 top_words 的 Top N 截断无关） */
  label_total: number
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
  /** 控制面 Origin 校验开关（默认 true）。反代/CDN 回源 Origin 不匹配致面板 403 时可关 */
  origin_check?: boolean
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
  /** 更新检查源（留空 = 内置源：GitHub 静态 latest.json → GitHub API）。
   *  国内/内网服务器连不上 GitHub 时填镜像或自建中转。 */
  update_check_url?: string
  autostart: boolean
  auto_start_proxy: boolean
  start_minimized: boolean
  debug: boolean
  log_retention_days?: number
  session_ttl?: number
  /**
   * 单请求语义识别预算上限（秒，P0-a）。
   * 环境变量 MASKIT_NER_REQ_BUDGET_S 存在时硬盘覆盖本项（界面会提示）。
   */
  ner_req_budget_s?: number
  diagnostic_unmatched?: boolean
  http2?: boolean
  /** 浏览器扩展链路总开关（默认关）。关闭时三个 /api/ext/* 端点 403 `ext_bridge_disabled` */
  ext_bridge_enabled?: boolean
  /**
   * 扩展访问令牌。**面板只回显，不进任何日志/导出/诊断包**。
   * 轮换即扩展失效（403 invalid_token → 直通、未脱敏）直到用户在扩展设置里更新。
   */
  ext_token?: string
  /** 引擎不可达时扩展侧是否阻断（默认关=直通）。**只管 (B) 类**，(A) 类无开关 */
  ext_block_when_engine_down?: boolean
  /** 扩展链路是否写入本地事件库与统计（默认 true）。只管落库，不管脱敏 */
  ext_record_events?: boolean
  /** 扩展链路是否自动将老版 Office (.doc / .xls) 在内存转码为 .docx / .xlsx 脱敏发送（默认 true） */
  ext_convert_legacy_office?: boolean
  target_domains?: string[]
  api_paths?: string[]
  wizard_done?: boolean
  data_root?: string
  db_size_mib?: number
  sensitive?: Record<string, string[]>
  sensitive_disabled?: string[]
  sensitive_word_disabled?: Record<string, string[]>
  /** 整词匹配开关：开启后该词两侧加边界。 */
  sensitive_word_whole?: string[]
  builtin_rules?: Record<string, boolean>
  secret_prefixes?: string[]
  audit?: Record<string, unknown>
  _meta?: {
    builtin_rule_meta: Record<string, unknown>
    transport_capabilities?: TransportCapabilities
    warnings?: string[]
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
  /** A-1：本条审计的耗时 / 扫描字节 / 是否被预算截断（老数据为 null） */
  audit_ms?: number | null
  audit_scan_bytes?: number | null
  audit_scan_truncated?: boolean | null
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
