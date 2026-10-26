/**
 * 一次请求的「结论」推导 —— 列表「结论」列的唯一取值来源。
 *
 * ## 为什么需要它
 *
 * 列表原先的「结果」列渲染的是**事件类型**（MASK / RESTORE / CANCEL / ERR …）。而一次
 * LLM 请求会产生 MASK（请求脱敏）与 RESTORE（回复还原）两条事件，前端按 sid 合并成
 * 一行、合并行保留 MASK 的 type —— 于是「脱敏成功」「客户端取消」「上游 502」在列表里
 * **长得一模一样**（都是「脱敏」），用户根本无法判断成功还是失败。
 *
 * 结论把「发生了什么类型的事件」升维成「这次请求最终怎么了」：类型降级为图标与详情，
 * 结论承担主判据。判据全部取自引擎已经落库的事实（http_status / unresolved / degraded /
 * decision / completeness / 终态事件类型），不新增任何推断性字段。
 *
 * ## 设计约束
 *
 * - **纯函数**：与时间有关的判据（进行中 / 未完成）由调用方传入 `nowSec`，用例才能固定
 *   时间轴。不读 DOM、不引 React、不引 lucide-react —— `scripts/check-log-outcome.mjs`
 *   用 `node --experimental-strip-types` 直接跑本文件，引了 React 就跑不起来。
 * - 图标与颜色属于展示层，放在 `components/events/OutcomeBadge.tsx`；本文件只给 i18n key。
 */

/** 结论：一次请求最终怎么了。与「事件类型」正交 —— 类型说明发生了什么，结论说明结果如何。 */
export type OutcomeKey =
  | 'success'
  | 'warn'
  | 'failed'
  | 'canceled'
  | 'pending'
  | 'incomplete'
  | 'passthrough'
  | 'alert'

/**
 * 下拉与图例的展示顺序：成功 → 需要注意 → 失败 → 未决 → 未处理 → 安全告警。
 * 与 `OUTCOME_META`（展示层）共用同一份顺序，避免两处各排一遍而漂移。
 */
export const OUTCOME_ORDER: readonly OutcomeKey[] = [
  'success',
  'warn',
  'failed',
  'canceled',
  'pending',
  'incomplete',
  'passthrough',
  'alert',
]

/** 结论 → i18n 标签 key。 */
export const OUTCOME_LABEL_KEY: Record<OutcomeKey, string> = {
  success: 'logs.outcome.success',
  warn: 'logs.outcome.warn',
  failed: 'logs.outcome.failed',
  canceled: 'logs.outcome.canceled',
  pending: 'logs.outcome.pending',
  incomplete: 'logs.outcome.incomplete',
  passthrough: 'logs.outcome.passthrough',
  alert: 'logs.outcome.alert',
}

/** 结论 → i18n 提示 key（徽标悬停显示，解释「为什么是它」）。 */
export const OUTCOME_HINT_KEY: Record<OutcomeKey, string> = {
  success: 'logs.outcomeHint.success',
  warn: 'logs.outcomeHint.warn',
  failed: 'logs.outcomeHint.failed',
  canceled: 'logs.outcomeHint.canceled',
  pending: 'logs.outcomeHint.pending',
  incomplete: 'logs.outcomeHint.incomplete',
  passthrough: 'logs.outcomeHint.passthrough',
  alert: 'logs.outcomeHint.alert',
}

/**
 * 「进行中」与「未完成」的分界（秒）。
 *
 * 依据（均为引擎已有常量，不另立标准）：端到端预算是 `_ENGINE_DEADLINE_S = 120s`
 * （engine/transparent.py），流空闲看门狗同样是 120s。超过这个预算仍没有终态记录，
 * 说明终态**不会再被写出来了**（上游未按规范收尾、引擎未收尾、或记录丢失），而不是
 * 「还在跑」。留 60s 余量，避免把慢请求误判成未完成。
 */
export const IN_FLIGHT_WINDOW_S = 180

/** 结论推导需要的最小输入面：MergedEvent 与审计行都能满足。 */
export interface OutcomeInput {
  /** 事件类型（MASK / RESTORE / CANCEL / ERR / BLOCK / PASS / BYPASS / SKIP / SCAN_WARN / DNS_ERROR） */
  type: string
  /** 事件时间（epoch 秒）；合并行取 MASK 的 ts，即请求进入时刻 */
  ts?: number
  /**
   * 本行折叠到的终态事件类型（由 `mergeMaskRestore` 写入）。
   * 缺省 = 这行没有终态记录（只有请求侧）。注意折叠行的 `type` 仍是 MASK，
   * 只看 `type` 会把「已取消」误判成「进行中」。
   */
  terminal?: 'RESTORE' | 'CANCEL' | 'ERR'
  http_status?: number
  /** 本机签发过、但映射已丢（复用表淘汰 / 重启后未预热）的占位符数（RESTORE） */
  unresolved?: number
  /** 非本机签发的占位符形态字符串数（RESTORE）。**不触发告警**，只用中性色展示 */
  foreign?: number
  /** 靠宽松兜底修回来的占位符数（RESTORE） */
  degraded?: number
  /** 处置结论（MASK）：masked / scanned_clean / blocked / passthrough */
  decision?: string
  /** 检测完整度（MASK）：complete / partial / failed / not_applicable / unknown */
  completeness?: string
  /** 终态归因（CANCEL / ERR）：原因签名 */
  reason?: string
  /** 终态归因（CANCEL / ERR）：责任方 client / dns / proxy / engine / upstream */
  failure_owner?: string
  /** 终态归因（ERR）：异常类名 */
  error_type?: string
  /** 终态归因（CANCEL）：上游连续静默秒数（reason=upstream_idle 的证据） */
  upstream_idle_s?: number
}

/**
 * 推导一次请求的结论。
 *
 * @param row 事件（合并后）行
 * @param nowSec 当前时间（epoch 秒）；由调用方注入，保证纯函数可测
 * @returns 结论 key
 */
export function deriveOutcome(row: OutcomeInput, nowSec: number): OutcomeKey {
  const type = row.type

  // 安全审计信号不是「一次请求的归宿」，单独成一类（列表里用琥珀底色 + 信号名区分）
  if (type === 'SCAN_WARN') return 'alert'

  // 折叠后的终态优先：脱敏行折进 CANCEL/ERR 时 type 仍是 MASK，必须看 terminal
  if (row.terminal === 'CANCEL' || type === 'CANCEL') return 'canceled'
  if (row.terminal === 'ERR' || type === 'ERR') return 'failed'
  // BLOCK 事件有两种形态（2026-10-26 用户第一准则）：
  //   · decision='blocked' —— 真拦截，请求没上行 → 失败
  //   · decision='flagged' —— 出口复检**只记录**（请求照常上行）→ 告警而非失败
  // 一律判 failed 会让用户以为请求被拦了（它明明成功），而且列表满屏红色。
  if (type === 'BLOCK') return row.decision === 'flagged' ? 'warn' : 'failed'

  // 没有走脱敏管线的事件：透传 / 绕过 / 跳过
  if (type === 'PASS' || type === 'BYPASS' || type === 'SKIP') return 'passthrough'
  // DNS 失败不是本机故障（AGENTS.md 红线：CANCEL / DNS_ERROR 视觉上不归为红色），
  // 但请求确实没走通，所以进「有告警」而不是「成功」
  if (type === 'DNS_ERROR') return 'warn'

  // 处置结论（MASK 侧）：阻断是失败。注意**不把 decision='passthrough' 判成「未处理」** ——
  // 那是一次正常完成的请求（引擎看过并决定不扫描），「直通未脱敏」由处理摘要列的
  // statePassthrough 徽标单独表达；把它塞进结论会让「未处理」筛选同时命中两类不同东西。
  if (row.decision === 'blocked') return 'failed'

  const hasTerminal = row.terminal === 'RESTORE' || type === 'RESTORE'
  if (!hasTerminal) {
    // 只有请求侧记录：响应侧终态还没落库
    if (!row.ts) return 'incomplete'
    return nowSec - row.ts <= IN_FLIGHT_WINDOW_S ? 'pending' : 'incomplete'
  }

  // 有终态（RESTORE）：按严重度依次判定
  if ((row.http_status ?? 0) >= 400) return 'failed'
  if ((row.unresolved ?? 0) > 0) return 'warn'
  if ((row.degraded ?? 0) > 0) return 'warn'
  if (row.completeness === 'partial' || row.completeness === 'failed') return 'warn'
  return 'success'
}

/** 终态原因文案（状态列显示）：i18n key + 插值变量。 */
export interface TerminalText {
  key: string
  vars?: Record<string, string | number>
}

/**
 * 把 CANCEL / ERR 的归因字段翻成状态列能显示的一句短语。
 *
 * 取值来源（engine/transparent.py）：
 * - CANCEL `reason`：`client_disconnected`（客户端断开，含 SDK 超时）/ `client_cancelled`
 *   （真的看到客户端取消）/ `upstream_idle`（上游静默到看门狗阈值被掐，此时
 *   `failure_owner` 也被改判为 upstream）。
 * - ERR `failure_owner`：client / dns / proxy / engine / upstream。
 *
 * 返回 null 表示没有可显示的归因（此时状态列显示「—」）。
 */
export function describeTerminal(row: OutcomeInput): TerminalText | null {
  if (row.reason === 'upstream_idle') {
    const s = row.upstream_idle_s
    return Number.isFinite(s) ? { key: 'logs.term.upstreamIdle', vars: { s: Math.round(s as number) } } : { key: 'logs.term.upstreamIdleNoSec' }
  }
  if (row.reason === 'client_cancelled') return { key: 'logs.term.clientCancelled' }
  if (row.reason === 'client_disconnected') return { key: 'logs.term.clientDisconnected' }
  switch (row.failure_owner) {
    case 'client':
      return { key: 'logs.term.clientDisconnected' }
    case 'dns':
      return { key: 'logs.term.dns' }
    case 'proxy':
      return { key: 'logs.term.proxy' }
    case 'engine':
      return { key: 'logs.term.engine' }
    case 'upstream':
      return { key: 'logs.term.upstream' }
    default:
      return null
  }
}

/** 结论筛选的哨兵前缀。后端按 `type` 精确过滤，结论是前端派生量，因此走客户端筛选。 */
export const OUTCOME_FILTER_PREFIX = 'OUTCOME:'

/** 结论 → 筛选哨兵值。 */
export function outcomeFilterValue(key: OutcomeKey): string {
  return OUTCOME_FILTER_PREFIX + key
}

/** 筛选哨兵值 → 结论；不是结论筛选时返回 null。
 *
 * **大小写不敏感**：Logs 页从 URL 回填 `?type=` 时会整体 `toUpperCase()`（对原语 MASK/CANCEL
 * 是对的），如果这里区分大小写，`OUTCOME:success` 会变成 `OUTCOME:SUCCESS` 而失配 ——
 * 后果是筛选器空白 + 列表一条不剩，且不报错。
 */
export function outcomeFromFilter(value: string): OutcomeKey | null {
  const raw = (value || '').trim()
  if (raw.length <= OUTCOME_FILTER_PREFIX.length) return null
  if (raw.slice(0, OUTCOME_FILTER_PREFIX.length).toUpperCase() !== OUTCOME_FILTER_PREFIX) return null
  const key = raw.slice(OUTCOME_FILTER_PREFIX.length).toLowerCase()
  return (OUTCOME_ORDER as readonly string[]).includes(key) ? (key as OutcomeKey) : null
}
