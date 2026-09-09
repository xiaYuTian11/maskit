/**
 * 普通事件日志的共享合并与排序逻辑（Dashboard 最近日志 与 Logs 拦截日志共用）。
 *
 * 需求背景：一次 LLM 请求会产生 MASK（请求脱敏）+ RESTORE（回复还原）两条事件，
 * 若原样展示会在一张表里占两行、且顺序按接口返回倒序不稳定，用户要求「一次请求
 * 对应一条日志」。因此按 sid 把 MASK/RESTORE 合成一行「往返链路」。
 *
 * 合并语义（与 Logs 页既有行为完全一致，勿改）：
 * - MASK 提供：ts/host/path/count(脱敏数)/upstream(客户端名)/mask_ms
 * - RESTORE 提供：restored/http_status/upstream_ms/total_ms/cost_usd/status/model
 * - unresolved/degraded 只在 RESTORE 事件上产生，必须带过来，否则合并行永远
 *   显示不出「未还原 / 兜底还原」。
 * - 详情回源优先 RESTORE 的 seq（_detailSeq），弹窗才能同时含请求+回复完整链路。
 * - 无 sid 的事件（CANCEL/DNS_ERROR/ERR/SCAN_WARN 等）不与任何行合并，保持独立。
 *
 * 审计行（SCAN_WARN 审计信号）由调用方在合并结果之上再并入，本模块不负责。
 */
import type { ShieldEvent } from '@/types/api'

/** 合并结果里的普通事件行。_audit=false 与审计行区分；_detailSeq 供详情回源。 */
export type MergedEvent = ShieldEvent & { _audit: boolean; _detailSeq?: number }

export interface MergeOptions {
  /** 事件类型筛选。传 "全部" 哨兵（FILTER_ALL）时不过滤，与 Logs 页常量对齐。 */
  filterType?: string
  /** 隐藏噪声（SKIP/PASS/BYPASS/CANCEL/DNS_ERROR），默认 false。 */
  hideNoise?: boolean
}

/** Logs 页「全部类型」筛选项的值（哨兵，不会与事件类型撞）。 */
export const FILTER_ALL = '__ALL__'

/** 隐藏噪声时排除的非链路事件类型（与 Logs 页既有常量一致）。 */
const NOISE_TYPES = new Set(['SKIP', 'PASS', 'BYPASS', 'CANCEL', 'DNS_ERROR'])

/**
 * 把普通事件列表合并为「一次请求一行」并按 ts 最新在前排序。
 *
 * @param events 原始事件列表（ShieldEvent[]）
 * @param opts 筛选选项；缺省时全部保留、不隐藏噪声
 * @returns 合并后的行，最新 ts 在前
 */
export function mergeMaskRestore(events: readonly ShieldEvent[], opts: MergeOptions = {}): MergedEvent[] {
  const { filterType, hideNoise } = opts
  const filtered = events.filter(
    (e) =>
      (filterType === undefined || filterType === FILTER_ALL || e.type === filterType) &&
      (!hideNoise || !NOISE_TYPES.has(e.type)),
  )

  const bySid = new Map<string, MergedEvent>()
  const noSid: MergedEvent[] = []
  for (const e of filtered) {
    const sid = e.sid || ''
    if (!sid) {
      noSid.push({ ...e, _audit: false, _detailSeq: undefined })
      continue
    }
    const existing = bySid.get(sid)
    if (!existing) {
      bySid.set(sid, { ...e, _audit: false, _detailSeq: undefined })
    } else if (e.type === 'RESTORE' || existing.type === 'RESTORE') {
      // 同 sid 的 MASK + RESTORE：RESTORE 的耗时/费用/状态/还原数/模型补到主行
      const merged: MergedEvent = { ...existing }
      if (e.type === 'RESTORE') {
        merged.http_status = e.http_status ?? merged.http_status
        merged.upstream_ms = e.upstream_ms ?? merged.upstream_ms
        merged.total_ms = e.total_ms ?? merged.total_ms
        merged.status = e.status ?? merged.status
        merged.restored = e.restored ?? merged.restored
        // unresolved 只在 RESTORE 事件上产生，不带过来的话合并行永远显示不出「未还原」
        merged.unresolved = e.unresolved ?? merged.unresolved
        merged.degraded = e.degraded ?? merged.degraded
        merged.stream_actual = e.stream_actual ?? merged.stream_actual
        merged.cost_usd = e.cost_usd ?? merged.cost_usd
        merged.model = e.model ?? merged.model
        // 详情弹窗回源 RESTORE（含请求+回复完整链路）
        merged._detailSeq = e.seq
        if (!merged.upstream) merged.upstream = e.upstream ?? ''
      }
      bySid.set(sid, merged)
    }
    // 其余类型（CANCEL/DNS_ERROR/ERR/SCAN_WARN 等）不与 MASK 合并，保持独立行
  }

  const ev = [...bySid.values(), ...noSid].map((e) => ({ ...e, _audit: false as const }))
  // 按 ts 降序（最新在前）
  return ev.sort((a, b) => (b.ts ?? 0) - (a.ts ?? 0))
}