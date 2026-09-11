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
  // 已成对（MASK+RESTORE 已合并）的 sid：再来的同类事件必须独立成行，绝不静默覆盖已成对的那行
  const paired = new Set<string>()
  const independent: MergedEvent[] = []
  for (const e of filtered) {
    const sid = e.sid || ''
    // 仅 MASK 与 RESTORE 参与会话往返链路合并；其余类型（ERR/BLOCK/SCAN_WARN/CANCEL 等）即便带 sid 也必须独立成行展示，绝不吞日志
    if (!sid || (e.type !== 'MASK' && e.type !== 'RESTORE')) {
      independent.push({ ...e, _audit: false, _detailSeq: undefined })
      continue
    }
    const existing = bySid.get(sid)
    if (!existing) {
      bySid.set(sid, { ...e, _audit: false, _detailSeq: undefined })
    } else if (paired.has(sid)) {
      // 该 sid 已合并成对，第三次及以后的事件独立成行，防止把已合并行的耗时/费用/还原数覆盖掉
      independent.push({ ...e, _audit: false, _detailSeq: undefined })
    } else if (
      (existing.type === 'MASK' && e.type === 'RESTORE') ||
      (existing.type === 'RESTORE' && e.type === 'MASK')
    ) {
      // 真正成对的 MASK + RESTORE：合并为一条往返链路行
      const m = existing.type === 'MASK' ? existing : e
      const r = existing.type === 'RESTORE' ? existing : e
      const merged: MergedEvent = {
        ...m,
        _audit: false,
        http_status: r.http_status ?? m.http_status,
        upstream_ms: r.upstream_ms ?? m.upstream_ms,
        total_ms: r.total_ms ?? m.total_ms,
        status: r.status ?? m.status,
        restored: r.restored ?? m.restored,
        unresolved: r.unresolved ?? m.unresolved,
        degraded: r.degraded ?? m.degraded,
        stream_actual: r.stream_actual ?? m.stream_actual,
        cost_usd: r.cost_usd ?? m.cost_usd,
        model: r.model || m.model || '',
        _detailSeq: r.seq,
        upstream: r.upstream || m.upstream || '',
      }
      bySid.set(sid, merged)
      paired.add(sid)
    } else {
      // 同一 sid 出现两个同类事件时，独立成行，防静默覆盖
      independent.push({ ...e, _audit: false, _detailSeq: undefined })
    }
  }

  const ev = [...bySid.values(), ...independent].map((e) => ({ ...e, _audit: false as const }))
  // 按 ts 降序（最新在前）
  return ev.sort((a, b) => (b.ts ?? 0) - (a.ts ?? 0))
}
