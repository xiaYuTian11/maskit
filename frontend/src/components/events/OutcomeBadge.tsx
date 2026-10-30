/**
 * 列表「结论」列的徽标：图标 + 颜色 + 文案（三处列表共用：Logs 页、Dashboard 最近事件）。
 *
 * 与 `EventTypeIcon` 的分工：`EventTypeIcon` 回答「发生了什么类型的事件」（脱敏 / 还原 /
 * 透传…），本组件回答「这次请求最终怎么了」（成功 / 失败 / 已取消…）。列表的**主判据**
 * 是结论，事件类型降级为详情与悬停。
 *
 * 颜色语义（与 `log-outcome.ts` 的分类一一对应）：
 * 成功绿 / 有告警琥珀 / 失败红 / 已取消与未处理中性灰 / 进行中蓝 / 安全告警琥珀。
 * 依据 AGENTS.md 红线：CANCEL 与 DNS_ERROR 不是本机故障，视觉上不归为红色。
 */
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  CircleDashed,
  CircleSlash,
  Loader2,
  ShieldAlert,
  XCircle,
  type LucideIcon,
} from 'lucide-react'
import { OUTCOME_HINT_KEY, OUTCOME_LABEL_KEY, type OutcomeKey } from '@/lib/log-outcome'
import { useI18n } from '@/lib/i18n'
import { cn } from '@/lib/utils'

interface OutcomeMeta {
  icon: LucideIcon
  /** 图标与文字的颜色类 */
  cls: string
  /** 图例色块类（带背景，用于图例里的圆点） */
  dot: string
  /** 是否让图标自转（仅「进行中」） */
  spin?: boolean
}

export const OUTCOME_META: Record<OutcomeKey, OutcomeMeta> = {
  success: { icon: CheckCircle2, cls: 'text-success-ink', dot: 'bg-success' },
  warn: { icon: AlertTriangle, cls: 'text-warning-ink', dot: 'bg-warning' },
  failed: { icon: XCircle, cls: 'text-destructive-ink', dot: 'bg-destructive' },
  canceled: { icon: CircleSlash, cls: 'text-muted-foreground', dot: 'bg-muted-foreground' },
  pending: { icon: Loader2, cls: 'text-primary-ink', dot: 'bg-primary', spin: true },
  incomplete: { icon: CircleDashed, cls: 'text-muted-foreground', dot: 'bg-muted-foreground' },
  passthrough: { icon: ArrowRight, cls: 'text-muted-foreground', dot: 'bg-muted-foreground' },
  alert: { icon: ShieldAlert, cls: 'text-warning-ink', dot: 'bg-warning' },
}

/**
 * 结论徽标。
 *
 * @param outcome 结论 key（由 `deriveOutcome` 推导）
 * @param hint 覆盖默认悬停提示（例如把「为什么是未完成」写得更具体）
 */
export function OutcomeBadge({
  outcome,
  hint,
  className,
}: {
  outcome: OutcomeKey
  hint?: string
  className?: string
}) {
  const { t } = useI18n()
  const meta = OUTCOME_META[outcome]
  const Icon = meta.icon
  return (
    <span className={cn('flex min-w-0 items-center gap-1', className)} title={hint ?? t(OUTCOME_HINT_KEY[outcome])}>
      <Icon className={cn('h-3.5 w-3.5 shrink-0', meta.cls, meta.spin && 'animate-spin')} />
      <span className={cn('truncate text-2xs font-medium', meta.cls)}>{t(OUTCOME_LABEL_KEY[outcome])}</span>
    </span>
  )
}
