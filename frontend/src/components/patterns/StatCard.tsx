import * as React from 'react'

import { cn } from '@/lib/utils'
import { Card } from '@/components/ui/card'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'

/**
 * 指标卡（KPI）的唯一实现。
 *
 * 为什么要有这个组件：控制台的 6 宫格与统计页的汇总卡视觉完全一致，此前却是
 * 两套代码（一个 `statCards` 数组 + 内联 className，一个独立的 `SummaryCard`）。
 * 同一视觉结果被实现两次，改一处漏一处，就是「风格不统一」的来源。
 *
 * 视觉纪律（改样式请改这里，不要在调用处覆盖）：
 * - 卡里有四样东西：图标（14px 单色，形状锚点）、标签（12px 灰）、数值（唯一主角）、
 *   脚注/子项（11px）。图标是必要的：6 张同构卡铺成网格时，纯文字标签没有任何
 *   可以「一眼定位」的锚点，整片看上去像表格；但它必须是单色的——给每张卡配彩底
 *   会把 12 个视觉元素送到用户眼前跟数字抢重心。
 * - 数值默认近黑；只有「异常值」上色（`tone`），0 与正常值保持中性
 * - 抬起/hover 只给真能点的卡；不可点的卡有 hover 等于骗点击
 */
export interface StatSubItem {
  label: string
  value: React.ReactNode
  /** 悬停说明（如「还原失败」的判定口径） */
  title?: string
}

export interface StatCardProps {
  label: string
  /** 标签左侧的识别图标（14px）：给同构卡一个形状锚点，不靠颜色 */
  icon?: React.ComponentType<{ className?: string }>
  /**
   * 图标的语义色。**默认灰**：只给「链路本身」上色（脱敏=primary / 还原=success /
   * 异常=warning），其余指标保持中性。全给彩色等于没有重点。
   */
  iconTone?: 'primary' | 'success' | 'warning' | 'muted'
  /** 已格式化好的显示值 */
  value: React.ReactNode
  /** 紧凑显示（1.2万）时的完整值，悬停展示；不传则不加 tooltip */
  fullValue?: string
  /** 脚注：说明口径或拆分明细 */
  hint?: React.ReactNode
  hintTitle?: string
  /** 子项：多指标并列（如告警卡下的 拦截/还原失败/错误） */
  sub?: StatSubItem[]
  /**
   * 数值强调色。**由调用方判断是否需要上色**（通常是「值 > 0 才传」）——
   * 组件不再从 value 里猜，因为 value 可能已经是格式化好的 ReactNode。
   */
  tone?: 'warning' | 'danger'
  /** lg = 32px（控制台 6 宫格，视距更远）；md = 26px（统计页，卡片更窄） */
  size?: 'md' | 'lg'
  /** 卡是否可点：为真才给 hover 抬起 + 手型光标 */
  interactive?: boolean
  onClick?: () => void
  className?: string
}

export function StatCard({
  label,
  icon,
  iconTone = 'muted',
  value,
  fullValue,
  hint,
  hintTitle,
  sub,
  tone,
  size = 'lg',
  interactive = false,
  onClick,
  className,
}: StatCardProps) {
  const toneCls = !tone
    ? 'text-foreground'
    : tone === 'danger'
      ? 'text-destructive-ink'
      : 'text-warning-ink'

  const numElement = (
    <div
      className={cn(
        'mb-1.5 mt-2.5 truncate font-semibold leading-none tabular-nums tracking-[-0.02em]',
        size === 'lg' ? 'text-[32px]' : 'text-[26px]',
        toneCls,
      )}
      title={fullValue || (typeof value === 'string' ? value : undefined)}
    >
      {value}
    </div>
  )

  const Icon = icon
  const iconCls =
    iconTone === 'primary'
      ? 'text-primary'
      : iconTone === 'success'
        ? 'text-success'
        : iconTone === 'warning'
          ? 'text-warning'
          : 'text-muted-foreground'

  return (
    <Card
      className={cn(
        'h-full transition-[transform,box-shadow,border-color] duration-200',
        interactive &&
          'cursor-pointer hover:-translate-y-0.5 hover:border-primary/30 hover:bg-accent/40 hover:shadow-card-hover',
        className,
      )}
      {...(onClick ? { onClick } : {})}
    >
      <div className="flex h-full flex-col p-4">
        <div className="flex items-center gap-1.5">
          {Icon && <Icon className={cn('h-3.5 w-3.5 shrink-0', iconCls)} />}
          <span className="min-w-0 truncate text-[12px] font-medium leading-5 text-muted-foreground">
            {label}
          </span>
        </div>
        {/* 数值行 flex-1 + 居中：网格等高时卡片会被最高的邻居撑高，数字贴顶会
            在卡底留出一大片空；居中后多出来的高度均分到数字上下，读起来像「仪表」
            而不是「空盒子」。标签仍贴顶、脚注仍贴底，三层的锚点不变。 */}
        <div className="flex min-h-0 flex-1 flex-col justify-center">
          {fullValue ? (
            <TooltipProvider delayDuration={150}>
              <Tooltip>
                <TooltipTrigger asChild className="cursor-default">
                  {numElement}
                </TooltipTrigger>
                <TooltipContent>
                  <p className="font-mono text-xs">{fullValue}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          ) : (
            numElement
          )}
          {/* hint 与数字同一组居中：若把 hint 留在流末尾用 mt-auto 贴底，
              带 hint 的卡数字会被顶高一截，同一行里与其他卡错位（实测 22px）。 */}
          {!sub && hint ? (
            <p className="truncate text-2xs font-medium text-muted-foreground" title={hintTitle}>
              {hint}
            </p>
          ) : null}
        </div>
        {sub ? (
          <div className="mt-auto flex flex-wrap items-baseline gap-x-3 gap-y-0.5 pt-1 text-2xs text-muted-foreground">
            {sub.map((s) => (
              <span key={s.label} className="whitespace-nowrap" title={s.title}>
                {s.label} <b className="font-medium tabular-nums text-foreground">{s.value}</b>
              </span>
            ))}
          </div>
        ) : null}
      </div>
    </Card>
  )
}
