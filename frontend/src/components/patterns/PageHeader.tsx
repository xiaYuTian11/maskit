import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

/**
 * 页面标题区（每页唯一的 h1）。
 *
 * 为什么要有它：8 个页面的页头此前是 4 种写法——控制台用 `text-[24px]
 * font-semibold`、其余用 `text-2xl font-bold`，副标题一处 `text-[13px]`、
 * 一处 `text-sm font-medium`。肉眼几乎看不出差别，但正是这种「一次一个样」
 * 让整站少了统一的节奏：字号、字重、行距、与正文的间距全部漂移。
 *
 * 纪律（改样式改这里，不要在页面覆盖）：
 * - 标题 text-2xl（24px）semibold，字距 -0.02em
 * - 副标题 13px regular 灰，与标题间距 4px
 * - 右侧动作区与标题**底对齐**（`items-end`），按钮不会被标题拉住基线
 */
export function PageHeader({
  title,
  subtitle,
  actions,
  className,
}: {
  title: ReactNode
  subtitle?: ReactNode
  /** 右侧动作：按钮或分段控件 */
  actions?: ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex flex-wrap items-end justify-between gap-3', className)}>
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-[-0.02em]">{title}</h1>
        {subtitle ? <p className="mt-1 text-[13px] text-muted-foreground">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}
