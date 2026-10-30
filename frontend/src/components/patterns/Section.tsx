import type { ComponentType, ReactNode } from 'react'

import { cn } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Hint } from '@/components/common/Hint'

/**
 * 设置分组卡（Section）。
 *
 * 为什么要有它：设置页此前有 25 张手写的 `<Card className="border bg-card">`，
 * 其中 7 张记得加 `shadow-card`、18 张没加——同一页里两种材质并存，肉眼说不上
 * 哪里不对但就是「不齐」。标题字号也漂移：`text-sm font-semibold` 13 处、
 * `flex items-center gap-1.5` 10 处、`text-base` 3 处。
 *
 * 纪律（改样式改这里）：
 * - 卡：`border bg-card shadow-card`，不要在这里再套内层盒子
 * - 标题：14px semibold；有图标时图标 16px 单色、与标题间距 8px
 * - 说明：一律走标题旁的 `?`（`hint`），不铺在卡里
 * - 内容区默认 `space-y-3`
 */
export function Section({
  id,
  title,
  icon: Icon,
  hint,
  badge,
  desc,
  children,
  className,
  contentClassName,
}: {
  id?: string
  title: ReactNode
  /** 标题左侧图标（16px，单色） */
  icon?: ComponentType<{ className?: string }>
  /** 标题旁的说明文本，收进 `?` */
  hint?: string
  /** 标题右侧的徽章/状态 */
  badge?: ReactNode
  /** 标题下方的一行短说明（仅当它本身是状态反馈、不适合塞进 `?` 时使用） */
  desc?: ReactNode
  children: ReactNode
  className?: string
  /** 内容区额外类（如 `flex flex-wrap items-center gap-3`） */
  contentClassName?: string
}) {
  return (
    <Card id={id} className={cn('border bg-card shadow-card', className)}>
      <CardHeader className="space-y-1">
        <div className="flex items-center gap-2">
          {Icon ? <Icon className="h-4 w-4 shrink-0 text-muted-foreground" /> : null}
          <CardTitle className="flex min-w-0 items-center gap-1.5 text-sm font-semibold">
            <span className="truncate">{title}</span>
            {hint ? <Hint text={hint} /> : null}
          </CardTitle>
          {badge ? <div className="ml-auto shrink-0">{badge}</div> : null}
        </div>
        {desc ? (
          <div className="text-xs text-muted-foreground">{desc}</div>
        ) : null}
      </CardHeader>
      <CardContent className={cn('space-y-3', contentClassName)}>{children}</CardContent>
    </Card>
  )
}
