import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

/**
 * 页面工具栏：左侧筛选条件、右侧动作按钮。
 *
 * 为什么要有它：拦截日志、审计中心、客户端管理的工具栏此前都是手拼的
 * `<div className="flex flex-wrap items-center gap-2">`，动作按钮混在筛选条件
 * 后面，用户分不清哪个是「过滤」哪个是「执行」。这里把两类分组固定下来：
 * 条件在左、动作在右（`ml-auto`），中间留出可扫读的空白。
 *
 * 窄屏时自动折行，动作组仍然靠右（`ml-auto` 在 flex-wrap 下会推到行末）。
 *
 * 有壁纸时叠加磨砂托底：确保输入框/芯片/按钮无论压在壁纸哪个位置都不会透字发花。
 */
export function Toolbar({
  children,
  actions,
  className,
}: {
  /** 筛选条件：Select / Input / 开关 chip */
  children?: ReactNode
  /** 动作：刷新 / 导出 / 清空 等按钮 */
  actions?: ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex flex-wrap items-center gap-2 rounded-lg bg-card/60 px-3 py-2 shadow-sm backdrop-blur-sm', className)}>
      {children}
      {actions ? <div className="ml-auto flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}
