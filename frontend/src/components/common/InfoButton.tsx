import * as React from 'react'

import { cn } from '@/lib/utils'

/**
 * 说明类 tooltip 的触发器（`?`、图例等）。
 *
 * 为什么不是裸 <svg>：说明被收进 tooltip 之后，如果触发器只是个图标，
 * 键盘 Tab 与触屏用户完全拿不到这段信息 —— 等于对他们把说明删掉了。
 * button 自带可聚焦、Enter/Space 激活与可访问名（aria-label）。
 *
 * 为什么必须 forwardRef + 透传 props：Radix 的 `<TooltipTrigger asChild>` 通过
 * cloneElement 往子元素上注 onPointerMove/onFocus/onBlur 与 ref。子组件若吞掉这些，
 * trigger 就完全不响应——连鼠标悬停都不会出提示（实测表现为 tooltip 永远不出现）。
 *
 * label 内部使用时必须拦住 click：`<label>` 里点任何东西都会激活它关联的控件，
 * 点一下 `?` 顺手把旁边的 Switch 关掉是最难查的那类 bug。
 */
export const InfoButton = React.forwardRef<
  HTMLButtonElement,
  {
    /** 触发器的可访问名，同时作为悬停提示的兜底说明 */
    label: string
    children: React.ReactNode
    className?: string
  } & React.ButtonHTMLAttributes<HTMLButtonElement>
>(({ label, children, className, onClick, ...rest }, ref) => (
  <button
    ref={ref}
    type="button"
    aria-label={label}
    {...rest}
    onClick={(e) => {
      onClick?.(e)
      e.preventDefault()
      e.stopPropagation()
    }}
    className={cn(
      'inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
      className,
    )}
  >
    {children}
  </button>
))
InfoButton.displayName = 'InfoButton'
