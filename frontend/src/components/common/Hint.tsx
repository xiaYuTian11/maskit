import { useState } from 'react'
import type { ReactNode } from 'react'
import { HelpCircle } from 'lucide-react'

import { cn } from '@/lib/utils'
import { InfoButton } from '@/components/common/InfoButton'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'

/**
 * 卡片标题旁的说明入口：`?` + 气泡。
 *
 * 为什么是受控而不是纯 hover：纯 hover 的 tooltip 在触屏上无处可点（Radix 不响应 tap），
 * 键盘 focus 也只在部分环境里自动展开。受控后三种输入都能拿到同一段说明：
 * 悬停、Tab 聚焦后回车、手指点击。再点一次收起（触屏没有 pointerleave 可依赖）。
 *
 * 触发器必须是 button（见 InfoButton），并且要透传 ref/props，否则 Radix 注入的
 * onPointerMove/onFocus 会被吞掉，气泡连悬停都不出现。
 */
export function Hint({
  text,
  content,
  className,
  contentClassName,
  side = 'top',
}: {
  /** 气泡与可访问名的主文本 */
  text: string
  /** 需要保留富内容（动态行、列表）时传这个，不传就用 text */
  content?: ReactNode
  className?: string
  contentClassName?: string
  side?: 'top' | 'right' | 'bottom' | 'left'
}) {
  const [open, setOpen] = useState(false)
  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip open={open} onOpenChange={setOpen}>
        <TooltipTrigger asChild>
          <InfoButton
            label={text}
            className={className ?? 'cursor-help'}
            onClick={() => setOpen((v) => !v)}
          >
            <HelpCircle className="h-3.5 w-3.5" />
          </InfoButton>
        </TooltipTrigger>
        <TooltipContent
          side={side}
          className={cn('max-w-[300px] text-xs leading-relaxed', contentClassName)}
        >
          {content ?? text}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
