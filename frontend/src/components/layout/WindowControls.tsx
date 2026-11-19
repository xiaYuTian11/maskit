/**
 * 桌面端自定义无边框窗口控制三键（圆角胶囊风格，仅 Windows 自定义标题栏渲染）。
 * 独立抽离以同时供 AppLayout 顶栏与 ErrorBoundary 降级页复用，确保崩溃时仍可关闭/最小化窗口。
 */
import { Minus, X } from 'lucide-react'
import { useI18n } from '@/lib/i18n'
import { windowClose, windowMinimize, windowToggleMaximize } from '@/lib/tauri'
import { cn } from '@/lib/utils'

interface WindowControlsProps {
  maximized?: boolean
  focused?: boolean
  className?: string
}

export function WindowControls({ maximized = false, focused = true, className }: WindowControlsProps) {
  const { t } = useI18n()
  const maxLabel = maximized ? t('layout.winRestore') : t('layout.winMaximize')

  return (
    <div
      data-window-controls="true"
      className={cn(
        'pointer-events-auto flex shrink-0 items-center gap-1 transition-opacity duration-150',
        !focused && 'opacity-60',
        className,
      )}
    >
      <button
        type="button"
        onClick={() => void windowMinimize()}
        title={t('layout.winMinimize')}
        aria-label={t('layout.winMinimize')}
        className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-foreground/10 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <Minus className="h-3.5 w-3.5" strokeWidth={1.75} />
      </button>
      <button
        type="button"
        onClick={() => void windowToggleMaximize()}
        title={maxLabel}
        aria-label={maxLabel}
        className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-foreground/10 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {maximized ? (
          <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth={1.35} className="h-3.5 w-3.5" aria-hidden="true">
            <rect x="2.25" y="4.25" width="7.5" height="7.5" rx="1.2" />
            <path d="M4.5 4.25V3a1 1 0 0 1 1-1h5.5a1 1 0 0 1 1 1v5.5a1 1 0 0 1-1 1H9.75" />
          </svg>
        ) : (
          <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth={1.35} className="h-3.5 w-3.5" aria-hidden="true">
            <rect x="2.25" y="2.25" width="9.5" height="9.5" rx="1.4" />
          </svg>
        )}
      </button>
      <button
        type="button"
        onClick={() => void windowClose()}
        title={t('layout.winClose')}
        aria-label={t('layout.winClose')}
        className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-destructive hover:text-destructive-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <X className="h-3.5 w-3.5" strokeWidth={1.75} />
      </button>
    </div>
  )
}
