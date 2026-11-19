/**
 * 全局错误边界：组件渲染异常不白屏，显示降级提示（方案 §14.4）
 */
import { Component, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { WindowControls } from '@/components/layout/WindowControls'
import { AlertCircle, RefreshCw, Home } from 'lucide-react'
import { tt, ttf } from '@/lib/i18n'

interface Props {
  children: ReactNode
  /** 仅最外层根 ErrorBoundary 置 true：页面级崩溃时 AppLayout 顶栏仍在，不应再叠画兜底三键 */
  root?: boolean
}

interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[ErrorBoundary] render error:', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      const err = this.state.error
      const msg = err?.message || String(err || tt('errorBoundary.unknown'))
      const stack = err?.stack
      const showFallbackChrome =
        Boolean(this.props.root) &&
        typeof document !== 'undefined' &&
        document.documentElement.dataset.windowChrome === 'custom'
      return (
        <div
          className={`flex flex-col items-center justify-center gap-4 p-8 text-center ${
            showFallbackChrome ? 'min-h-screen' : 'min-h-[60vh]'
          }`}
        >
          {showFallbackChrome && (
            <div className="fixed inset-x-0 top-0 z-[60] flex h-14 items-center px-3">
              <div data-tauri-drag-region className="h-full flex-1 select-none" />
              <WindowControls />
            </div>
          )}
          <div className="w-full max-w-xl rounded-2xl border border-destructive/30 bg-destructive/10 p-5 text-left text-sm text-destructive-ink shadow-lg">
            <div className="flex items-center gap-2 font-bold text-base">
              <AlertCircle className="h-5 w-5 shrink-0" />
              <span>{ttf('errorBoundary.title', { e: msg })}</span>
            </div>
            {stack && (
              <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-black/10 p-3 font-mono text-2xs leading-relaxed text-destructive-ink">
                {stack}
              </pre>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5"
              onClick={() => {
                this.setState({ error: null })
                window.location.hash = '#/'
                window.location.reload()
              }}
            >
              <Home className="h-4 w-4" />
              {tt('common.goHome')}
            </Button>
            <Button
              size="sm"
              className="gap-1.5"
              onClick={() => {
                this.setState({ error: null })
                window.location.reload()
              }}
            >
              <RefreshCw className="h-4 w-4" />
              {tt('common.reload')}
            </Button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
