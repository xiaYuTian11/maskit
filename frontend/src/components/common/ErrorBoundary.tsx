/**
 * 全局错误边界：组件渲染异常不白屏，显示降级提示（方案 §14.4）
 */
import { Component, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { AlertCircle, RefreshCw, Home } from 'lucide-react'
import { tt, ttf } from '@/lib/i18n'

interface Props {
  children: ReactNode
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
      return (
        <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 p-8 text-center">
          <div className="w-full max-w-xl rounded-2xl border border-red-500/30 bg-red-500/10 p-5 text-left text-sm text-red-600 dark:text-red-400 shadow-lg">
            <div className="flex items-center gap-2 font-bold text-base">
              <AlertCircle className="h-5 w-5 shrink-0" />
              <span>{ttf('errorBoundary.title', { e: msg })}</span>
            </div>
            {stack && (
              <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-black/10 p-3 font-mono text-[11px] leading-relaxed text-red-700 dark:text-red-300">
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
