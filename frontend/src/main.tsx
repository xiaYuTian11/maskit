import React from 'react'
import ReactDOM from 'react-dom/client'
import { HashRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import { ErrorBoundary } from '@/components/common/ErrorBoundary'
import { LanguageProvider } from '@/lib/i18n'
import './index.css'

// ===== 主题初始化：render 前同步执行（亮色优先） =====
// 必须在 React 挂载前设置 html[data-theme]，否则首帧会闪一下另一套变量（FOUC）。
// 默认亮色：办公场景的默认预期就是亮色，深色是主动选择而非强加。
// 用户选过就尊重用户；localStorage 异常时兜底亮色。
let savedTheme: string | null = null
try {
  savedTheme = localStorage.getItem('shield_theme')
} catch {
  savedTheme = null
}
document.documentElement.setAttribute(
  'data-theme',
  savedTheme === 'dark' ? 'dark' : 'light',
)

// TanStack Query 全局配置（方案 §5：轮询/缓存/重试，不用裸 setInterval）
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 30000,
      refetchIntervalInBackground: false,
    },
    mutations: {
      retry: 0,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <LanguageProvider>
      <QueryClientProvider client={queryClient}>
        <HashRouter>
          <ErrorBoundary>
            <App />
          </ErrorBoundary>
        </HashRouter>
      </QueryClientProvider>
    </LanguageProvider>
  </React.StrictMode>,
)
