import React from 'react'
import ReactDOM from 'react-dom/client'
import { HashRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import { ErrorBoundary } from '@/components/common/ErrorBoundary'
import { LanguageProvider } from '@/lib/i18n'
import './index.css'

// ===== 主题初始化：render 前同步执行（暗色优先） =====
// 必须在 React 挂载前设置 html[data-theme]，否则首帧会闪一下另一套变量（FOUC）。
// 默认暗色：暗色模式视觉质感更佳、防眩光。
// 一次性迁移：旧版本在首次挂载时曾自动将 'shield_theme: light' 写进 localStorage，
// 导致老用户浏览器被永久固定在亮色；检测未完成 v2 迁移时清掉旧自动值，启用新默认暗色。
let savedTheme: string | null = null
try {
  if (!localStorage.getItem('shield_theme_v2')) {
    localStorage.setItem('shield_theme_v2', '1')
    if (localStorage.getItem('shield_theme') === 'light') {
      localStorage.removeItem('shield_theme')
    }
  }
  savedTheme = localStorage.getItem('shield_theme')
} catch {
  savedTheme = null
}
document.documentElement.setAttribute(
  'data-theme',
  savedTheme === 'light' ? 'light' : 'dark',
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
