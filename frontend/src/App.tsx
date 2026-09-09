import { ttf } from '@/lib/i18n'
import { useEffect } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout } from '@/components/layout/AppLayout'
import DashboardPage from '@/pages/Dashboard'
import LogsPage from '@/pages/Logs'
import StatsPage from '@/pages/Stats'
import SettingsPage from '@/pages/Settings'
import AuditPage from '@/pages/Audit'
import WordsPage from '@/pages/Words'
import ClientsPage from '@/pages/Clients'
import { useAuthStore } from '@/stores/authStore'
import { getShieldToken, getEngineState } from '@/lib/tauri'
import { isTauri, initEnginePort, readBrowserToken, saveBrowserToken } from '@/lib/shield-fetch'
import { TokenGate } from '@/components/common/TokenGate'

function App() {
  const { token, setToken, setEngineReady, setEngineError } = useAuthStore()

  // 启动初始化：Tauri 下经 IPC 取 token + 引擎就绪状态（方案 §4.2/§4.7）
  useEffect(() => {
    if (!isTauri()) {
      // 浏览器模式：无壳层，引擎由外部 python panel.py 提供（vite dev 或 Docker）。
      // token 来源优先级：URL ?token=（兼容旧链接）→ URL #token=（不随 HTTP 请求发送）
      // → 本 tab sessionStorage → 构建期 VITE_SHIELD_TOKEN（仅开发）。都没有则渲染 TokenGate。
      setEngineReady(true)
      const url = new URL(window.location.href)
      const fromUrl = (url.searchParams.get('token') || '').trim()
      const fragmentParams = new URLSearchParams(url.hash.startsWith('#') ? url.hash.slice(1) : '')
      const fromFragment = (fragmentParams.get('token') || '').trim()
      const fromLink = fromUrl || fromFragment
      if (fromLink) {
        saveBrowserToken(fromLink)
        // 立刻从地址栏抹掉，避免 token 留在历史记录 / 被截图；fragment 方式
        // 本来不会发给服务器，但仍不应长期留在浏览器历史中。
        url.searchParams.delete('token')
        if (fromFragment) {
          fragmentParams.delete('token')
          const rest = fragmentParams.toString()
          url.hash = rest ? `#${rest}` : ''
        }
        window.history.replaceState(null, '', url.pathname + url.search + url.hash)
      }
      // 仅开发构建允许用 VITE_SHIELD_TOKEN 便于本地联调；生产 bundle 不应
      // 包含任何可能的面板令牌，即使构建机误配置了同名环境变量。
      const devToken = import.meta.env.DEV ? (import.meta.env.VITE_SHIELD_TOKEN || '') : ''
      const t = fromLink || readBrowserToken() || devToken
      if (t) setToken(t)
      return
    }

    // token：引擎一旦监听端口就会写入 token 文件，单次读取即可（尽早就绪）。
    getShieldToken()
      .then((t) => { if (t) setToken(t) })
      .catch((e) => setEngineError(String(e)))

    // 引擎就绪状态不能靠一次性快照：Rust 的 readiness_loop 在后台把 ready 从
    // false 推成 true（启动竞态），崩溃 watchdog 还会自动重启后再变 true。
    // 快照早于它就永远 false，顶栏「启动代理」被 disabled=!engineReady 定格——
    // 而页面能加载本身说明 panel API 已可访问，越显矛盾。
    // 这里短间隔轮询直到 ready，之后降频到低频同步，以覆盖崩溃恢复 + 错误清空。
    let cancelled = false
    let timer = 0 as number | ReturnType<typeof setTimeout>
    let fast = true
    const schedule = () => { timer = setTimeout(run, fast ? 120 : 10000) }
    const run = async () => {
      if (cancelled) return
      try {
        const s = await getEngineState()
        if (cancelled) return
        initEnginePort(s.port)
        setEngineReady(s.ready)
        // last_error 可被清空（成功就绪时 Rust 置 None），必须同步清掉旧错误，
        // 否则引擎恢复后顶栏仍挂着过期的「引擎错误」。
        setEngineError(s.last_error ?? null)
        if (s.ready) fast = false
      } catch {
        if (!cancelled) setEngineError(ttf('app.engineError'))
      }
      if (!cancelled) schedule()
    }
    run()
    return () => { cancelled = true; clearTimeout(timer) }
  }, [setToken, setEngineReady, setEngineError])

  if (!isTauri() && !token) {
    return <TokenGate />
  }

  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/logs" element={<LogsPage />} />
        <Route path="/stats" element={<StatsPage />} />
        <Route path="/words" element={<WordsPage />} />
        <Route path="/clients" element={<ClientsPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppLayout>
  )
}

export default App
