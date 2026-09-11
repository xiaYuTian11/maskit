/**
 * 主布局：左侧导航（可收起）+ 顶部状态栏 + 内容区
 * 视觉：shadcn/ui token + Tailwind，亮色优先（data-theme 切换）
 */
import { useEffect, useState, type ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import { useVisibility } from '@/lib/useVisibility'
import {
  LayoutDashboard,
  FileText,
  BarChart3,
  ShieldCheck,
  Settings,
  PanelLeft,
  Play,
  Square,
  Moon,
  Sun,
  ScanSearch,
  Network,
  AlertCircle,
  RefreshCw,
  Loader2,
  ArrowUpCircle,
  Check,
  Languages,
  AlertTriangle,
  X,
} from 'lucide-react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { getStatus, startProxy, stopProxy } from '@/api/proxy'
import { emergencyDisableOriginCheck } from '@/api/settings'
import { useAuthStore } from '@/stores/authStore'
import { Button } from '@/components/ui/button'
import { ErrorBoundary } from '@/components/common/ErrorBoundary'
import { Logo } from '@/components/brand/Logo'
import { cn } from '@/lib/utils'
import { toast } from '@/lib/toast'
import { shieldFetch } from '@/lib/shield-fetch'

function GithubIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
      <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
    </svg>
  )
}
import { useI18n } from '@/lib/i18n'
import { checkUpdate, updateTrayProxyStatus } from '@/lib/tauri'
import { useNavigate, useLocation } from 'react-router-dom'

// 导航项：label 用 i18n key（t('nav.' + key)），随语言切换
const NAV_ITEMS = [
  { to: '/', key: 'dashboard', icon: LayoutDashboard },
  { to: '/logs', key: 'logs', icon: FileText },
  { to: '/stats', key: 'stats', icon: BarChart3 },
  { to: '/words', key: 'words', icon: ScanSearch },
  { to: '/clients', key: 'clients', icon: Network },
  { to: '/audit', key: 'audit', icon: ShieldCheck },
  { to: '/settings', key: 'settings', icon: Settings },
]

/** 主题：亮色优先，data-theme 属性切换（Tailwind darkMode selector 对齐）。
 *  初值直接读 main.tsx 已写入的属性，不再自己判断默认值——两处各判一次必然漂移。 */
function useTheme() {
  // 初始值直接读 html 属性（main.tsx 已同步初始化）
  const [dark, setDark] = useState(() => {
    return document.documentElement.getAttribute('data-theme') === 'dark'
  })
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light')
    try {
      localStorage.setItem('shield_theme', dark ? 'dark' : 'light')
    } catch {
      // localStorage 不可用时仅内存态
    }
  }, [dark])
  return { dark, toggle: () => setDark((d) => !d) }
}

export function AppLayout({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(false)
  const { dark, toggle } = useTheme()
  const queryClient = useQueryClient()
  const { engineReady, engineError } = useAuthStore()
  // 页面隐藏时停止所有轮询（WebView2 后台不再渲染/请求），可见时自动刷新
  const { hidden } = useVisibility()

  // 个性化背景：localStorage 存图（URL/base64/内置名）+ 透明度，纯前端偏好不进后端配置
  const [bgImage, setBgImage] = useState<string>(() => {
    try { return localStorage.getItem('shield_bg_image') || '' } catch { return '' }
  })
  const [bgOpacity, setBgOpacity] = useState<number>(() => {
    try { return Number(localStorage.getItem('shield_bg_opacity')) || 0 } catch { return 0 }
  })
  // 跨窗口/跨标签同步：设置页改了背景，其他打开的页面即时刷新
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === 'shield_bg_image') setBgImage(e.newValue || '')
      if (e.key === 'shield_bg_opacity') setBgOpacity(Number(e.newValue) || 0)
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const [checkingUpdate, setCheckingUpdate] = useState(false)
  const [proxyBusy, setProxyBusy] = useState(false)
  const [originBlocked, setOriginBlocked] = useState(false)
  const [rescuingOrigin, setRescuingOrigin] = useState(false)

  useEffect(() => {
    const onOriginRejected = () => setOriginBlocked(true)
    window.addEventListener('shield:origin_rejected', onOriginRejected)
    return () => window.removeEventListener('shield:origin_rejected', onOriginRejected)
  }, [])

  const handleRescueOrigin = async () => {
    setRescuingOrigin(true)
    try {
      await emergencyDisableOriginCheck()
      setOriginBlocked(false)
      toast(t('settings.toast.saved'))
      queryClient.invalidateQueries()
    } catch (e) {
      toast(String(e), 'error')
    } finally {
      setRescuingOrigin(false)
    }
  }

  // 代理状态轮询（方案 §5：TanStack Query refetchInterval 替代 setInterval）
  // 页面隐藏时停止轮询，正常 5s 轮询。
  // 在刚启动（status 未返回/starting）或操作中时，以 1000ms 快速探活，消除状态滞后！
  const { data: status, error: statusError } = useQuery({
    queryKey: ['proxyStatus'],
    queryFn: getStatus,
    refetchInterval: (query) => {
      if (hidden) return false
      const s = query.state.data
      if (s === undefined || s.proxy_starting || s.proxy_stopping) return 1000
      return 5000
    },
    retry: 3,
  })

  const isRunning = status?.proxy_running ?? false
  const isStarting = (status === undefined && !statusError) || !!status?.proxy_starting || (proxyBusy && !isRunning)
  const isStopping = (proxyBusy && isRunning) || !!status?.proxy_stopping

  // 实时同步代理运行状态至桌面端系统托盘菜单（运行中显示「停止代理」，已停止显示「启动代理」）
  useEffect(() => {
    if (typeof status?.proxy_running === 'boolean') {
      updateTrayProxyStatus(status.proxy_running)
    }
  }, [status])

  // 引擎可用兜底：engineReady 来自 Rust IPC 快照/轮询，可能有几百 ms 延迟；
  // 而 /api/status 能成功返回本身就是「面板可达」的硬信号；重取失败时，
  // TanStack Query 可能暂留上一份 data，因此还要排除 statusError，避免用旧状态启用按钮。
  // 只有 IPC 或本轮 status 都确认可达时才启用，请求失败不会误启用。
  const statusReached = !!status && !statusError
  const engineAvailable = engineReady || statusReached
  const { lang, setLang, t, tf } = useI18n()
  const navigate = useNavigate()
  const routeLocation = useLocation()
  // 后台自动检查发现的新版本号。null = 没有新版/还没查。
  // 更新入口原本只在「设置 → 工具」里，且必须用户主动点「检查更新」才知道有新版——
  // 等于绝大多数人永远停在旧版本，安全修复发出去也到不了用户手上。
  // 这里在启动后静默查一次，有新版就在顶栏常驻一个显眼入口。
  const [updateVersion, setUpdateVersion] = useState<string | null>(null)
  // 手动检查完成后如果已是最新，按钮就地展示 2.5 秒「已是最新版本」绿色反馈，
  // 避免用户只看右上角按钮没注意右上/右下角提示而以为没反应
  const [upToDateNotice, setUpToDateNotice] = useState(false)
  const checkForUpdate = async () => {
    setCheckingUpdate(true)
    setUpToDateNotice(false)
    try {
      const r = await checkUpdate()
      if (!r.ok) {
        toast(r.error || t('layout.checkFail'), 'error')
      } else if (r.has_update) {
        setUpdateVersion(r.version ?? null)
        toast(tf('layout.newVersionToast', { v: r.version ?? '' }))
        // 带 install=1：关于页的 AboutUpdateCard 收到后自动检查+下载，不用再手动点
        navigate('/settings?tab=about&install=1')
      } else {
        setUpdateVersion(null)
        setUpToDateNotice(true)
        setTimeout(() => setUpToDateNotice(false), 2500)
        toast(t('layout.upToDate'))
      }
    } catch (e) {
      toast(tf('layout.checkFailWith', { e: String(e) }), 'error')
    } finally {
      setCheckingUpdate(false)
    }
  }

  // 启动后延迟静默检查，之后每 6 小时复查一次。
  //
  // 常驻托盘可能连续运行数天；定期复查避免顶栏版本号停留在启动时的旧快照。
  //
  // 延迟 8 秒首查是为了不和启动时的引擎拉起抢资源；6 小时的周期与
  // 客户端策略拉取同频，不额外增加服务器压力。
  useEffect(() => {
    let cancelled = false
    const probe = async () => {
      try {
        const r = await checkUpdate()
        if (cancelled || !r.ok) return
        // 没有更新时要**清掉**旧值，否则用户手动装完新版，
        // 顶栏还挂着上一次查到的版本号不消失
        setUpdateVersion(r.has_update ? (r.version ?? null) : null)
      } catch {
        /* 静默：自动检查失败不打扰用户 */
      }
    }
    const first = setTimeout(probe, 8000)
    const timer = setInterval(probe, 6 * 3600 * 1000)
    return () => {
      cancelled = true
      clearTimeout(first)
      clearInterval(timer)
    }
  }, [])

  // 页面标题（从路由映射，i18n）
  // 必须用 useLocation() 而不是全局 window.location：应用跑在 HashRouter 下，
  // window.location.pathname 恒为 "/"，导致顶栏标题在任何页面都显示「控制台」
  // useLocation 还能在路由变化时触发重渲染。
  const pageTitle = (() => {
    const p = routeLocation.pathname
    if (p === '/') return t('nav.dashboard')
    if (p === '/logs') return t('nav.logs')
    if (p === '/stats') return t('nav.stats')
    if (p === '/words') return t('nav.words')
    if (p === '/clients') return t('nav.clients')
    if (p === '/audit') return t('nav.audit')
    if (p === '/settings') return t('nav.settings')
    return t('layout.appName')
  })()


  const toggleProxy = async () => {
    if (proxyBusy) return
    setProxyBusy(true)
    try {
      if (isRunning) {
        await stopProxy()
        toast(t('layout.proxyStoppedToast'))
      } else {
        const r = await startProxy()
        if (!r.ok) {
          toast(r.message || r.error || t('layout.proxyStartFail'), 'error')
          return
        }
        toast(t('layout.proxyStartedToast'))
      }
      queryClient.invalidateQueries({ queryKey: ['proxyStatus'] })
    } catch (e) {
      toast(tf('layout.opFail', { e: String(e) }), 'error')
    } finally {
      setProxyBusy(false)
    }
  }

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
      {/* 个性化背景层：在所有内容之下，透明度由用户控制 */}
      {bgImage && bgOpacity > 0 && (
        <div
          className="pointer-events-none fixed inset-0 z-0 bg-cover bg-center bg-no-repeat"
          style={{
            backgroundImage: `url("${bgImage}")`,
            opacity: bgOpacity / 100,
          }}
        />
      )}
      {/* ===== 侧边栏 ===== */}
      <aside
        className={cn(
          'relative flex shrink-0 flex-col border-r bg-card transition-all duration-300',
          collapsed ? 'w-[52px]' : 'w-56',
        )}
      >
        {/* Logo 区 */}
        <div className={cn('flex h-14 shrink-0 items-center gap-2.5 border-b px-3', collapsed && 'justify-center px-0')}>
          <Logo className="h-8 w-8 shrink-0 drop-shadow-[0_2px_8px_hsl(217_91%_60%/0.35)]" />
          {!collapsed && (
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="truncate text-sm font-bold leading-tight">Data Maskit</span>
                {status?.version && (
                  <span className="rounded border bg-muted/60 px-1 py-0 font-mono text-[10px] text-muted-foreground">
                    v{status.version}
                  </span>
                )}
              </div>
              <div className="truncate text-[10px] font-medium leading-tight text-muted-foreground">
                {t('layout.slogan')}
              </div>
            </div>
          )}
        </div>

        {/* 导航 */}
        <nav className="flex-1 space-y-0.5 overflow-y-auto p-2">
          {NAV_ITEMS.map((item) => {
            const label = t(`nav.${item.key}`)
            return (
            <NavLink
              key={item.to}
              to={item.to}
              title={label}
              className={({ isActive }) =>
                cn(
                  'group relative flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] font-semibold transition-all duration-150',
                  isActive
                    ? 'bg-gradient-to-r from-primary/15 to-primary/5 text-primary shadow-[inset_0_1px_0_rgb(255_255_255/0.04)]'
                    : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
                  collapsed && 'justify-center px-0',
                )
              }
            >
              {({ isActive }) => (
                <>
                  {/* 激活指示条 */}
                  <span
                    className={cn(
                      'absolute left-0 top-1/2 h-4 w-[3px] -translate-y-1/2 rounded-r-full bg-primary transition-all',
                      isActive ? 'opacity-100' : 'opacity-0',
                    )}
                  />
                  <item.icon className={cn('h-4 w-4 shrink-0', isActive && 'drop-shadow-[0_0_6px_hsl(217_91%_60%/0.5)]')} />
                  {!collapsed && <span className="truncate">{label}</span>}
                </>
              )}
            </NavLink>
            )
          })}
        </nav>

        {/* 收起按钮 */}
        <button
          onClick={() => setCollapsed((c) => !c)}
          className={cn(
            'flex h-9 shrink-0 items-center justify-center border-t text-muted-foreground transition-colors hover:bg-muted hover:text-foreground',
          )}
          title={collapsed ? t('layout.collapseSidebar') : t('layout.expandSidebar')}
        >
          <PanelLeft className={cn('h-4 w-4 transition-transform duration-300', collapsed && 'rotate-180')} />
        </button>
      </aside>

      {/* ===== 主区 ===== */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* 顶栏：毛玻璃 */}
        <header className="flex h-14 shrink-0 items-center gap-3 border-b bg-background/70 px-5 backdrop-blur-md">
          {/* 状态指示 */}
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-2.5 w-2.5">
              {/* 去掉常驻 animate-ping：它每帧重绘合成层，是 WebView2 后台发热的主因之一。
                  运行态用静态圆点 + 微光晕，异常/启动过渡态才用 pulse 提醒（少例不常驻）。 */}
              <span
                className={cn(
                  'relative inline-flex h-2.5 w-2.5 rounded-full',
                  engineError
                    ? 'bg-red-500 shadow-[0_0_8px_hsl(0_72%_51%/0.6)] animate-pulse'
                    : isStarting || isStopping
                      ? 'bg-amber-400 shadow-[0_0_8px_hsl(38_92%_50%/0.5)] animate-pulse'
                      : isRunning
                        ? 'bg-emerald-400 shadow-[0_0_6px_hsl(152_60%_45%/0.5)]'
                        : 'bg-slate-500',
                )}
              />
            </span>
            <span className="text-[13px] font-medium text-foreground">
              {engineError
                ? t('layout.engineErr')
                : isStarting
                  ? t('layout.startingProxy')
                  : isStopping
                    ? t('layout.stoppingProxy')
                    : isRunning
                      ? t('common.running')
                      : t('common.stopped')}
            </span>
          </div>

          {/* 页面标题（从路由映射，填充顶栏空白） */}
          <div className="ml-2 hidden items-baseline gap-2.5 sm:flex">
            <h1 className="text-[15px] font-bold tracking-tight">{pageTitle}</h1>
          </div>

          {/* fallback 徽章 */}
          {status && !isRunning && status.fallback_mode && (
            <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 text-[11px] font-medium text-amber-600 dark:text-amber-400">
              {t('layout.fallbackPrefix')}
              {status.fallback_mode === 'passthrough'
                ? t('layout.fallbackPass')
                : status.fallback_mode === 'error'
                  ? t('layout.fallback503')
                  : t('layout.fallbackBlock')}
            </span>
          )}

          <div className="ml-auto flex items-center gap-2">
            {/* 有新版时的常驻入口：用实心主色按钮而不是灰色图标，因为它是这一栏里
                唯一需要用户「现在就处理」的东西，藏在 ghost 按钮里等于没有。 */}
            {updateVersion ? (
              <Button
                size="sm"
                onClick={() => navigate('/settings?tab=about&install=1')}
                title={tf('layout.newVersionHint', { v: updateVersion ?? '' })}
                className="h-8 gap-1.5 px-3 text-xs font-medium"
              >
                <ArrowUpCircle className="h-3.5 w-3.5" />
                <span>{tf('layout.updateTo', { v: updateVersion ?? '' })}</span>
              </Button>
            ) : (
              <Button size="sm" variant="ghost" onClick={checkForUpdate} title={t('common.checkUpdate')} className="h-8 gap-1.5 px-2.5 text-xs" disabled={checkingUpdate}>
                {checkingUpdate ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : upToDateNotice ? (
                  <Check className="h-3.5 w-3.5 text-emerald-500" />
                ) : (
                  <RefreshCw className="h-3.5 w-3.5" />
                )}
                <span className={cn('hidden sm:inline', upToDateNotice && 'font-medium text-emerald-600 dark:text-emerald-400')}>
                  {upToDateNotice ? t('layout.upToDate') : t('common.checkUpdate')}
                </span>
              </Button>
            )}
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setLang(lang === 'zh' ? 'en' : 'zh')}
              title={lang === 'zh' ? t('layout.switchToEnglish') : t('layout.switchToChinese')}
              className="h-8 gap-1.5 px-2 text-xs font-medium text-muted-foreground hover:text-foreground"
            >
              <Languages className="h-3.5 w-3.5" />
              <span>{lang === 'zh' ? 'EN' : '中'}</span>
            </Button>
            <Button size="sm" variant="ghost" onClick={toggle} title={t('layout.toggleTheme')} className="h-8 w-8 px-0">
              {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={async () => {
                const url = 'https://github.com/xiaYuTian11/maskit'
                try {
                  const r = await shieldFetch('/api/open-url', {
                    method: 'POST',
                    body: JSON.stringify({ url }),
                  })
                  if (!(r as { ok?: boolean })?.ok) {
                    window.open(url, '_blank')
                  }
                } catch {
                  window.open(url, '_blank')
                }
              }}
              title="GitHub"
              className="h-8 w-8 px-0 text-muted-foreground hover:text-foreground"
            >
              <GithubIcon className="h-4 w-4" />
            </Button>
            <Button
              size="sm"
              variant={isRunning ? 'destructive' : 'default'}
              onClick={toggleProxy}
              disabled={!engineAvailable || isStarting || isStopping}
              loading={proxyBusy || isStarting || isStopping}
              className="h-8 gap-1.5 px-3.5 text-[13px] font-medium"
            >
              {!(proxyBusy || isStarting || isStopping) && (isRunning ? <Square className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />)}
              {isStarting
                ? t('layout.startingProxy')
                : isStopping
                  ? t('layout.stoppingProxy')
                  : isRunning
                    ? t('layout.stopProxy')
                    : t('layout.startProxy')}
            </Button>
          </div>
        </header>

        {originBlocked && (
          <div className="flex items-center justify-between border-b border-amber-500/40 bg-amber-500/15 px-4 py-2 text-xs text-amber-800 dark:text-amber-200">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
              <span>{t('layout.originRejectedBanner')}</span>
            </div>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                className="h-6 border-amber-500/50 text-[11px] hover:bg-amber-500/20"
                onClick={handleRescueOrigin}
                disabled={rescuingOrigin}
              >
                {rescuingOrigin ? t('common.loading') : t('layout.disableOriginCheckNow')}
              </Button>
              <button
                type="button"
                onClick={() => setOriginBlocked(false)}
                className="text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* 内容区：不自己滚（子页按需管理；Logs 页要固定高度让虚拟滚动生效） */}
        <main className="min-h-0 flex-1 overflow-hidden">
          <div className="mx-auto h-full w-full max-w-[1200px] overflow-y-auto p-6 lg:p-8">
            {statusError && (
              <div className="mb-4 flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-600 dark:text-red-400">
                <AlertCircle className="h-3.5 w-3.5 shrink-0" />
                {tf('layout.connFail', { err: String(statusError).slice(0, 120) })}
              </div>
            )}
            <ErrorBoundary>
              {children}
            </ErrorBoundary>
          </div>
        </main>
      </div>
    </div>
  )
}
