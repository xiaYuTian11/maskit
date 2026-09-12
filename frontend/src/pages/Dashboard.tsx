/**
 * 控制台（对标旧版概览仪表盘）：
 * - 大状态横幅：过滤状态 + 捕获模式 + 运行时长
 * - 6 张统计卡：今日请求 / 已脱敏 / 已还原回复 / 告警(4子项) / Token(输入输出) / 今日费用估算
 * - 网关管理快捷操作：启停 / CA证书 / 健康检查 / 紧急恢复
 * - 核心安全防护策略：failClosed / responseScan / SSE / 流式排除 / 自启 / 自启代理
 * - 最近事件 7 列表格
 * - 向导横幅 / 自动恢复横幅 / 引擎错误横幅
 */
import { useMemo, useState } from 'react'
import { useVisibility } from '@/lib/useVisibility'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  ShieldCheck,
  ShieldOff,
  Activity,
  Shield,
  Zap,
  AlertCircle,
  AlertTriangle,
  Globe,
  X,
  Clock,
  ArrowRight,
  HelpCircle,
  Coins,
  Loader2,
  LockKeyhole,
} from 'lucide-react'
import { getStatus, dismissAutoRecover } from '@/api/proxy'
import { getTodayStats, getRestoreItems, getConfig, saveConfig, getHealth, getStatsModels } from '@/api/settings'
import { getLogs } from '@/api/logs'
import { mergeMaskRestore } from '@/lib/log-events'
import { EventTypeIcon, EVENT_TYPE_META } from '@/components/events/EventTypeIcon'
import { EventDetailDialog } from '@/components/events/EventDetailDialog'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table'
import { cn } from '@/lib/utils'
import { CRED_LABELS, maskWord } from '@/lib/sensitive-word'
import { toast } from '@/lib/toast'
import { useI18n } from '@/lib/i18n'
import { isTauri } from '@/lib/shield-fetch'
import { setAutostartTauri } from '@/lib/tauri'
import dayjs from 'dayjs'


/** 运行时长格式化：秒 → HH:MM:SS */
function formatUptime(sec: number): string {
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = Math.floor(sec % 60)
  return [h, m, s].map((n) => String(n).padStart(2, '0')).join(':')
}

/** 耗时格式统一：<1s 毫秒；<60s 秒(1 位小数)；≥60s 分:秒（与 Logs 页完全对齐） */
const fmtMs = (ms?: number | null) => {
  if (ms == null) return '—'
  if (ms < 1000) return `${Math.round(ms)}ms`
  const s = ms / 1000
  if (s < 60) return `${s.toFixed(1)}s`
  const m = Math.floor(s / 60)
  return `${m}m${Math.round(s % 60)}s`
}

export default function Dashboard() {
  const queryClient = useQueryClient()
  const { t, tf, lang } = useI18n()
  // 页面隐藏时停止轮询；可见时自动刷新
  const { hidden } = useVisibility()

  const { data: status } = useQuery({
    queryKey: ['proxyStatus'],
    queryFn: getStatus,
    refetchInterval: (query) => {
      if (hidden) return false
      const s = query.state.data
      if (s === undefined || s.proxy_starting || s.proxy_stopping) return 1000
      return 5000
    },
  })

  const isStarting = (status === undefined) || !!status?.proxy_starting
  const isStopping = !!status?.proxy_stopping
  const [statsRange, setStatsRange] = useState<'today' | '7d' | '30d'>('today')
  const { data: stats } = useQuery({
    queryKey: ['todayStats', statsRange],
    queryFn: () => getTodayStats(statsRange === 'today' ? undefined : statsRange),
    refetchInterval: hidden ? false : 10000,
  })
  const { data: cfg } = useQuery({ queryKey: ['config'], queryFn: getConfig, refetchInterval: hidden ? false : 120000 })

  // 写队列健康（drops/dead_letters/restarts > 0 时显示告警横幅）
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    refetchInterval: hidden ? false : 60000,
  })
  const ws = health?.writer_stats
  const hasWriterIssues = ws && (
    (ws.event_writer?.drops ?? 0) > 0 ||
    (ws.audit_writer?.drops ?? 0) > 0 ||
    (ws.event_writer?.dead_letters ?? 0) > 0 ||
    (ws.audit_writer?.dead_letters ?? 0) > 0 ||
    (ws.event_writer?.restarts ?? 0) > 0 ||
    (ws.audit_writer?.restarts ?? 0) > 0
  )

  const running = status?.proxy_running ?? false
  const filterOn = status?.filter_enabled ?? true

  const { data: recentLogs } = useQuery({
    queryKey: ['recentLogs'],
    // 需拉足量原始事件再合并 MASK/RESTORE：若只拉 limit=10 条原始事件，
    // 合并成「一次请求一行」后可能只剩 5 行。拉 40 条再合并取最新 10 行，
    // 与 Logs 页口径一致（同 sid 链路合成一行、最新 ts 在前）。
    queryFn: () => getLogs({ limit: 40, slim: true }),
    refetchInterval: hidden ? false : 5000,
  })

  // 今日费用估算（数据源 /api/stats/models?days=1，价格估算非真实账单）
  const { data: costData } = useQuery({
    queryKey: ['statsModels', '1'],
    queryFn: () => getStatsModels(1),
    refetchInterval: hidden ? false : 60000,
  })

  const [maskedOpen, setMaskedOpen] = useState(false)
  const [restoredOpen, setRestoredOpen] = useState(false)
  // 明文显示开关：默认打码，普通 PII 可切换；凭据类恒打码（安全红线）
  const [maskedPlain, setMaskedPlain] = useState(false)
  const [restoredPlain, setRestoredPlain] = useState(false)
  // 行点击详情弹窗（复用 Logs 页的 EventDetailDialog）
  const [detailSeq, setDetailSeq] = useState<number | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)
  const { data: restoreItems } = useQuery({
    queryKey: ['restoreItems'],
    queryFn: () => getRestoreItems(200),
    enabled: restoredOpen,
  })


  const dismiss = async () => {
    try {
      await dismissAutoRecover()
      queryClient.invalidateQueries({ queryKey: ['proxyStatus'] })
    } catch {
      // 忽略
    }
  }

  const toggle = async (key: string, v: boolean) => {
    if (!cfg) return
    try {
      // 自启走 Tauri IPC
      if (key === 'autostart' && isTauri()) {
        await setAutostartTauri(v)
      }
      const r = await saveConfig({ [key]: v })
      if (!r.ok) toast(r.error || t('common.saveFail'), 'error')
      else toast(t('common.saved'))
      queryClient.invalidateQueries({ queryKey: ['config'] })
      queryClient.invalidateQueries({ queryKey: ['proxyStatus'] })
    } catch (e) {
      toast(tf('common.saveFailWith', { e: String(e) }), 'error')
    }
  }

  const dismissWizard = async () => {
    if (!cfg) return
    try {
      await saveConfig({ wizard_done: true })
      queryClient.invalidateQueries({ queryKey: ['proxyStatus'] })
    } catch {
      // 忽略
    }
  }

  const tokensTotal = (stats?.tokens.prompt ?? 0) + (stats?.tokens.completion ?? 0)

  // 最近事件：合并 MASK/RESTORE 成「一次请求一行」并取最新 10 行（与 Logs 页同口径）
  const recentMerged = useMemo(
    () => mergeMaskRestore(recentLogs?.events ?? []).slice(0, 10),
    [recentLogs?.events],
  )

  // 今日费用估算：读 /api/stats/models?days=1（today 自然日），只计已定价模型
  const todayCostModels = costData?.models ?? []
  const todayCost = todayCostModels.reduce((s, m) => s + (m.priced ? (m.cost_usd ?? 0) : 0), 0)
  const todayPricedCount = todayCostModels.filter((m) => m.priced).length
  // 有请求但一个模型都没定价 → 费用估算不可用（不展示假 0 账单）
  const todayCostUnavailable =
    todayCostModels.length > 0 && todayPricedCount === 0
  const todayCostReady = Boolean(costData)

  // 6 张统计卡（i18n）
  const statCards = [
    {
      label: t('dash.reqToday'), value: (stats?.requests ?? 0).toLocaleString(), hint: t('dash.reqHint'),
      icon: Activity, num: 'text-blue-600 dark:text-blue-400',
      iconBg: 'from-blue-500/15 to-blue-500/5 text-blue-600 dark:text-blue-400',
      to: '/logs',
    },
    {
      label: t('dash.maskedReq'), value: (stats?.mask_events ?? 0).toLocaleString(), hint: `${t('dash.maskedHint')} ${(stats?.masked_items ?? 0).toLocaleString()}`,
      icon: Shield, num: 'text-emerald-600 dark:text-emerald-400',
      iconBg: 'from-emerald-500/15 to-emerald-500/5 text-emerald-600 dark:text-emerald-400',
      onClick: () => setMaskedOpen(true),
    },
    {
      label: t('dash.restored'), value: (stats?.restored ?? 0).toLocaleString(), hint: t('dash.restoredHint'),
      icon: ShieldCheck, num: 'text-emerald-600 dark:text-emerald-400',
      iconBg: 'from-teal-500/15 to-teal-500/5 text-teal-600 dark:text-teal-400',
      onClick: () => setRestoredOpen(true),
    },
    {
      label: t('dash.alerts'), value: (stats?.alerts ?? 0).toLocaleString(),
      sub: [
        { label: t('dash.blocked'), value: ((stats as Record<string, unknown> | undefined)?.by_type as Record<string, {events:number}> | undefined)?.BLOCK?.events ?? 0 },
        { label: t('dash.restoreFail'), value: stats?.restore_failed ?? 0 },
        { label: t('dash.errors'), value: ((stats as Record<string, unknown> | undefined)?.by_type as Record<string, {events:number}> | undefined)?.ERR?.events ?? 0 },
        { label: t('dash.respWarn'), value: ((stats as Record<string, unknown> | undefined)?.by_type as Record<string, {events:number}> | undefined)?.SCAN_WARN?.events ?? 0 },
      ],
      icon: AlertCircle, num: 'text-amber-600 dark:text-amber-400',
      iconBg: 'from-amber-500/15 to-amber-500/5 text-amber-600 dark:text-amber-400',
      to: '/logs',
    },
    {
      label: t('dash.tokenToday'), value: tokensTotal.toLocaleString(),
      hint: `${t('dash.tokenHint')} ${(stats?.tokens.prompt ?? 0).toLocaleString()} · ${(stats?.tokens.completion ?? 0).toLocaleString()}`,
      icon: Zap, num: 'text-violet-600 dark:text-violet-400',
      iconBg: 'from-violet-500/15 to-violet-500/5 text-violet-600 dark:text-violet-400',
      to: '/stats',
    },
    {
      // 今日费用估算：按模型价格 × 今日 token 用量估算，未定价模型不计入；
      // 请求加载中显示破折号，有请求但全部未定价时提示估算不可用（不展示假 0 账单）。
      label: t('dash.costToday'),
      value: !todayCostReady || todayCostUnavailable ? '—' : `$${Number(todayCost || 0).toFixed(4)}`,
      hint: !todayCostReady ? t('common.loading') : todayCostUnavailable ? t('dash.costUnavailable') : t('dash.costHint'),
      icon: Coins, num: 'text-emerald-600 dark:text-emerald-400',
      iconBg: 'from-emerald-500/15 to-emerald-500/5 text-emerald-600 dark:text-emerald-400',
      to: '/stats',
    },
  ]

  return (
    <div className="space-y-5">
      <h1 className="sr-only">{t('nav.dashboard')}</h1>
      {/* ===== 大状态横幅 ===== */}
      <div
        className={cn(
          'flex flex-wrap items-center gap-4 rounded-2xl border p-5 transition-all duration-300',
          isStarting || isStopping
            ? 'border-amber-500/30 bg-gradient-to-br from-amber-500/10 to-amber-500/5'
            : running && filterOn
              ? 'border-emerald-500/30 bg-gradient-to-br from-emerald-500/10 to-emerald-500/5'
              : running
                ? 'border-amber-500/30 bg-gradient-to-br from-amber-500/10 to-amber-500/5'
                : 'border-border bg-gradient-to-br from-muted/40 to-muted/10',
        )}
      >
        <div
          className={cn(
            'flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl text-white shadow-lg',
            isStarting || isStopping
              ? 'bg-gradient-to-br from-amber-500 to-orange-500 shadow-amber-500/25'
              : running && filterOn
                ? 'bg-gradient-to-br from-emerald-500 to-green-500 shadow-emerald-500/25'
                : running
                  ? 'bg-gradient-to-br from-amber-500 to-orange-500 shadow-amber-500/25'
                  : 'bg-gradient-to-br from-slate-400 to-slate-500 shadow-slate-500/25',
          )}
        >
          {isStarting || isStopping ? (
            <Loader2 className="h-6 w-6 animate-spin" />
          ) : running && filterOn ? (
            <ShieldCheck className="h-6 w-6" />
          ) : (
            <ShieldOff className="h-6 w-6" />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-lg font-bold tracking-tight">
              {isStarting
                ? t('dash.startingTitle')
                : isStopping
                  ? t('layout.stoppingProxy')
                  : !running
                    ? t('dash.proxyStoppedTitle')
                    : filterOn
                      ? t('dash.filterOn')
                      : t('dash.filterOff')}
            </span>
            {running && !isStarting && (
              <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-600 dark:text-emerald-400">
                {t(`dash.captureMode.${status?.capture_mode ?? 'reverse'}`)}
              </span>
            )}
          </div>
          <p className="mt-1 text-[13px] text-muted-foreground">
            {isStarting
              ? t('dash.startingDesc')
              : running
                ? t('dash.maskingDesc')
                : status?.fallback_mode === 'passthrough'
                  ? t('dash.passthroughDesc')
                  : status?.fallback_mode === 'error'
                    ? t('dash.proxy503')
                    : t('dash.proxyStopped')}
          </p>
        </div>
        <div className="flex items-center gap-6 text-[13px] text-muted-foreground">
          <div className="text-right">
            <div className="flex items-center gap-1 text-base font-semibold tabular-nums text-foreground">
              <Clock className="h-3.5 w-3.5" />
              {isStarting ? t('dash.starting') : running ? formatUptime(status?.uptime ?? 0) : '—'}
            </div>
            <div className="text-xs">{t('dash.uptime')}</div>
          </div>
        </div>
      </div>

      {/* 引擎错误横幅 */}
      {status?.last_error && !status.auto_recover_fail && (
        <div className="flex items-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-600 dark:text-red-400">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span className="min-w-0 flex-1 truncate">{t('dash.engineError')}{status.last_error}</span>
        </div>
      )}

      {/* 自动恢复横幅 */}
      {status?.auto_recovered_at && !status.auto_recover_fail && (
        <div className="flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-600 dark:text-emerald-400">
          <ShieldCheck className="h-4 w-4 shrink-0" />
          <span>{tf('dash.autoRecovered', { time: status.auto_recovered_at ? dayjs(status.auto_recovered_at).format('HH:mm:ss') : '—' })}</span>
          <Button size="icon" variant="ghost" className="ml-auto h-6 w-6 shrink-0" onClick={dismiss}>
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>
      )}
      {status?.auto_recover_fail && (
        <div className="flex items-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-600 dark:text-red-400">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span className="min-w-0 flex-1 truncate">{t('dash.autoRecoverFail')}{status.auto_recover_fail}</span>
          <Button size="icon" variant="ghost" className="ml-auto h-6 w-6 shrink-0" onClick={dismiss}>
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>
      )}

      {/* 向导横幅 */}
      {status?.wizard_recommended && (
        <div className="flex items-center gap-3 rounded-xl border bg-gradient-to-r from-primary/10 to-transparent p-4">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/15 font-bold text-primary">1</div>
          <div className="min-w-0 flex-1 text-sm">
            <div className="font-semibold">{t('dash.wizardTitle')}</div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              {t('dash.wizardSteps')}
            </div>
          </div>
          <Link to="/clients" className="shrink-0 rounded-lg border border-input bg-secondary px-3 py-1.5 text-xs font-medium hover:bg-accent">
            {t('dash.goConfig')}
          </Link>
          <Button size="icon" variant="ghost" className="h-7 w-7 shrink-0" onClick={dismissWizard}><X className="h-4 w-4" /></Button>
        </div>
      )}

      {/* 写队列健康告警：drops/dead_letters/restarts > 0 时显示 */}
      {hasWriterIssues && (
        <div className="flex items-center gap-2 rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
          <span className="text-amber-700 dark:text-amber-300">
            {t('dash.writerIssue')}
            {ws.event_writer?.drops ? tf('dash.writerDropped', { n: ws.event_writer.drops }) : ''}
            {ws.audit_writer?.drops ? ` / ${tf('dash.writerAuditDropped', { n: ws.audit_writer.drops })}` : ''}
            {ws.event_writer?.dead_letters ? ` / ${tf('dash.writerDead', { n: ws.event_writer.dead_letters })}` : ''}
            {ws.event_writer?.restarts ? ` / ${tf('dash.writerRestarts', { n: ws.event_writer.restarts })}` : ''}
            {t('dash.writerLost')}
          </span>
        </div>
      )}

      {/* ===== 5 张统计卡 ===== */}
      <div className="mb-1 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-muted-foreground">
          {statsRange === 'today' ? t('dash.statsToday') : statsRange === '7d' ? t('dash.stats7d') : t('dash.stats30d')}
        </h2>
        <div className="flex items-center gap-1 rounded-lg bg-muted/60 p-0.5 text-xs">
          {([['today', t('dash.today')], ['7d', t('dash.7d')], ['30d', t('dash.30d')]] as const).map(([k, label]) => (
            <button
              key={k}
              type="button"
              onClick={() => setStatsRange(k)}
              className={cn('rounded-md px-2.5 py-1 font-medium transition-colors', statsRange === k ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      {/* 6 卡：2-3 列为主，宽屏(≥1536px)才一行六列，避免 1280-1440 屏拥挤 */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
        {statCards.map((c) => {
          const interactive = !!(c.to || c.onClick)
          const card = (
            <Card
              className={cn(
                'h-full border bg-card shadow-[var(--shadow-card)] transition-[transform,box-shadow,border-color] duration-200',
                // hover 效果只给真能点的卡。Token 卡没有去处，给它抬起+手型
                // 等于骗一次点击——之前 to:'/logs' 也从没接到路由，
                // 三张卡看着可点实际点了没反应
                interactive &&
                  'cursor-pointer hover:-translate-y-0.5 hover:border-primary/30 hover:bg-accent/40 hover:shadow-[var(--shadow-card-hover)]',
              )}
              {...(c.onClick ? { onClick: c.onClick } : {})}
            >
              <CardContent className="flex h-full flex-col p-5">
                {/* 标题与数值各占一行：标题行只放标题和图标，数值行左对齐顶格，
                    5 张卡的数值基线才能横向对齐（标题长短不一时尤其明显） */}
                <div className="flex items-start justify-between gap-2">
                  <span className="min-w-0 flex-1 text-[13px] font-semibold leading-5 text-foreground/80">
                    {c.label}
                  </span>
                  <div className={cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br', c.iconBg)}>
                    <c.icon className="h-[18px] w-[18px]" />
                  </div>
                </div>
                <div className={cn('mt-2.5 mb-2 text-[28px] font-bold leading-tight tabular-nums tracking-tight', c.num)}>
                  {c.value}
                </div>
                {c.sub ? (
                  <div className="mt-auto grid grid-cols-2 gap-x-2 gap-y-0.5 border-t pt-2 text-xs text-muted-foreground" style={{ minHeight: 44 }}>
                    {c.sub.map((s) => (
                      <span key={s.label} className="truncate">
                        {s.label} <b className="font-medium tabular-nums text-foreground">{s.value}</b>
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="mt-auto border-t pt-2 text-[11px] font-medium text-muted-foreground/80" style={{ minHeight: 44 }}>{c.hint}</p>
                )}
              </CardContent>
            </Card>
          )
          return c.to
            ? <Link key={c.label} to={c.to} className="block h-full">{card}</Link>
            : <div key={c.label} className="h-full">{card}</div>
        })}
      </div>


{/* 核心安全防护策略 */}
<Card className="overflow-hidden border bg-card shadow-[var(--shadow-card)]">
          <div className="flex items-center justify-between border-b p-5">
            <h3 className="flex items-center gap-2 text-base font-bold">
              <ShieldCheck className="h-5 w-5 text-emerald-500" />
              {t('dash.security')}
            </h3>
            <span className="flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              {t('dash.live')}
            </span>
          </div>
          <CardContent className="space-y-3.5 p-5">
            {([
              ['fail_closed', t('dash.failClosed'), t('dash.failClosedDesc')],
              ['response_scan', t('dash.respScan'), t('dash.respScanDesc')],
            ] as [string, string, string][]).map(([k, title, desc]) => (
              <label key={k} className="flex cursor-pointer select-none items-center justify-between border-t pt-3.5 first:border-t-0 first:pt-0 transition-colors hover:text-foreground">
                <div className="flex min-w-0 items-center gap-1.5">
                  <span className="truncate text-sm font-semibold">{title}</span>
                  <TooltipProvider delayDuration={200}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span onClick={(e) => e.stopPropagation()}>
                          <HelpCircle className="h-3.5 w-3.5 shrink-0 cursor-help text-muted-foreground/60" />
                        </span>
                      </TooltipTrigger>
                      <TooltipContent className="max-w-[260px] text-xs">{desc}</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </div>
                <Switch
                  checked={Boolean((status as Record<string, unknown> | undefined)?.[k])}
                  onCheckedChange={(v) => toggle(k, v)}
                  className="scale-90"
                />
              </label>
            ))}
            {/* 自启 */}
            {([
              ['autostart', t('dash.autostart'), t('dash.autostartDesc')],
              ['auto_start_proxy', t('dash.autoStartProxy'), t('dash.autoStartProxyDesc')],
            ] as [string, string, string][]).map(([k, title, desc]) => (
              <label key={k} className="flex cursor-pointer select-none items-center justify-between border-t pt-3.5 transition-colors hover:text-foreground">
                <div className="flex min-w-0 items-center gap-1.5">
                  <span className="truncate text-sm font-semibold">{title}</span>
                  <TooltipProvider delayDuration={200}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span onClick={(e) => e.stopPropagation()}>
                          <HelpCircle className="h-3.5 w-3.5 shrink-0 cursor-help text-muted-foreground/60" />
                        </span>
                      </TooltipTrigger>
                      <TooltipContent className="max-w-[260px] text-xs">{desc}</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </div>
                <Switch
                  checked={Boolean((status as Record<string, unknown> | undefined)?.[k])}
                  onCheckedChange={(v) => toggle(k, v)}
                  className="scale-90"
                />
              </label>
            ))}
          </CardContent>
        </Card>

      {/* ===== 最近事件表格（与 Logs 页列对齐）===== */}
      <Card className="overflow-hidden border bg-card shadow-[var(--shadow-card)]">
        <div className="flex items-center justify-between border-b bg-muted/20 p-5">
          <div className="flex items-center gap-3">
            <h3 className="text-base font-bold">{t('dash.recentLogs')}</h3>
            <span className="rounded-full border bg-secondary px-2 py-0.5 font-mono text-[11px] text-muted-foreground">{t('dash.livePush')}</span>
          </div>
          <Link to="/logs" className="flex items-center gap-1 text-sm font-semibold text-primary hover:underline">
            {t('dash.viewAll')} <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
        <div className="overflow-x-auto">
          <Table className="w-full text-sm">
            <TableHeader>
              <TableRow className="border-b bg-muted/50">
                <TableHead className="w-[68px] py-2.5 px-4 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('logs.colTime')}</TableHead>
                <TableHead className="w-[92px] py-2.5 px-4 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('logs.colResult')}</TableHead>
                <TableHead className="w-[88px] py-2.5 px-4 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('logs.colUpstream')}</TableHead>
                <TableHead className="min-w-[200px] py-2.5 px-4 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('logs.colModel')}</TableHead>
                <TableHead className="w-[140px] min-w-[120px] py-2.5 px-4 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('logs.colSummary')}</TableHead>
                <TableHead className="w-[56px] py-2.5 px-4 text-center text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('logs.colStatus')}</TableHead>
                <TableHead className="w-[58px] py-2.5 px-4 text-right text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('logs.colDuration')}</TableHead>
                <TableHead className="w-[64px] py-2.5 px-4 text-right text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('logs.colCost')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recentMerged.map((e) => (
                <TableRow key={e.seq} className="cursor-pointer border-b text-[13px] transition-colors hover:bg-muted/40" onClick={() => { setDetailSeq(e._detailSeq ?? e.seq); setDetailOpen(true) }}>
                  <TableCell className="py-2.5 px-4 whitespace-nowrap tabular-nums text-xs text-muted-foreground">
                    <div className="flex flex-col leading-tight">
                      <span>{e.ts ? dayjs(e.ts * 1000).format('MM-DD') : '—'}</span>
                      <span className="opacity-70">{e.ts ? dayjs(e.ts * 1000).format('HH:mm:ss') : ''}</span>
                    </div>
                  </TableCell>
                  <TableCell className="py-2.5 px-4">
                    <span className="flex items-center gap-1.5">
                      <EventTypeIcon type={e.type} className="h-3.5 w-3.5" />
                      <span className="text-[11px] font-medium">{t(EVENT_TYPE_META[e.type]?.labelKey ?? e.type)}</span>
                      {e.stream_actual && (
                        <span className="ml-1 rounded bg-muted/60 px-1 py-0.5 font-mono text-[9px] text-muted-foreground">
                          {e.stream_actual === 'stream' ? t('logs.streaming') : t('logs.whole')}
                        </span>
                      )}
                    </span>
                  </TableCell>
                  {/* 上游：优先配置名 upstream，client_app（进程探测）仅作缺失回退 */}
                  <TableCell className="py-2.5 px-4 truncate text-xs text-muted-foreground" title={String(e.upstream || e.client_app || '')}>
                    {String(e.upstream || e.client_app || '—')}
                  </TableCell>
                  {/* 模型：完整 host/path 放 title（悬停可见），列只展示模型名 */}
                  <TableCell className="py-2.5 px-4 font-mono text-[11px]" title={`${e.host ?? ''}${e.path ?? ''}${e.model ? `\n${tf('logs.modelIn', { m: e.model })}` : ''}`}>
                    <div className="flex items-center gap-1.5 truncate">
                      <span className="truncate">{e.model || (e.upstream ? '—' : e.host) || '—'}</span>
                      {e.stream_actual && (
                        <span className="shrink-0 rounded bg-muted/60 px-1 py-0.5 font-mono text-[9px] text-muted-foreground">
                          {e.stream_actual === 'stream' ? t('logs.streaming') : t('logs.whole')}
                        </span>
                      )}
                    </div>
                  </TableCell>
                  {/* 脱敏/还原/未还原/兜底：与 Logs 页口径完全对齐（未还原用琥珀告警，兜底用中性） */}
                  <TableCell className="py-2.5 px-4 text-xs">
                    {((e.count ?? 0) > 0 || (e.restored ?? 0) > 0 || (e.unresolved ?? 0) > 0 || (e.degraded ?? 0) > 0) ? (
                      <span className="flex items-center gap-1.5">
                        {(e.count ?? 0) > 0 && <span className="text-blue-600 dark:text-blue-400">{t('logs.colMasked')} {e.count}</span>}
                        {(e.restored ?? 0) > 0 && <span className="text-emerald-600 dark:text-emerald-400">{t('logs.colRestored')} {e.restored}</span>}
                        {(e.unresolved ?? 0) > 0 && <span className="text-amber-600 dark:text-amber-400" title={t('logs.unresolvedHint')}>{t('logs.colUnresolved')} {e.unresolved}</span>}
                        {(e.degraded ?? 0) > 0 && <span className="text-muted-foreground" title={t('logs.degradedHint')}>{t('logs.colDegraded')} {e.degraded}</span>}
                      </span>
                    ) : (
                      <span className="text-muted-foreground/50">—</span>
                    )}
                  </TableCell>
                  {/* 状态：http_status 状态码或 status 语义 */}
                  <TableCell className="py-2.5 px-4 text-center">
                    {e.http_status ? (
                      <Badge
                        variant="outline"
                        className={cn(
                          'px-1 py-0 text-[9px] font-mono',
                          e.http_status >= 400
                            ? 'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400'
                            : e.http_status >= 200 && e.http_status < 300
                              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                              : 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400',
                        )}
                      >
                        {e.http_status}
                      </Badge>
                    ) : e.status ? (
                      <span className="truncate text-[9px] text-muted-foreground" title={String(e.status)}>
                        {e.status === 'no_placeholder_in_response' ? t('logs.statusNoRestore') : e.status === 'no_sensitive_data' ? t('logs.statusNoSensitive') : String(e.status).slice(0, 6)}
                      </span>
                    ) : (
                      <span className="text-muted-foreground/50">—</span>
                    )}
                  </TableCell>
                  {/* 耗时 */}
                  <TableCell className="py-2.5 px-4 text-right tabular-nums text-xs text-muted-foreground">
                    {fmtMs(e.total_ms ?? e.upstream_ms ?? (e as { mask_ms?: number }).mask_ms)}
                  </TableCell>
                  {/* 费用：RESTORE 事件由后端按 model×usage 估算，与 Logs 页口径一致 */}
                  <TableCell className="py-2.5 px-4 text-right tabular-nums text-[11px]">
                    {e.cost_usd != null && e.cost_usd > 0 ? (
                      <span className="text-emerald-600 dark:text-emerald-400">${e.cost_usd.toFixed(4)}</span>
                    ) : (
                      <span className="text-muted-foreground/50">—</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {recentMerged.length === 0 && (
                <TableRow>
                  <TableCell colSpan={8} className="py-10 text-center text-sm text-muted-foreground">
                    {t('dash.noEvents')}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </Card>

      <EventDetailDialog open={detailOpen} onOpenChange={setDetailOpen} seq={detailSeq} />

      {/* ===== 客户端上游卡片 ===== */}
      <div>
        <h2 className="mb-3 text-[13px] font-semibold text-muted-foreground">{t('dash.clientsTitle')}</h2>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {(status?.upstream_ports ?? []).map((u) => (
            <Card
              key={u.port}
              className="border bg-card shadow-[var(--shadow-card)] transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[var(--shadow-card-hover)]"
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-[15px] font-semibold">{u.name || `:${u.port}`}</span>
                  <span
                    className={cn(
                      'flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium',
                      u.listening
                        ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                        : 'border-border text-muted-foreground',
                    )}
                  >
                    <span
                      className={cn(
                        'h-1.5 w-1.5 rounded-full',
                        u.listening
                          ? 'animate-pulse bg-emerald-400 shadow-[0_0_6px_hsl(152_60%_45%/0.7)]'
                          : 'bg-slate-500',
                      )}
                    />
                    {u.listening ? t('common.running') : t('common.stopped')}
                  </span>
                </div>
                <div className="mt-3 space-y-1.5 text-[13px]">
                  <div className="flex items-center gap-2">
                    <span className="w-9 shrink-0 text-muted-foreground">{t('dash.port')}</span>
                    <code className="rounded-md bg-muted/80 px-1.5 py-0.5 font-mono text-xs">{u.port}</code>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-9 shrink-0 text-muted-foreground">{t('dash.target')}</span>
                    <code className="truncate font-mono text-xs text-muted-foreground">{u.target}</code>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
          {(status?.upstream_ports ?? []).length === 0 && (
            <Card className="border bg-card">
              <CardContent className="py-10 text-center text-sm text-muted-foreground">
                {t('dash.noClients')}
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* 出口代理提示 */}
      {(status?.egress_proxy_users ?? []).length > 0 && (
        <div className="flex items-center gap-2 rounded-xl border border-amber-500/20 bg-amber-500/5 px-4 py-2.5 text-xs text-amber-600 dark:text-amber-400">
          <Globe className="h-3.5 w-3.5 shrink-0" />
          <span>{t('dash.egressOn')}{status!.egress_proxy_users.join(lang === 'en' ? ', ' : '、')}</span>
        </div>
      )}

      {/* 今日脱敏词明细弹窗（已脱敏请求卡）：明文开关，凭据类恒打码 */}
      <Dialog open={maskedOpen} onOpenChange={(v) => { setMaskedOpen(v); if (!v) setMaskedPlain(false) }}>
        <DialogContent className="max-h-[80vh] max-w-2xl overflow-y-auto">
          <DialogHeader>
            <div className="flex items-center justify-between gap-2">
              <DialogTitle>{t('dash.maskedDetail')}</DialogTitle>
              <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground">
                <Switch checked={maskedPlain} onCheckedChange={setMaskedPlain} className="scale-75" />
                <span className="select-none">{t('stats.showPlain')}</span>
              </label>
            </div>
          </DialogHeader>
          <div className="space-y-2">
            {(stats?.top_words ?? []).slice(0, 20).map((w) => {
              const cred = CRED_LABELS.has(w.label)
              const display = cred || !maskedPlain ? maskWord(w.word) : w.word
              return (
                <div key={`${w.label}:${w.word}`} className="flex items-center justify-between gap-3 rounded-lg border bg-muted/30 px-3 py-2 text-sm">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="shrink-0 rounded border px-1.5 py-0.5 text-[10px] text-muted-foreground">{w.label}</span>
                    <span className="truncate font-mono text-xs" title={display}>{display}</span>
                    {cred && <LockKeyhole className="h-3 w-3 shrink-0 text-muted-foreground" aria-label={t('stats.credHint')} />}
                  </div>
                  <span className="shrink-0 tabular-nums text-xs text-muted-foreground">×{w.count.toLocaleString()}</span>
                </div>
              )
            })}
            {(stats?.top_words ?? []).length === 0 && (
              <p className="py-8 text-center text-sm text-muted-foreground">{t('dash.noMaskedToday')}</p>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* 今日还原明细弹窗（已还原回复卡）：明文开关，凭据类恒打码 */}
      <Dialog open={restoredOpen} onOpenChange={(v) => { setRestoredOpen(v); if (!v) setRestoredPlain(false) }}>
        <DialogContent className="max-h-[80vh] max-w-2xl overflow-y-auto">
          <DialogHeader>
            <div className="flex items-center justify-between gap-2">
              <DialogTitle>{t('dash.restoredDetail')}</DialogTitle>
              <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground">
                <Switch checked={restoredPlain} onCheckedChange={setRestoredPlain} className="scale-75" />
                <span className="select-none">{t('stats.showPlain')}</span>
              </label>
            </div>
          </DialogHeader>
          <div className="space-y-2">
            {(restoreItems?.items ?? []).map((it, i) => {
              const display = it.cred || !restoredPlain ? it.preview : (it.original ?? it.preview)
              return (
                <div key={it.label + i} className="flex items-center justify-between gap-3 rounded-lg border bg-muted/30 px-3 py-2 text-sm">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="shrink-0 rounded border px-1.5 py-0.5 text-[10px] text-muted-foreground">{it.label}</span>
                    <span className="truncate font-mono text-xs" title={display}>{display}</span>
                    {it.cred && <LockKeyhole className="h-3 w-3 shrink-0 text-muted-foreground" aria-label={t('stats.credHint')} />}
                  </div>
                  <span className="shrink-0 tabular-nums text-xs text-muted-foreground">×{it.events}</span>
                </div>
              )
            })}
            {(restoreItems?.items ?? []).length === 0 && (
              <p className="py-8 text-center text-sm text-muted-foreground">{t('dash.noRestoreToday')}</p>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
