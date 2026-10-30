/**
 * 控制台（对标旧版概览仪表盘）：
 * - 大状态横幅：过滤状态 + 捕获模式 + 运行时长
 * - 6 张统计卡：今日请求 / 已脱敏 / 已还原回复 / 告警(4子项) / Token(输入输出) / 今日费用估算
 * - 前缀保真度卡：零改写透传率 / 占位符复用率 / 平均首个差异字节（MASK 事件诊断字段）
 * - 网关管理快捷操作：启停 / CA证书 / 健康检查 / 紧急恢复
 * - 核心安全防护策略：failClosed / responseScan / SSE / 流式排除 / 自启 / 自启代理
 * - 最近事件 7 列表格
 * - 向导横幅 / 自动恢复横幅 / 引擎错误横幅
 */
import { useMemo, useState } from 'react'
import { useVisibility } from '@/lib/useVisibility'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import {
  ShieldCheck,
  ShieldOff,
  Activity,
  Shield,
  Zap,
  Coins,
  AlertCircle,
  AlertTriangle,
  Globe,
  X,
  Clock,
  ArrowRight,
  Gauge,
  Loader2,
  LockKeyhole,
} from 'lucide-react'
import { getStatus, dismissAutoRecover } from '@/api/proxy'
import { getTodayStats, getRestoreItems, getConfig, saveConfig, getHealth, getStatsModels, getStatsHistory, type StatsHistoryPoint } from '@/api/settings'
import { getLogs } from '@/api/logs'
import { mergeMaskRestore, type MergedEvent } from '@/lib/log-events'
import { EventTypeIcon, EVENT_TYPE_META } from '@/components/events/EventTypeIcon'
import { OutcomeBadge } from '@/components/events/OutcomeBadge'
import { deriveOutcome, describeTerminal } from '@/lib/log-outcome'
import { EventDetailDialog } from '@/components/events/EventDetailDialog'
import { DiagnosticPreviewButton } from '@/components/settings/DiagnosticPreviewButton'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table'
import { cn, formatCompactNumber, formatTokensShort, formatBytes, formatPercent } from '@/lib/utils'
import { CRED_LABELS, maskWord } from '@/lib/sensitive-word'
import { groupWordsByIngress, ingressQuery } from '@/lib/ingress-groups'
import { Hint } from '@/components/common/Hint'
import { StatCard } from '@/components/patterns/StatCard'
import { PageHeader } from '@/components/patterns/PageHeader'
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

function renderStatValue(v?: string | null) {
  if (typeof v === 'string' && v.startsWith('$')) {
    return (
      <>
        <span className="mr-0.5 text-[20px] font-normal text-muted-foreground">$</span>
        <span>{v.slice(1)}</span>
      </>
    )
  }
  return v ?? '—'
}

/**
 * 迷你趋势图：一条面积折线，不引图表库。
 *
 * 为什么首页需要它：6 张数字卡 + 一堆开关，整页没有任何「视觉主体」，
 * 材质调得再细也只是「干净」。一张横跨的曲线卡能把视线先钉住，
 * 其余信息退成背景 —— 这是「好看」和「不难看」的分界。
 */
function Sparkline({ points }: { points: StatsHistoryPoint[] }) {
  const W = 800
  const H = 120
  const pad = { t: 10, r: 8, b: 22, l: 8 }
  const vals = points.map((p) => p.requests ?? 0)
  const max = Math.max(1, ...vals)
  const n = Math.max(1, vals.length - 1)
  const x = (i: number) => pad.l + (i / n) * (W - pad.l - pad.r)
  const y = (v: number) => pad.t + (1 - v / max) * (H - pad.t - pad.b)

  // Catmull-Rom → 三次贝塞尔：控制点取相邻点的切线（p1 + (p2-p0)/6），
  // 曲线贴合数据点。用「中点做控制点」会过度圆润，7 个点的日数据会被画成一团软波。
  let path = ''
  if (vals.length > 1) {
    path = `M ${x(0)} ${y(vals[0])}`
    for (let i = 0; i < vals.length - 1; i++) {
      const p0 = { x: x(Math.max(0, i - 1)), y: y(vals[Math.max(0, i - 1)]) }
      const p1 = { x: x(i), y: y(vals[i]) }
      const p2 = { x: x(i + 1), y: y(vals[i + 1]) }
      const p3 = { x: x(Math.min(vals.length - 1, i + 2)), y: y(vals[Math.min(vals.length - 1, i + 2)]) }
      const c1 = { x: p1.x + (p2.x - p0.x) / 6, y: p1.y + (p2.y - p0.y) / 6 }
      const c2 = { x: p2.x - (p3.x - p1.x) / 6, y: p2.y - (p3.y - p1.y) / 6 }
      path += ` C ${c1.x} ${c1.y}, ${c2.x} ${c2.y}, ${p2.x} ${p2.y}`
    }
  }
  const area = vals.length > 1 ? `${path} L ${x(vals.length - 1)} ${H - pad.b} L ${x(0)} ${H - pad.b} Z` : ''
  const last = vals.length - 1
  const firstLabel = points[0]?.label ?? ''
  const lastLabel = points[last]?.label ?? ''

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="mt-3 block w-full" style={{ height: 120 }} preserveAspectRatio="none">
      <defs>
        <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity="0.30" />
          <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0" />
        </linearGradient>
      </defs>
      {area && <path d={area} fill="url(#spark-fill)" />}
      {path && (
        <path
          d={path}
          fill="none"
          stroke="hsl(var(--primary))"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
      )}
      {last >= 0 && (
        <circle cx={x(last)} cy={y(vals[last])} r="3.5" fill="hsl(var(--primary))" stroke="hsl(var(--card))" strokeWidth="2" vectorEffect="non-scaling-stroke" />
      )}
      {/* 首尾日期锚点：没有它，曲线只是「一条好看的线」，看不出覆盖了哪几天 */}
      <g fill="hsl(var(--muted-foreground))" fontSize="10" fontFamily="inherit">
        <text x={pad.l} y={H - 6}>{firstLabel}</text>
        <text x={W - pad.r} y={H - 6} textAnchor="end">{lastLabel}</text>
      </g>
    </svg>
  )
}

export default function Dashboard() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
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

  // 前缀保真度：null = 本区间一条 MASK 事件都没有（空库 / 老库刚升级）。
  // 与「有样本但零改写率 0%」必须分开渲染——前者是没数据，后者是数据很差。
  const prefix = stats?.prefix ?? null

  // 最近事件：合并 MASK/RESTORE 成「一次请求一行」并取最新 10 行（与 Logs 页同口径）。
  // nowSec 与行一起返回：结论里的「进行中 / 未完成」需要它，且必须与筛选用同一个值。
  const { rows: recentMerged, nowSec } = useMemo(() => {
    const now = Date.now() / 1000
    return { rows: mergeMaskRestore(recentLogs?.events ?? [], { nowSec: now }).slice(0, 10), nowSec: now }
  }, [recentLogs?.events])

  /**
   * 状态列文案（无 HTTP 码时的回退）：终态归因 → 原始 status 语义。
   * 与 Logs 页同一口径：CANCEL/ERR 显示「客户端断开 / 上游静默 106s / 域名解析失败」，
   * 而不是旧实现那句 `String(status).slice(0, 6)`（把 restored 截成 restor）。
   */
  const statusText = (e: MergedEvent): string | null => {
    const term = describeTerminal(e)
    if (term) return term.vars ? tf(term.key, term.vars) : t(term.key)
    if (e.status) {
      return e.status === 'no_placeholder_in_response'
        ? t('logs.statusNoRestore')
        : e.status === 'no_sensitive_data'
          ? t('logs.statusNoSensitive')
          : String(e.status)
    }
    return null
  }

  // 今日费用估算：读 /api/stats/models?days=1（today 自然日），只计已定价模型
  const todayCostModels = costData?.models ?? []
  const todayCost = todayCostModels.reduce((s, m) => s + (m.priced ? (m.cost_usd ?? 0) : 0), 0)
  const todayPricedCount = todayCostModels.filter((m) => m.priced).length
  // 有请求但一个模型都没定价 → 费用估算不可用（不展示假 0 账单）
  const todayCostUnavailable =
    todayCostModels.length > 0 && todayPricedCount === 0
  const todayCostReady = Boolean(costData)

  const unitSystem = t('stats.unitSystem') === 'si' ? 'si' : 'cjk'
  const reqNum = formatCompactNumber(stats?.requests ?? 0, unitSystem)
  const maskNum = formatCompactNumber(stats?.mask_events ?? 0, unitSystem)
  const restoreNum = formatCompactNumber(stats?.restored ?? 0, unitSystem)
  const alertNum = formatCompactNumber(stats?.alerts ?? 0, unitSystem)
  // 趋势卡与下面 6 张卡共用一个区间控件：原先两块各有一组胶囊，纵向相邻、长得一模一样、
  // 作用域却不同（一块管曲线、一块管卡片），用户没有线索能分清。
  // 今日没有「多日趋势」可画，退化成近 7 天，标题跟着改写。
  const trendDays: 7 | 30 = statsRange === '30d' ? 30 : 7
  const { data: trendData } = useQuery({
    queryKey: ['statsHistory', 'day', trendDays],
    queryFn: () => getStatsHistory(trendDays, 'day'),
    refetchInterval: hidden ? false : 60000,
  })
  const trendPoints = useMemo(() => trendData?.data ?? [], [trendData])
  // 副指标必须与曲线同口径：它们原先取自 stats（跟随下方 6 卡的区间），
  // 于是「近 7 天 7,990」下面挂着「已脱敏 1,284」，两个数说的不是同一件事。
  const trendTotals = useMemo(
    () =>
      trendPoints.reduce(
        (acc, p) => ({
          requests: acc.requests + (p.requests ?? 0),
          masks: acc.masks + (p.mask_events ?? 0),
          restored: acc.restored + (p.restored ?? 0),
          alerts: acc.alerts + (p.alerts ?? 0),
        }),
        { requests: 0, masks: 0, restored: 0, alerts: 0 },
      ),
    [trendPoints],
  )
  // 环比：最后一点 vs 前一点（日粒度）。没有前一日样本就不显示 —— 不拿 0 当分母，
  // 也不在没有数据时编一个趋势出来。
  const trendDelta = useMemo(() => {
    if (trendPoints.length < 2) return null
    const prev = trendPoints[trendPoints.length - 2]?.requests ?? 0
    const cur = trendPoints[trendPoints.length - 1]?.requests ?? 0
    if (prev <= 0) return null
    return Math.round(((cur - prev) / prev) * 100)
  }, [trendPoints])

  const tokenNum = formatCompactNumber(tokensTotal, unitSystem)

  // 6 张统计卡（i18n）。字段即 <StatCard> 的入参，样式一律由组件决定，
  // 这里只描述数据——旧版每个元素还带 icon/iconBg/num（渲染类名），
  // 一处视觉结果散在数组里，改版时最容易漏。
  interface DashStatCard {
    label: string
    icon?: React.ComponentType<{ className?: string }>
    iconTone?: 'primary' | 'success' | 'warning' | 'muted'
    value: string
    fullValue?: string
    isCompact?: boolean
    hint?: string
    hintTitle?: string
    sub?: { label: string; value: number | string; title?: string }[]
    tone?: 'warning' | 'danger'
    to?: string
    onClick?: () => void
  }
  const hasAlert = (stats?.alerts ?? 0) > 0
  const statCards: DashStatCard[] = [
    {
      label: t('dash.reqToday'),
      icon: Activity,
      value: reqNum.compact,
      fullValue: reqNum.full,
      isCompact: reqNum.isCompact,
      hint: t('dash.reqHint'),
      to: '/logs',
    },
    {
      label: t('dash.maskedReq'),
      icon: Shield,
      iconTone: 'primary',
      value: maskNum.compact,
      fullValue: maskNum.full,
      isCompact: maskNum.isCompact,
      hint: `${t('dash.maskedHint')} ${formatTokensShort(stats?.masked_items ?? 0, unitSystem)}`,
      hintTitle: `${t('dash.maskedHint')} ${(stats?.masked_items ?? 0).toLocaleString()}`,
      onClick: () => setMaskedOpen(true),
    },
    {
      label: t('dash.restored'),
      icon: ShieldCheck,
      iconTone: 'success',
      value: restoreNum.compact,
      fullValue: restoreNum.full,
      isCompact: restoreNum.isCompact,
      hint: t('dash.restoredHint'),
      onClick: () => setRestoredOpen(true),
    },
    {
      label: t('dash.alerts'),
      icon: AlertCircle,
      iconTone: hasAlert ? 'warning' : 'muted',
      value: alertNum.compact,
      fullValue: alertNum.full,
      isCompact: alertNum.isCompact,
      sub: [
        { label: t('dash.blocked'), value: ((stats as Record<string, unknown> | undefined)?.by_type as Record<string, {events:number}> | undefined)?.BLOCK?.events ?? 0 },
        { label: t('dash.restoreFail'), value: stats?.restore_failed ?? 0, title: t('logs.unresolvedHint') },
        { label: t('dash.errors'), value: ((stats as Record<string, unknown> | undefined)?.by_type as Record<string, {events:number}> | undefined)?.ERR?.events ?? 0 },
        { label: t('dash.respWarn'), value: ((stats as Record<string, unknown> | undefined)?.by_type as Record<string, {events:number}> | undefined)?.SCAN_WARN?.events ?? 0 },
        // 外部占位符：本机从未签发过的占位符形态字符串（客户端历史携带 / 文档示例 /
        // 模型自造）。**既不计入 alerts、也不计入「还原失败」**——本机无论如何都
        // 还原不了它们，混进还原失败只会让指标长期虚高（实测当天 4 条里 0 条是
        // 本机签发过的）。恒显示（0 也是值），避免有时有有时无让用户以为漏了。
        { label: t('dash.foreignTokens'), value: stats?.restore_by_status?.foreign ?? 0, title: t('dash.foreignTokensHint') },
      ],
      tone: hasAlert ? 'warning' : undefined,
      to: '/logs',
    },
    {
      label: t('dash.tokenToday'),
      icon: Zap,
      value: tokenNum.compact,
      fullValue: tokenNum.full,
      isCompact: tokenNum.isCompact,
      hint: `${t('dash.tokenHint')} ${formatTokensShort(stats?.tokens.prompt ?? 0, unitSystem)} · ${formatTokensShort(stats?.tokens.completion ?? 0, unitSystem)}`,
      hintTitle: `${t('dash.tokenHint')} ${(stats?.tokens.prompt ?? 0).toLocaleString()} · ${(stats?.tokens.completion ?? 0).toLocaleString()}`,
      to: '/stats',
    },
    {
      // 今日费用估算：按模型价格 × 今日 token 用量估算，未定价模型不计入；
      // 请求加载中显示破折号，有请求但全部未定价时提示估算不可用（不展示假 0 账单）。
      label: t('dash.costToday'),
      icon: Coins,
      value: !todayCostReady || todayCostUnavailable ? '—' : `$${Number(todayCost || 0).toFixed(4)}`,
      hint: !todayCostReady ? t('common.loading') : todayCostUnavailable ? t('dash.costUnavailable') : t('dash.costHint'),
      to: '/stats',
    },
  ]

  return (
    <div className="space-y-6">
      {/* 页面标题：Logs / Settings 都有可见大标题，只有控制台把它藏成 sr-only，
          于是这一页从状态条直接开始 —— 没有标题层级，整片内容缺一个「从哪读起」。 */}
      <PageHeader title={t('nav.dashboard')} subtitle={t('dash.subtitle')} />
      {/* ===== 大状态横幅 ===== */}
      <div
        className={cn(
          // 状态条：单行、中性底，状态靠图标与文案表达。旧版每种状态一个渐变底色
          // （绿/橙/灰三套），每屏最大的一块颜色被一个「一直在那里」的常驻区占死，
          // 真正需要颜色的告警反而看不出。
          'flex flex-wrap items-center gap-4 rounded-xl border border-border bg-card px-4 py-3.5 transition-colors duration-300',
        )}
      >
        <div
          className={cn(
            'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg',
            isStarting || isStopping
              ? 'bg-warning/10 text-warning-ink'
              : running && filterOn
                ? 'bg-primary/10 text-primary-ink'
                : running
                  ? 'bg-warning/10 text-warning-ink'
                  : 'bg-muted text-muted-foreground',
          )}
        >
          {isStarting || isStopping ? (
            <Loader2 className="h-[18px] w-[18px] animate-spin" />
          ) : running && filterOn ? (
            <ShieldCheck className="h-[18px] w-[18px]" />
          ) : (
            <ShieldOff className="h-[18px] w-[18px]" />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[15px] font-semibold tracking-tight">
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
              <span className="rounded-md border border-border bg-muted px-2 py-0.5 text-2xs font-medium text-muted-foreground">
                {t(`dash.captureMode.${status?.capture_mode ?? 'reverse'}`)}
              </span>
            )}
          </div>
          <p className="mt-0.5 text-[12px] text-muted-foreground">
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

      {/* 趋势焦点卡：整页唯一的「视觉主体」。
          在此之前，控制台是 6 张等权数字卡叠一堆开关，视线无处停留；
          一张横跨的曲线把「现在什么态势」先讲清楚，其余信息自然退成背景。 */}
      <Card className="border bg-card shadow-card">
        <CardContent className="p-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              {/* 用「区间累计」而不是「今日」：下面 6 张卡已经是今日口径，
                  焦点卡再报一次今日请求就是重复信息，占着最贵的位置说同一件事。 */}
              <div className="text-[12px] font-medium text-muted-foreground">
                {trendDays === 7 ? t('dash.stats7d') : t('dash.stats30d')}
              </div>
              <div className="mt-1.5 flex items-baseline gap-2.5">
                <div
                  className="text-[42px] font-semibold leading-none tabular-nums tracking-[-0.03em]"
                  title={String(trendTotals.requests)}
                >
                  {formatCompactNumber(trendTotals.requests, unitSystem).compact}
                </div>
                {trendDelta !== null && (
                  <span
                    className={cn(
                      'text-[13px] font-medium tabular-nums',
                      trendDelta > 0
                        ? 'text-success-ink'
                        : trendDelta < 0
                          ? 'text-destructive-ink'
                          : 'text-muted-foreground',
                    )}
                  >
                    {trendDelta > 0 ? '↑' : trendDelta < 0 ? '↓' : '·'} {Math.abs(trendDelta)}%
                  </span>
                )}
              </div>
              <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-2xs text-muted-foreground">
                <span>
                  {t('dash.maskedReq')}{' '}
                  <b className="font-medium tabular-nums text-foreground">
                    {formatCompactNumber(trendTotals.masks, unitSystem).compact}
                  </b>
                </span>
                <span>
                  {t('dash.restored')}{' '}
                  <b className="font-medium tabular-nums text-foreground">
                    {formatCompactNumber(trendTotals.restored, unitSystem).compact}
                  </b>
                </span>
                <span>
                  {t('dash.alerts')}{' '}
                  <b
                    className={cn(
                      'font-medium tabular-nums',
                      trendTotals.alerts > 0 ? 'text-warning-ink' : 'text-foreground',
                    )}
                  >
                    {formatCompactNumber(trendTotals.alerts, unitSystem).compact}
                  </b>
                </span>
              </div>
            </div>
          </div>
          <Sparkline points={trendPoints} />
        </CardContent>
      </Card>

      {/* 引擎错误横幅 */}
      {status?.last_error && !status.auto_recover_fail && (
        <div className="flex items-center gap-2 rounded-xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive-ink">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span className="min-w-0 flex-1 truncate">{t('dash.engineError')}{status.last_error}</span>
          <DiagnosticPreviewButton />
        </div>
      )}

      {/* 环境变量 token 被忽略：Docker 无头用户翻不到启动日志，必须首屏可见 */}
      {status?.panel_token_env_rejected && (
        <div className="flex items-center gap-2 rounded-xl border border-warning/30 bg-warning/10 px-4 py-3 text-sm text-warning-ink">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span className="min-w-0 flex-1">{t('dash.panelTokenRejected')}</span>
        </div>
      )}

      {/* 自动恢复横幅 */}
      {status?.auto_recovered_at && !status.auto_recover_fail && (
        <div className="flex items-center gap-2 rounded-xl border border-success/30 bg-success/10 px-4 py-3 text-sm text-success-ink">
          <ShieldCheck className="h-4 w-4 shrink-0" />
          <span>{tf('dash.autoRecovered', { time: status.auto_recovered_at ? dayjs(status.auto_recovered_at).format('HH:mm:ss') : '—' })}</span>
          <Button size="icon" variant="ghost" className="ml-auto h-6 w-6 shrink-0" onClick={dismiss}>
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>
      )}
      {status?.auto_recover_fail && (
        <div className="flex items-center gap-2 rounded-xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive-ink">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span className="min-w-0 flex-1 truncate">{t('dash.autoRecoverFail')}{status.auto_recover_fail}</span>
          <Button size="icon" variant="ghost" className="ml-auto h-6 w-6 shrink-0" onClick={dismiss}>
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>
      )}

      {/* 向导横幅 */}
      {status?.wizard_recommended && (
        <div className="flex items-center gap-3 rounded-xl border bg-card p-4">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/15 font-bold text-primary-ink">1</div>
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
        <div className="flex items-center gap-2 rounded-xl border border-warning/40 bg-warning/10 p-3 text-xs">
          <AlertTriangle className="h-4 w-4 shrink-0 text-warning-ink" />
          <span className="text-warning-ink">
            {t('dash.writerIssue')}
            {ws.event_writer?.drops ? tf('dash.writerDropped', { n: ws.event_writer.drops }) : ''}
            {ws.audit_writer?.drops ? ` / ${tf('dash.writerAuditDropped', { n: ws.audit_writer.drops })}` : ''}
            {ws.event_writer?.dead_letters ? ` / ${tf('dash.writerDead', { n: ws.event_writer.dead_letters })}` : ''}
            {ws.event_writer?.restarts ? ` / ${tf('dash.writerRestarts', { n: ws.event_writer.restarts })}` : ''}
            {t('dash.writerLost')}
          </span>
        </div>
      )}

      {/* ===== 统计分组 =====
          6 张卡放进一块灰底面板，而不是直接铺在页面底色上。
          同一张白卡压 #ebebed 与压在 #e1e1e4 上是两个观感：后者让「这 6 张说的是
          同一件事」在视觉上成立，页面也终于有了块面，而不是一片白卡平铺到底。 */}
      <section className="rounded-2xl border border-border/70 bg-muted/60 p-2.5">
      <div className="mb-2.5 flex items-center justify-between px-1.5 pt-0.5">
        <h2 className="text-[13px] font-semibold text-muted-foreground">
          {statsRange === 'today' ? t('dash.statsToday') : statsRange === '7d' ? t('dash.stats7d') : t('dash.stats30d')}
        </h2>
        <div className="flex items-center gap-1 rounded-full bg-background/70 p-1 text-xs">
          {([['today', t('dash.today')], ['7d', t('dash.7d')], ['30d', t('dash.30d')]] as const).map(([k, label]) => (
            <button
              key={k}
              type="button"
              onClick={() => setStatsRange(k)}
              className={cn('rounded-full px-3 py-1 font-medium transition-all', statsRange === k ? 'bg-card text-foreground shadow-[0_1px_2px_rgb(0_0_0/0.18)] ring-1 ring-black/5 dark:ring-white/10' : 'text-muted-foreground hover:text-foreground')}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      {/* 6 卡：窄屏 2 列、中屏 3 列，≥1536px 直接一行 6 列 ——
          1440 宽下 3 列会让每张卡横向白白多出 ~120px，数字反而显得空旷。 */}
      <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
        {statCards.map((c) => {
          const interactive = !!(c.to || c.onClick)
          const card = (
            <StatCard
              label={c.label}
              {...(c.icon ? { icon: c.icon } : {})}
              {...(c.iconTone ? { iconTone: c.iconTone } : {})}
              value={c.isCompact ? renderStatValue(c.value) : c.value}
              {...(c.isCompact && c.fullValue ? { fullValue: c.fullValue } : {})}
              {...(c.sub ? { sub: c.sub } : {})}
              {...(c.hint ? { hint: c.hint } : {})}
              {...(c.hintTitle ? { hintTitle: c.hintTitle } : {})}
              {...(c.tone ? { tone: c.tone } : {})}
              interactive={interactive}
              {...(c.onClick ? { onClick: c.onClick } : {})}
            />
          )
          return c.to
            ? <Link key={c.label} to={c.to} className="block h-full">{card}</Link>
            : <div key={c.label} className="h-full">{card}</div>
        })}
      </div>
      </section>

      {/* 前缀保真度：MASK 事件三个诊断字段（body_rewritten / first_diff_byte /
          suffix_reused）的聚合，用来回答「上游缓存命中率掉了，是我们改了请求
          字节还是上游自己 miss」。刻意**不塞进上面那个 6 卡网格**——它的列数
          （2/3/6）是按 6 张卡调过的，第 7 张在 ≥1536px 宽屏上会单独落一行。
          第一列分母是 masks（全部样本）；第二、三列分母是 rewritten（改写过的
          请求）——`suffix_reused` 与 `first_diff_byte` 都只在回写分支才有意义，
          零改写透传的请求没签发票据、也没有差异位，用 masks 当分母会把指标
          稀释成「复用机制没生效」（实测 100 次请求 10 次命中、8 次复用，
          用 masks 显示 8%，真实是 80%）。
          `prefix` 为 null 时按 mask_events 区分两种「没有数据」：区间内压根没
          请求 vs 有请求但都早于该统计上线（升级当天就是后者，不能说成「脱敏
          没生效」）。 */}
      <Card className="border bg-card shadow-card">
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
              <Gauge className="h-[18px] w-[18px]" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5 text-[13px] font-semibold leading-5 text-foreground/80">
                <span>{t('dash.prefixFidelity')}</span>
                <Hint text={t('dash.prefixFidelityTooltip')} />
              </div>
              <div className="text-2xs font-medium text-muted-foreground">{t('dash.prefixHint')}</div>
            </div>
            {prefix && (
              <span className="shrink-0 rounded-md border border-border bg-muted px-2 py-0.5 text-2xs font-medium text-muted-foreground">
                {tf('dash.prefixSamples', { n: prefix.masks.toLocaleString() })}
              </span>
            )}
          </div>
          <div className="mt-4 grid grid-cols-3 gap-3 border-t pt-3">
            <div className="min-w-0">
              <div className="flex items-center gap-1 text-2xs font-medium text-muted-foreground">
                <span className="truncate">{t('dash.prefixClean')}</span>
                <Hint text={t('dash.prefixCleanTooltip')} />
              </div>
              <div className="text-[20px] font-semibold leading-tight tabular-nums text-foreground">
                {prefix ? formatPercent(prefix.clean_rate, 1, { isNotFull: prefix.clean < prefix.masks }) : '—'}
              </div>
              <div className="truncate text-2xs text-muted-foreground">
                {prefix
                  ? `${prefix.clean.toLocaleString()} / ${prefix.masks.toLocaleString()}`
                  : (stats?.mask_events ?? 0) > 0
                    ? t('dash.prefixNoSamples')
                    : t('dash.prefixNoData')}
              </div>
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-1 text-2xs font-medium text-muted-foreground">
                <span className="truncate">{t('dash.prefixReuse')}</span>
                <Hint text={t('dash.prefixReuseTooltip')} />
              </div>
              <div className="text-[20px] font-semibold leading-tight tabular-nums text-foreground">
                {prefix?.reuse_rate != null
                  ? formatPercent(prefix.reuse_rate, 1, {
                      isNotFull: prefix.rewritten > 0 && prefix.suffix_reused < prefix.rewritten,
                    })
                  : '—'}
              </div>
              <div className="truncate text-2xs text-muted-foreground">
                {prefix
                  ? prefix.rewritten > 0
                    ? `${prefix.suffix_reused.toLocaleString()} / ${prefix.rewritten.toLocaleString()}`
                    : t('dash.prefixNoPlaceholder')
                  : '—'}
              </div>
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-1 text-2xs font-medium text-muted-foreground">
                <span className="truncate">{t('dash.prefixDiff')}</span>
                <Hint
                  text={t('dash.prefixDiffTooltip')}
                  content={
                    <>
                      <div>{t('dash.prefixDiffTooltip')}</div>
                      {prefix?.avg_first_diff != null && (
                        <div className="mt-1 border-t border-border pt-1 text-2xs text-muted-foreground">
                          {tf('dash.prefixDiffExact', { n: prefix.avg_first_diff.toLocaleString() })}
                        </div>
                      )}
                    </>
                  }
                />
              </div>
              <div className="text-[20px] font-semibold leading-tight tabular-nums text-foreground">
                {prefix?.avg_first_diff != null ? formatBytes(prefix.avg_first_diff) : '—'}
              </div>
              <div className="truncate text-2xs text-muted-foreground">
                {prefix
                  ? prefix.rewritten > 0
                    ? `${prefix.diff_samples.toLocaleString()} / ${prefix.rewritten.toLocaleString()}`
                    : t('dash.prefixNoRewrite')
                  : '—'}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>


{/* 核心安全防护策略 */}
<Card className="overflow-hidden border bg-card shadow-card">
          <div className="flex items-center justify-between border-b p-4">
            <h3 className="flex items-center gap-2 text-[15px] font-semibold">
              <ShieldCheck className="h-[18px] w-[18px] text-muted-foreground" />
              {t('dash.security')}
            </h3>
            <span className="flex items-center gap-1.5 rounded-md border border-border bg-muted px-2 py-0.5 text-2xs font-medium text-muted-foreground">
              <span className="h-1.5 w-1.5 rounded-full bg-success" />
              {t('dash.live')}
            </span>
          </div>
          <CardContent className="space-y-3.5 p-4">
            {([
              ['fail_closed', t('dash.failClosed'), t('dash.failClosedDesc')],
              ['response_scan', t('dash.respScan'), t('dash.respScanDesc')],
            ] as [string, string, string][]).map(([k, title, desc]) => (
              <label key={k} className="flex cursor-pointer select-none items-center justify-between border-t pt-3.5 first:border-t-0 first:pt-0 transition-colors hover:text-foreground">
                <div className="flex min-w-0 items-center gap-1.5">
                  <span className="truncate text-sm font-semibold">{title}</span>
                  <Hint text={desc} />
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
                  <Hint text={desc} />
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
      <Card className="overflow-hidden border bg-card shadow-card">
        <div className="flex items-center justify-between border-b bg-muted/20 p-5">
          <div className="flex items-center gap-3">
            <h3 className="text-base font-bold">{t('dash.recentLogs')}</h3>
            <span className="rounded-full border bg-secondary px-2 py-0.5 font-mono text-2xs text-muted-foreground">{t('dash.livePush')}</span>
          </div>
          <Link to="/logs" className="flex items-center gap-1 text-sm font-semibold text-primary-ink hover:underline">
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
                    {/* 结论（与 Logs 页同一列语义）：事件类型降为左侧小图标，悬停可看 */}
                    <span className="flex items-center gap-1.5">
                      <span className="shrink-0" title={t(EVENT_TYPE_META[e.type]?.labelKey ?? e.type)}>
                        <EventTypeIcon type={e.type} className="h-3 w-3 opacity-60" />
                      </span>
                      <OutcomeBadge outcome={deriveOutcome(e, nowSec)} />
                    </span>
                  </TableCell>
                  {/* 上游：优先配置名 upstream，client_app（进程探测）仅作缺失回退；扩展流量加小徽标 */}
                  <TableCell className="py-2.5 px-4 truncate text-xs text-muted-foreground" title={String(e.upstream || e.client_app || '')}>
                    <span className="flex items-center gap-1">
                      {e.ingress === 'ext' && <Globe className="h-3 w-3 shrink-0 text-primary-ink" />}
                      <span className="min-w-0 truncate">{String(e.upstream || e.client_app || '—')}</span>
                    </span>
                  </TableCell>
                  {/* 模型：完整 host/path 放 title（悬停可见），列只展示模型名 */}
                  <TableCell className="py-2.5 px-4 font-mono text-2xs" title={`${e.host ?? ''}${e.path ?? ''}${e.model ? `\n${tf('logs.modelIn', { m: e.model })}` : ''}`}>
                    <div className="flex items-center gap-1.5 truncate">
                      <span className="truncate">{e.model || (e.upstream ? '—' : e.host) || '—'}</span>
                      {e.stream_actual && (
                        <span className="shrink-0 rounded bg-muted/60 px-1 py-0.5 font-mono text-2xs text-muted-foreground">
                          {e.stream_actual === 'stream' ? t('logs.streaming') : t('logs.whole')}
                        </span>
                      )}
                    </div>
                  </TableCell>
                  {/* 脱敏/还原/未还原/兜底：与 Logs 页口径完全对齐（未还原用琥珀告警，兜底用中性） */}
                  <TableCell className="py-2.5 px-4 text-xs">
                    {((e.count ?? 0) > 0 || (e.restored ?? 0) > 0 || (e.unresolved ?? 0) > 0 || (e.degraded ?? 0) > 0) ? (
                      <span className="flex items-center gap-1.5">
                        {(e.count ?? 0) > 0 && <span className="text-primary-ink">{t('logs.colMasked')} {e.count}</span>}
                        {(e.restored ?? 0) > 0 && <span className="text-success-ink">{t('logs.colRestored')} {e.restored}</span>}
                        {(e.unresolved ?? 0) > 0 && <span className="text-warning-ink" title={t('logs.unresolvedHint')}>{t('logs.colUnresolved')} {e.unresolved}</span>}
                        {(e.degraded ?? 0) > 0 && <span className="text-muted-foreground" title={t('logs.degradedHint')}>{t('logs.colDegraded')} {e.degraded}</span>}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  {/* 状态：http_status 状态码或终态归因/status 语义（与 Logs 页同口径） */}
                  <TableCell className="py-2.5 px-4 text-center">
                    {e.http_status ? (
                      <Badge
                        variant="outline"
                        className={cn(
                          'px-1 py-0 text-2xs font-mono',
                          e.http_status >= 400
                            ? 'border-destructive/30 bg-destructive/10 text-destructive-ink'
                            : e.http_status >= 200 && e.http_status < 300
                              ? 'border-success/30 bg-success/10 text-success-ink'
                              : 'border-warning/30 bg-warning/10 text-warning-ink',
                        )}
                      >
                        {e.http_status}
                      </Badge>
                    ) : statusText(e) ? (
                      <span className="truncate text-2xs text-muted-foreground" title={statusText(e) ?? ''}>
                        {statusText(e)}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  {/* 耗时：端到端优先；只有脱敏耗时时显式标注口径（与 Logs 页同口径） */}
                  <TableCell className="py-2.5 px-4 text-right tabular-nums text-xs text-muted-foreground">
                    {(e.total_ms ?? e.upstream_ms) != null ? (
                      <span title={t('logs.durE2eHint')}>{fmtMs(e.total_ms ?? e.upstream_ms)}</span>
                    ) : e.mask_ms != null ? (
                      <span className="text-muted-foreground" title={t('logs.durMaskHint')}>
                        {tf('logs.durMask', { v: fmtMs(e.mask_ms) })}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  {/* 费用：RESTORE 事件由后端按 model×usage 估算，与 Logs 页口径一致 */}
                  <TableCell className="py-2.5 px-4 text-right tabular-nums text-2xs">
                    {e.cost_usd != null && e.cost_usd > 0 ? (
                      <span className="text-success-ink">${e.cost_usd.toFixed(4)}</span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
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
              className="border bg-card shadow-card transition-all duration-200 hover:-translate-y-0.5 hover:shadow-card-hover"
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-[15px] font-semibold">{u.name || `:${u.port}`}</span>
                  <span
                    className={cn(
                      'flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-2xs font-medium',
                      u.listening
                        ? 'border-success/30 bg-success/10 text-success-ink'
                        : 'border-border text-muted-foreground',
                    )}
                  >
                    <span
                      className={cn(
                        'h-1.5 w-1.5 rounded-full',
                        u.listening
                          ? 'animate-pulse bg-success'
                          : 'bg-muted-foreground',
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
            <Card className="border bg-card shadow-card">
              <CardContent className="py-10 text-center text-sm text-muted-foreground">
                {t('dash.noClients')}
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* 出口代理提示 */}
      {Boolean(status?.egress_proxy?.enabled) && (status?.egress_proxy_users ?? []).length > 0 && (
        <div className="flex items-center gap-2 rounded-xl border border-warning/20 bg-warning/5 px-4 py-2.5 text-xs text-warning-ink">
          <Globe className="h-3.5 w-3.5 shrink-0" />
          <span>{t('dash.egressOn')}{status!.egress_proxy_users.join(lang === 'en' ? ', ' : '、')}</span>
        </div>
      )}
      {/* egress 开了但没有任何客户端勾选：状态型提示常驻展示（不再走保存 toast，
          那样每存一次任意配置都会重复弹一遍，用户反馈被骚扰） */}
      {Boolean(status?.egress_proxy?.enabled) && (status?.egress_proxy_users ?? []).length === 0 && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-warning/30 bg-warning/10 px-4 py-2.5 text-xs text-warning-ink">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0 text-warning-ink" />
            <span>{t('dash.egressNoUserNotice')}</span>
          </div>
          <Link to="/settings" className="shrink-0 font-medium underline hover:text-foreground">
            {t('settings.clients.goToEgressSetting')}
          </Link>
        </div>
      )}
      {!status?.egress_proxy?.enabled && (status?.egress_proxy_users ?? []).length > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-warning/30 bg-warning/10 px-4 py-2.5 text-xs text-warning-ink">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0 text-warning-ink" />
            <span>{tf('dash.egressNotConfiguredNotice', { list: status!.egress_proxy_users.join(lang === 'en' ? ', ' : '、') })}</span>
          </div>
          <Link to="/settings" className="shrink-0 font-medium underline hover:text-foreground">
            {t('settings.clients.goToEgressSetting')}
          </Link>
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
            {/* 按入口分组同屏（代理链路 / 浏览器扩展），各组各取 Top N。
                组头计数让「×N 与日志条数一致」可核对，跳转恒带 &ingress=。 */}
            {groupWordsByIngress(stats, 20)
              .filter((g) => g.ingress === 'proxy' || !!cfg?.ext_bridge_enabled)
              .map((g) => (
                <div key={g.ingress} className="space-y-2">
                  <div className="flex items-center gap-2 pt-1 text-2xs font-semibold text-muted-foreground">
                    <span>
                      {g.ingress === 'ext'
                        ? tf('logs.ingress.groupExt', { n: g.total.toLocaleString() })
                        : tf('logs.ingress.groupProxy', { n: g.total.toLocaleString() })}
                    </span>
                    <span className="h-px flex-1 bg-border" />
                  </div>
                  {/* ext 组为空但开关是开的 → 恰是「扩展装了但一条都没走通」的信号，
                      保留组头并提示，不静默藏掉 */}
                  {g.items.length === 0 && (
                    <p className="py-3 text-center text-xs text-muted-foreground">
                      {t('logs.ingress.emptyGroup')}
                    </p>
                  )}
                  {g.items.map((w) => {
                    const cred = CRED_LABELS.has(w.label)
                    const display = cred || !maskedPlain ? maskWord(w.word, cred) : w.word
                    const searchTerm = cred ? w.label : (w.word.startsWith('<') ? w.label : w.word)
                    return (
                      <div
                        key={`${g.ingress}:${w.label}:${w.word}`}
                        onClick={() => {
                          setMaskedOpen(false)
                          // 跳转必须带 ingress：否则词条按入口分组、日志列表却不认这个参数，
                          // 又回到「数字对不上」
                          navigate(`/logs?q=${encodeURIComponent(searchTerm)}&fulltext=1${ingressQuery(g.ingress)}`)
                        }}
                        className="group flex cursor-pointer items-center justify-between gap-3 rounded-lg border bg-muted/30 px-3 py-2 text-sm transition-colors hover:border-primary/40 hover:bg-muted/60"
                        title={t('dash.clickToFilterLogs')}
                      >
                        <div className="flex min-w-0 items-center gap-2">
                          <span className="shrink-0 rounded border px-1.5 py-0.5 text-2xs text-muted-foreground">{w.label}</span>
                          <span className="truncate font-mono text-xs" title={display}>{display}</span>
                          {cred && <LockKeyhole className="h-3 w-3 shrink-0 text-muted-foreground" aria-label={t('stats.credHint')} />}
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="shrink-0 tabular-nums text-xs text-muted-foreground">×{w.count.toLocaleString()}</span>
                          <ArrowRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                        </div>
                      </div>
                    )
                  })}
                </div>
              ))}
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
              const searchTerm = it.cred ? it.label : (it.original ?? it.preview)
              return (
                <div
                  key={it.label + i}
                  onClick={() => {
                    setRestoredOpen(false)
                    navigate(`/logs?q=${encodeURIComponent(searchTerm)}&fulltext=1`)
                  }}
                  className="group flex cursor-pointer items-center justify-between gap-3 rounded-lg border bg-muted/30 px-3 py-2 text-sm transition-colors hover:border-primary/40 hover:bg-muted/60"
                  title={t('dash.clickToFilterLogs')}
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="shrink-0 rounded border px-1.5 py-0.5 text-2xs text-muted-foreground">{it.label}</span>
                    <span className="truncate font-mono text-xs" title={display}>{display}</span>
                    {it.cred && <LockKeyhole className="h-3 w-3 shrink-0 text-muted-foreground" aria-label={t('stats.credHint')} />}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="shrink-0 tabular-nums text-xs text-muted-foreground">×{it.events}</span>
                    <ArrowRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                  </div>
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
