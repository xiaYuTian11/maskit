/**
 * 数据统计页（用户要求：单独菜单显示数据统计，按天/小时）。
 * 两个图表：
 *  - 折线图：脱敏 + 还原 + 告警 三条线叠加（带图例 + 渐变填充 + hover 高亮）
 *  - 柱状图：Token 用量（prompt+completion 合计）
 * 顶部汇总数字卡片：总请求 / 总脱敏 / 总还原 / 总告警 / 总 Token
 * 轻量 SVG 图表，不引外部图表库，保持离线。悬停显示数值。
 */
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useVisibility } from '@/lib/useVisibility'
import { getStatsHistory, getTodayStats, getStatsModels, getPriceSyncStatus, type StatsHistoryPoint } from '@/api/settings'
import { BarChart3, TrendingUp, Coins, ShieldCheck, ShieldAlert, RotateCcw, Layers, Trophy, Tags, LockKeyhole } from 'lucide-react'
import { cn } from '@/lib/utils'
import { CRED_LABELS, maskWord } from '@/lib/sensitive-word'
import { useI18n } from '@/lib/i18n'
import dayjs from 'dayjs'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { ShareCard } from '@/components/stats/ShareCard'

type Granularity = 'day' | 'hour'

interface LineMetric {
  key: 'mask_events' | 'restored' | 'alerts'
  /** i18n key：迁移后优先用它取文案 */
  labelKey?: string
  label?: string
  color: string
  fill: string
}

const LINE_METRICS: LineMetric[] = [
  { key: 'mask_events', labelKey: 'stats.mask', color: '#10b981', fill: 'rgba(16,185,129,0.18)' },
  { key: 'restored', labelKey: 'stats.restored2', color: '#8b5cf6', fill: 'rgba(139,92,246,0.18)' },
  { key: 'alerts', labelKey: 'stats.alerts2', color: '#f59e0b', fill: 'rgba(245,158,11,0.18)' },
]

// 审计信号线（新增：注入审计/投毒检测信号数，含高危子计数）
const AUDIT_METRIC = { key: 'audit_signals' as const, labelKey: 'stats.audit2', color: '#ef4444', fill: 'rgba(239,68,68,0.15)' }

const TOKEN_COLOR = '#3b82f6'

export default function StatsPage() {
  const { t } = useI18n()
  const { hidden } = useVisibility()
  const [granularity, setGranularity] = useState<Granularity>('day')
  const [days, setDays] = useState(30)

  const { data, isFetching } = useQuery({
    queryKey: ['statsHistory', granularity, days],
    queryFn: () => getStatsHistory(days, granularity),
    refetchInterval: hidden ? false : 60000,
  })
  // 估算费用合计（与模型排行共用缓存；只计已定价模型）
  const { data: costData } = useQuery({
    queryKey: ['statsModels', '7'],
    queryFn: () => getStatsModels(7),
    refetchInterval: hidden ? false : 60000,
  })
  const totalCost = (costData?.models ?? []).reduce((s2, m) => s2 + (m.priced ? (m.cost_usd ?? 0) : 0), 0)

  // useMemo 包一层：`data?.data ?? []` 每次渲染都会产出新的空数组引用，
  // 让下面 totals 的 useMemo 每帧重算（数据没变也算），等于白写缓存。
  const points = useMemo(() => data?.data ?? [], [data])

  // 汇总数字
  const totals = useMemo(() => {
    let requests = 0
    let mask = 0
    let restored = 0
    let alerts = 0
    let tokens = 0
    let audit = 0
    for (const p of points) {
      requests += p.requests ?? 0
      mask += p.mask_events ?? 0
      restored += p.restored ?? 0
      alerts += p.alerts ?? 0
      tokens += (p.tokens_prompt ?? 0) + (p.tokens_completion ?? 0)
      audit += p.audit_signals ?? 0
    }
    return { requests, mask, restored, alerts, tokens, audit }
  }, [points])

  return (
    <div className="space-y-4">
      {/* 页头 */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t('stats.title')}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{t('stats.subtitle')}</p>
        </div>
        {/* 战绩卡片：本地生成分享图，零上传 */}
        <ShareCard />
      </div>

      {/* 粒度切换 */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border bg-card p-3 shadow-[var(--shadow-card)]">
        <div className="flex items-center gap-1 rounded-lg bg-muted/60 p-0.5 text-xs">
          {([['day', t('stats.byDay')], ['hour', t('stats.byHour')]] as const).map(([k, label]) => (
            <button
              key={k}
              type="button"
              onClick={() => { setGranularity(k); setDays(k === 'hour' ? 24 : 30) }}
              className={cn('rounded-md px-3 py-1 font-medium transition-colors', granularity === k ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1 rounded-lg bg-muted/60 p-0.5 text-xs">
          {granularity === 'day'
            ? ([['7', 'stats.period7d'], ['30', 'stats.period30d'], ['90', 'stats.period90d']] as const).map(([k, lk]) => (
                <button key={k} type="button" onClick={() => setDays(Number(k))} className={cn('rounded-md px-2.5 py-1 font-medium transition-colors', String(days) === k ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')}>{t(lk)}</button>
              ))
            : ([['6', 'stats.period6h'], ['24', 'stats.period24h'], ['72', 'stats.period72h']] as const).map(([k, lk]) => (
                <button key={k} type="button" onClick={() => setDays(Number(k))} className={cn('rounded-md px-2.5 py-1 font-medium transition-colors', String(days) === k ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')}>{t(lk)}</button>
              ))
          }
        </div>
        {isFetching && <span className="ml-auto text-xs text-muted-foreground">{t('stats.refreshing')}</span>}
      </div>

      {/* 汇总数字卡片 */}
      <div className="grid gap-3 grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7">
        <SummaryCard icon={Layers} label={t('stats.totalReq')} value={totals.requests} color="#3b82f6" bg="from-blue-500/15 to-blue-500/5" />
        <SummaryCard icon={ShieldCheck} label={t('stats.totalMasked')} value={totals.mask} color="#10b981" bg="from-emerald-500/15 to-emerald-500/5" />
        <SummaryCard icon={RotateCcw} label={t('stats.totalRestored')} value={totals.restored} color="#8b5cf6" bg="from-violet-500/15 to-violet-500/5" />
        <SummaryCard icon={ShieldAlert} label={t('stats.totalAlerts')} value={totals.alerts} color="#f59e0b" bg="from-amber-500/15 to-amber-500/5" />
        <SummaryCard icon={ShieldCheck} label={t('stats.totalAudit')} value={totals.audit} color="#ef4444" bg="from-red-500/15 to-red-500/5" />
        <SummaryCard icon={Coins} label={t('stats.totalTokens')} value={totals.tokens} color="#ec4899" bg="from-pink-500/15 to-pink-500/5" />
        <SummaryCard icon={Trophy} label={t('stats.estCost')} value={`$${Number(totalCost || 0).toFixed(2)}`} color="#10b981" bg="from-emerald-500/15 to-emerald-500/5" />
      </div>

      {/* 柱状图：Token 用量（放第一，用户指定） */}
      <div className="rounded-xl border bg-card p-5 shadow-[var(--shadow-card)]">
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <BarChart3 className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-semibold">{t('stats.tokenChart')}</span>
          <span className="text-xs text-muted-foreground">{t('stats.tokenHint')}</span>
        </div>
        {points.length === 0 && !isFetching ? (
          <EmptyState />
        ) : (
          <TokenBarChart points={points} />
        )}
      </div>

      {/* 折线图：脱敏 + 还原 + 告警（数值平时不显示，悬停才显示，避免重叠） */}
      <div className="rounded-xl border bg-card p-5 shadow-[var(--shadow-card)]">
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <TrendingUp className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-semibold">{t('stats.trendChart')}</span>
          <span className="text-xs text-muted-foreground">{t('stats.trendHint')}</span>
          <div className="ml-auto flex items-center gap-3">
            {[...LINE_METRICS, AUDIT_METRIC].map((m) => (
              <span key={m.key} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: m.color }} />
                {t(m.labelKey ?? '')}
              </span>
            ))}
          </div>
        </div>
        {points.length === 0 && !isFetching ? (
          <EmptyState />
        ) : (
          <MultiLineChart points={points} />
        )}
      </div>

      {/* 模型使用排行：哪个模型用得多 + 费用估算 */}
      <ModelRanking />

      {/* 排行榜：拦得最多的词 + 类型分布 */}
      <Leaderboards days={days} />
    </div>
  )
}

/**
 * 模型使用排行：按模型聚合请求数 / token / 估算费用。
 *
 * 数据源 /api/stats/models（daily_models 摘要表）。费用 = 内置价格表 + 用户自配
 *（设置-高级选项 model_prices），未收录模型显示「{t('stats.unpriced')}」，不占费用合计。
 */
function ModelRanking() {
  const { t, tf } = useI18n()
  const [range, setRange] = useState<'7' | '30'>('7')
  const { data } = useQuery({
    queryKey: ['statsModels', range],
    queryFn: () => getStatsModels(Number(range)),
    refetchInterval: 60000,
  })
  const { data: priceSync } = useQuery({
    queryKey: ['priceSync'],
    queryFn: getPriceSyncStatus,
    refetchInterval: 60000,
  })
  const models = data?.models ?? []
  const maxReq = Math.max(1, ...models.map((m) => m.requests))
  const totalCost = models.reduce((s, m) => s + (m.priced ? (m.cost_usd ?? 0) : 0), 0)
  const totalTokens = models.reduce((s, m) => s + (m.prompt ?? 0) + (m.completion ?? 0), 0)
  const totalReq = models.reduce((s, m) => s + m.requests, 0)
  const totalErr = models.reduce((s, m) => s + (m.errors ?? 0), 0)
  const totalAttempts = totalReq + totalErr
  const overallSuccessRate = totalAttempts > 0 ? Math.round((totalReq / totalAttempts) * 1000) / 10 : 100

  return (
    <div className="rounded-xl border bg-card p-5 shadow-[var(--shadow-card)]">
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Trophy className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-semibold">{t('stats.modelRanking')}</span>
        <span className="text-xs text-muted-foreground">{t('stats.modelHint')}</span>
        <div className="ml-auto flex items-center gap-1 rounded-lg bg-muted/60 p-0.5 text-xs">
          {([['7', 'stats.period7d'], ['30', 'stats.period30d']] as const).map(([k, lk]) => (
            <button
              key={k}
              type="button"
              onClick={() => setRange(k)}
              className={cn('rounded-md px-2.5 py-1 font-medium transition-colors', range === k ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')}
            >
              {t(lk)}
            </button>
          ))}
        </div>
      </div>

      {models.length === 0 ? (
        <div className="py-8 text-center text-sm text-muted-foreground">
          <Layers className="mx-auto mb-2 h-7 w-7 text-muted-foreground/40" />
          {t('stats.noModels')}
        </div>
      ) : (
        <>
          {/* 顶部合计 */}
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <span className="rounded-lg border bg-muted/30 px-2.5 py-1 text-xs text-muted-foreground">
              {tf('stats.modelSummary', { n: models.length, r: totalReq.toLocaleString() })}
              {t('stats.tokens')} {totalTokens.toLocaleString()}
            </span>
            <span
              className={cn(
                'rounded-lg border px-2.5 py-1 text-xs font-semibold',
                totalErr === 0
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                  : overallSuccessRate >= 95
                    ? 'border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-400'
                    : 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400',
              )}
              title={tf('stats.reqAndErr', { s: totalReq, e: totalErr })}
            >
              {t('stats.successRate')} {overallSuccessRate.toFixed(1)}%
              {totalErr > 0 && <span className="ml-1 text-[10px] font-normal opacity-80">({tf('stats.modelErrorsCount', { n: totalErr })})</span>}
            </span>
            <span className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs font-semibold text-emerald-600 dark:text-emerald-400">
              {t('stats.estCost')} ${Number(totalCost || 0).toFixed(2)}
            </span>
            <span className="text-[11px] text-muted-foreground">
              {t('stats.unpricedHint')}
              {priceSync && priceSync.synced_at > 0 && (
                <span className="ml-1">{tf('stats.priceSyncFrom', { date: dayjs(priceSync.synced_at * 1000).format('MM-DD') })}</span>
              )}
            </span>
          </div>

          <div className="space-y-2.5">
            {models.map((m, i) => {
              const toks = (m.prompt ?? 0) + (m.completion ?? 0)
              const pct = Math.max(2, Math.round((m.requests / maxReq) * 100))
              const req = m.requests
              const err = m.errors ?? 0
              const attempts = req + err
              const rate = attempts > 0 ? Math.round((req / attempts) * 1000) / 10 : 100

              return (
                <div key={m.model} className="flex items-center gap-3">
                  <span className="w-5 shrink-0 text-right font-mono text-xs text-muted-foreground">{i + 1}</span>
                  <div className="min-w-0 flex-1">
                    <div className="mb-1 flex items-center justify-between gap-2">
                      <div className="flex min-w-0 items-center gap-1.5 truncate">
                        <span className="truncate font-mono text-xs font-medium">{m.model}</span>
                        {err > 0 ? (
                          <span
                            className={cn(
                              'shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium leading-none',
                              rate >= 95
                                ? 'border border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400'
                                : 'border border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400',
                            )}
                            title={tf('stats.reqAndErr', { s: req, e: err })}
                          >
                            {rate.toFixed(1)}% ({err}{t('stats.failedShort')})
                          </span>
                        ) : attempts > 0 ? (
                          <span
                            className="shrink-0 rounded border border-emerald-500/20 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium leading-none text-emerald-600 dark:text-emerald-400"
                            title={tf('stats.allSuccess', { n: req })}
                          >
                            100%
                          </span>
                        ) : null}
                      </div>
                      <span className="shrink-0 text-[11px] text-muted-foreground">
                        {m.requests.toLocaleString()} {t('stats.timesSuffix')} · {(toks / 1000).toFixed(1)}k {t('stats.tokens')}
                        {m.priced
                          ? <b className="ml-1.5 text-emerald-600 dark:text-emerald-400">${(m.cost_usd ?? 0).toFixed(3)}</b>
                          : <span className="ml-1.5 text-muted-foreground/60">{t('stats.unpriced')}</span>}
                      </span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

/**
 * 敏感词排行榜 + 类型分布。
 *
 * 数据源是 /api/stats/today?range=Nd 的 top_words / by_label（后端已按天摘要聚合，
 * 不扫全量事件）。词是否为明文由高级设置的「敏感词统计记录明文」决定：
 * 关掉后这里显示的是打码形态，属预期，不做特殊提示以外的处理。
 */
function Leaderboards({ days }: { days: number }) {
  const { t } = useI18n()
  const range = days <= 1 ? '1d' : `${days}d`
  const { data } = useQuery({
    queryKey: ['statsLeaderboard', range],
    queryFn: () => getTodayStats(range),
    refetchInterval: 60000,
  })
  const [showPlain, setShowPlain] = useState(false)
  const [viewWord, setViewWord] = useState<RankRow | null>(null)

  const words = (data?.top_words ?? []).slice(0, 10)
  const labels = Object.entries(data?.by_label ?? {})
    .map(([label, count]) => ({ label, count: Number(count) || 0 }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)

  const wordMax = words[0]?.count ?? 0
  const labelMax = labels[0]?.count ?? 0

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <RankCard
        icon={Trophy}
        title={t('stats.wordRanking')}
        hint={`${t('stats.wordRankingHint')} · ${days}d`}
        rows={words.map((w) => ({
          key: `${w.label}:${w.word}`,
          name: w.word,
          tag: w.label,
          count: w.count,
          cred: CRED_LABELS.has(w.label),
        }))}
        max={wordMax}
        color="#10b981"
        showPlain={showPlain}
        onTogglePlain={() => setShowPlain((v) => !v)}
        onView={(r) => setViewWord(r)}
      />
      <RankCard
        icon={Tags}
        title={t('stats.labelDist')}
        hint={`${t('stats.labelDistHint')} · ${days}d`}
        rows={labels.map((l) => ({ key: l.label, name: l.label, count: l.count }))}
        max={labelMax}
        color="#8b5cf6"
      />
      {/* 词条详情弹窗：明文切换时超长词（key 串等）点开看全文 */}
      <Dialog open={viewWord !== null} onOpenChange={(v) => !v && setViewWord(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {t('stats.wordDetail')}
              {viewWord?.tag && <span className="rounded border px-1.5 py-0.5 text-[10px] text-muted-foreground">{viewWord.tag}</span>}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <div className="mb-1 text-xs font-semibold text-muted-foreground">{t('stats.original')}</div>
              <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-muted/60 p-3 font-mono text-xs leading-relaxed">
                {viewWord?.name}
              </pre>
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              {t('stats.count')}：<b className="font-mono tabular-nums text-foreground">{viewWord?.count?.toLocaleString()}</b>
              {viewWord?.cred && (
                <span className="flex items-center gap-1 rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-600 dark:text-amber-400"><LockKeyhole className="h-3 w-3" />{t('stats.credLocked')}</span>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button size="sm" variant="outline" onClick={() => setViewWord(null)}>{t('stats.close')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

interface RankRow {
  key: string
  name: string
  tag?: string
  count: number
  cred?: boolean
}

/** 排行榜卡片：名次 + 词 + 占比条 + 次数。前三名用金银铜色区分，一眼看到重点。 */
function RankCard({
  icon: Icon,
  title,
  hint,
  rows,
  max,
  color,
  showPlain = false,
  onTogglePlain,
  onView,
}: {
  icon: typeof Trophy
  title: string
  hint: string
  rows: RankRow[]
  max: number
  color: string
  showPlain?: boolean
  onTogglePlain?: () => void
  onView?: (r: RankRow) => void
}) {
  const { t } = useI18n()
  // 前三名配色：金/银/铜。第 4 名起统一用卡片主色，避免整列花掉。
  const medal = ['#f59e0b', '#94a3b8', '#b45309']
  return (
    <div className="flex flex-col rounded-xl border bg-card p-5 shadow-[var(--shadow-card)]">
      <div className="mb-4 flex h-7 items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
          <span className="shrink-0 text-sm font-semibold">{title}</span>
          <span className="truncate text-xs text-muted-foreground">{hint}</span>
        </div>
        {onTogglePlain && (
          <label className="flex shrink-0 cursor-pointer items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground">
            <Switch checked={showPlain} onCheckedChange={onTogglePlain} className="scale-75" />
            <span className="select-none">{t('stats.showPlain')}</span>
          </label>
        )}
      </div>
      {rows.length === 0 ? (
        <EmptyState />
      ) : (
        <ol className="space-y-2">
          {rows.map((r, i) => {
            // 只有敏感词才需要打码；如果不是敏感词（如规则标签/类型分布），直接显示原名！
            const masked = onTogglePlain ? (r.cred || !showPlain) : false
            const display = masked ? maskWord(r.name) : r.name
            return (
              <li key={r.key} className="flex h-9 items-center gap-2.5">
                <span
                  className="flex h-5 w-5 shrink-0 items-center justify-center rounded-md text-[11px] font-bold tabular-nums"
                  style={
                    i < 3
                      ? { background: `${medal[i]}22`, color: medal[i] }
                      : { background: 'hsl(var(--muted))', color: 'hsl(var(--muted-foreground))' }
                  }
                >
                  {i + 1}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-1.5">
                    {onView ? (
                      <button
                        type="button"
                        className="truncate font-mono text-[12px] hover:underline"
                        title={r.name}
                        onClick={() => onView(r)}
                      >
                        {display}
                      </button>
                    ) : (
                      <span className="truncate font-mono text-[12px] font-medium text-foreground" title={r.name}>
                        {display}
                      </span>
                    )}
                    {r.tag && (
                      <span className="shrink-0 rounded border px-1 text-[10px] text-muted-foreground">{r.tag}</span>
                    )}
                    {r.cred && <LockKeyhole className="h-3 w-3 shrink-0 text-muted-foreground" aria-label={t('stats.credHint')} />}
                  </span>
                  {/* 占比条：相对第一名，长度即相对量级，比纯数字更快看出梯度 */}
                  <span className="mt-1 block h-1.5 w-full overflow-hidden rounded-full bg-muted">
                    <span
                      className="block h-full rounded-full transition-[width] duration-500"
                      style={{ width: `${max > 0 ? Math.max(4, (r.count / max) * 100) : 0}%`, background: i < 3 ? medal[i] : color }}
                    />
                  </span>
                </span>
                <span className="shrink-0 font-mono text-[13px] font-semibold tabular-nums">{fmtNum(r.count, t)}</span>
              </li>
            )
          })}
        </ol>
      )}
    </div>
  )
}

/** 汇总数字卡片 */
function SummaryCard({ icon: Icon, label, value, color, bg }: { icon: typeof Layers; label: string; value: number | string; color: string; bg: string }) {
  return (
    <div className="flex flex-col rounded-xl border bg-card p-4 shadow-[var(--shadow-card)] transition-[transform,box-shadow] duration-200 hover:-translate-y-0.5 hover:shadow-[var(--shadow-card-hover)]">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-foreground/70">{label}</span>
        <div className={cn('flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br', bg)}>
          <Icon className="h-4 w-4" style={{ color }} />
        </div>
      </div>
      <div className="mt-3 text-2xl font-bold tabular-nums tracking-tight" style={{ color }}>
        {value.toLocaleString()}
      </div>
    </div>
  )
}

function EmptyState() {
  const { t } = useI18n()
  return (
    <div className="py-16 text-center text-sm text-muted-foreground">{t('common.noData')}</div>
  )
}

function getTokens(p: StatsHistoryPoint): number {
  return (p.tokens_prompt ?? 0) + (p.tokens_completion ?? 0)
}

/** 数值缩写（避免节点文字过长）：
 * 中文按万/亿进位（12345678 -> 1234.6万），英文按 k/M/B 进位（-> 12.3M）。
 * 进位体系由 stats.unitSystem 决定，t 从调用处传入（本函数是纯函数不挂 hook）。 */
function fmtNum(v: number, t: (k: string) => string): string {
  const trim = (x: number) => x.toFixed(1).replace(/\.0$/, '')
  if (t('stats.unitSystem') === 'cjk') {
    if (v >= 1e8) return trim(v / 1e8) + t('stats.numUnit')
    if (v >= 1e4) return trim(v / 1e4) + t('stats.tenThousandUnit')
    if (v >= 1000) return trim(v / 1e3) + 'k'
    return String(v)
  }
  if (v >= 1e9) return trim(v / 1e9) + 'B'
  if (v >= 1e6) return trim(v / 1e6) + 'M'
  if (v >= 1000) return trim(v / 1e3) + 'k'
  return String(v)
}

/** 折线图：脱敏/还原/告警/审计信号 多线叠加。
 * 设计（避免节点数值重叠）：
 *  - 悬停：垂直参考线高亮整列 + 聚合 tooltip 一次显示该点全部指标数值
 *  - 峰值：仅每个指标的最大值点标注数值（不重叠）
 *  - 数据点：小圆点常显，hover 放大
 */
function MultiLineChart({ points }: { points: StatsHistoryPoint[] }) {
  const { t } = useI18n()
  const [hover, setHover] = useState<number | null>(null)
  const W = 800
  const H = 280
  const padding = { top: 20, right: 16, bottom: 32, left: 52 }
  const cw = (W - padding.left - padding.right) / Math.max(1, points.length - 1)
  const ch = H - padding.top - padding.bottom
  const metrics = [...LINE_METRICS, AUDIT_METRIC]
  const maxVal = Math.max(1, ...points.flatMap((p) => metrics.map((m) => p[m.key] ?? 0)))
  const step = Math.max(1, Math.ceil(points.length / 10))
  // 每个指标的最大值索引（峰值标注）
  const peakIdx = new Map<string, number>()
  metrics.forEach((m) => {
    let maxI = 0
    let maxV = -1
    points.forEach((p, i) => {
      const v = p[m.key] ?? 0
      if (v > maxV) { maxV = v; maxI = i }
    })
    if (maxV > 0) peakIdx.set(m.key, maxI)
  })

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full"
        style={{ height: 'auto' }}
        onMouseLeave={() => setHover(null)}
      >
      {/* 网格 + Y 轴 */}
      {[0, 0.25, 0.5, 0.75, 1].map((r) => {
        const y = padding.top + ch * (1 - r)
        return (
          <g key={r}>
            <line x1={padding.left} y1={y} x2={W - padding.right} y2={y} stroke="hsl(var(--border))" strokeWidth={1} opacity={0.5} />
            <text x={padding.left - 6} y={y + 3} textAnchor="end" fontSize={10} fill="hsl(var(--muted-foreground))">
              {fmtNum(Math.round(maxVal * r), t)}
            </text>
          </g>
        )
      })}

      {/* 悬停垂直参考线 + 该列全部数据点高亮 */}
      {hover != null && (
        <g>
          <line
            x1={padding.left + hover * cw}
            y1={padding.top}
            x2={padding.left + hover * cw}
            y2={padding.top + ch}
            stroke="hsl(var(--foreground))"
            strokeWidth={1}
            strokeDasharray="4 3"
            opacity={0.35}
          />
          {metrics.map((m) => {
            const v = points[hover]
            const vv = v[m.key] ?? 0
            const x = padding.left + hover * cw
            const y = padding.top + ch - (vv / maxVal) * ch
            return (
              <circle key={m.key} cx={x} cy={y} r={6} fill={m.color} stroke="hsl(var(--card))" strokeWidth={2} />
            )
          })}
        </g>
      )}

      {/* 每条线：渐变填充 + 折线 + 数据点 + 峰值标注 */}
      {metrics.map((m) => {
        const linePath = points.map((p, i) => {
          const v = p[m.key] ?? 0
          const x = padding.left + i * cw
          const y = padding.top + ch - (v / maxVal) * ch
          return `${i === 0 ? 'M' : 'L'}${x},${y}`
        }).join(' ')
        const areaPath = `${linePath} L${padding.left + (points.length - 1) * cw},${padding.top + ch} L${padding.left},${padding.top + ch} Z`
        const gid = `area-${m.key}`
        const peakI = peakIdx.get(m.key)
        return (
          <g key={m.key}>
            <defs>
              <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={m.color} stopOpacity="0.22" />
                <stop offset="100%" stopColor={m.color} stopOpacity="0.02" />
              </linearGradient>
            </defs>
            {points.length > 1 && <path d={areaPath} fill={`url(#${gid})`} />}
            <path d={linePath} fill="none" stroke={m.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
            {/* 数据点（常显小圆点；0 值也画淡点，避免节点缺失观感） */}
            {points.map((p, i) => {
              const v = p[m.key] ?? 0
              const x = padding.left + i * cw
              const y = padding.top + ch - (v / maxVal) * ch
              return v > 0
                ? <circle key={i} cx={x} cy={y} r={3} fill={m.color} opacity={0.85} />
                : <circle key={i} cx={x} cy={y} r={1.5} fill={m.color} opacity={0.25} />
            })}
            {/* 峰值高亮：仅 hover 该列时圈出（数值不再标注，hover tooltip 已含全部指标） */}
            {peakI != null && points.length > 2 && hover === peakI && (
              <circle cx={padding.left + peakI * cw} cy={padding.top + ch - ((points[peakI][m.key] ?? 0) / maxVal) * ch} r={4.5} fill={m.color} stroke="hsl(var(--card))" strokeWidth={2} />
            )}
          </g>
        )
      })}

      {/* 悬停捕获区（透明条，按列命中） */}
      {points.map((_p, i) => (
        <rect
          key={i}
          x={padding.left + i * cw - cw / 2}
          y={padding.top}
          width={cw}
          height={ch}
          fill="transparent"
          onMouseEnter={() => setHover(i)}
        />
      ))}

      {/* 全 0 空数据状态柔和提示 */}
      {points.length > 0 && points.every((p) => metrics.every((m) => (p[m.key] ?? 0) === 0)) && (
        <text
          x={W / 2}
          y={padding.top + ch / 2}
          textAnchor="middle"
          fontSize={12}
          fill="hsl(var(--muted-foreground))"
          opacity={0.6}
        >
          {t('stats.chartAllZero')}
        </text>
      )}

      {/* X 轴标签 */}
      {points.map((p, i) => {
        if (i % step !== 0) return null
        const x = padding.left + i * cw
        return (
          <text key={i} x={x} y={H - padding.bottom + 16} textAnchor="middle" fontSize={9} fill="hsl(var(--muted-foreground))">
            {p.label}
          </text>
        )
      })}
      </svg>
      {hover != null && points[hover] && (
        <ChartTooltip point={points[hover]} xPct={((padding.left + hover * cw) / W) * 100} />
      )}
    </div>
  )
}

/** 聚合 tooltip：悬停时显示该时间点全部指标数值（避免多线各自标注重叠） */
function ChartTooltip({ point, xPct }: { point: StatsHistoryPoint; xPct: number }) {
  const { t } = useI18n()
  const metrics = [...LINE_METRICS, AUDIT_METRIC]
  return (
    <div
      className="pointer-events-none absolute z-10 -translate-x-1/2 rounded-lg border bg-popover px-3 py-2 text-xs shadow-lg"
      style={{ left: `${Math.min(88, Math.max(12, xPct))}%`, top: 4 }}
    >
      <div className="mb-1.5 font-semibold text-foreground">{point.label}</div>
      <div className="space-y-1">
        {metrics.map((m) => {
          const v = point[m.key] ?? 0
          if (v <= 0) return null
          return (
            <div key={m.key} className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full" style={{ background: m.color }} />
              <span className="text-muted-foreground">{t(m.labelKey ?? '')}</span>
              <span className="ml-auto pl-3 font-mono tabular-nums text-foreground">{v.toLocaleString()}</span>
            </div>
          )
        })}
        {(point.tokens_prompt ?? 0) > 0 && (
          <div className="flex items-center gap-2 border-t pt-1">
            <span className="h-2 w-2 rounded-full" style={{ background: TOKEN_COLOR }} />
            <span className="text-muted-foreground">{t('stats.tokens')}</span>
            <span className="ml-auto pl-3 font-mono tabular-nums text-foreground">{((point.tokens_prompt ?? 0) + (point.tokens_completion ?? 0)).toLocaleString()}</span>
          </div>
        )}
        {(point.audit_high ?? 0) > 0 && (
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-red-600" />
            <span className="text-red-600 dark:text-red-400">{t('stats.highRisk')}</span>
            <span className="ml-auto pl-3 font-mono tabular-nums text-red-600 dark:text-red-400">{(point.audit_high ?? 0).toLocaleString()}</span>
          </div>
        )}
      </div>
    </div>
  )
}

/** Token 柱状图：柱顶数值平时不显示（避免密集重叠），hover 才显示。 */
function TokenBarChart({ points }: { points: StatsHistoryPoint[] }) {
  const { t } = useI18n()
  const [hover, setHover] = useState<number | null>(null)
  const W = 800
  const H = 260
  const padding = { top: 16, right: 16, bottom: 32, left: 52 }
  const cw = (W - padding.left - padding.right) / Math.max(1, points.length)
  const ch = H - padding.top - padding.bottom
  const maxVal = Math.max(1, ...points.map(getTokens))
  const step = Math.max(1, Math.ceil(points.length / 10))

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: 'auto' }} onMouseLeave={() => setHover(null)}>
      {/* 网格 + Y 轴（缩写） */}
      {[0, 0.25, 0.5, 0.75, 1].map((r) => {
        const y = padding.top + ch * (1 - r)
        return (
          <g key={r}>
            <line x1={padding.left} y1={y} x2={W - padding.right} y2={y} stroke="hsl(var(--border))" strokeWidth={1} opacity={0.5} />
            <text x={padding.left - 6} y={y + 3} textAnchor="end" fontSize={10} fill="hsl(var(--muted-foreground))">
              {fmtNum(Math.round(maxVal * r), t)}
            </text>
          </g>
        )
      })}

      {/* 柱子（柱顶数值仅 hover 时显示，防密集重叠） */}
      {points.map((p, i) => {
        const v = getTokens(p)
        const h = (v / maxVal) * ch
        const x = padding.left + i * cw + cw * 0.18
        const w = cw * 0.64
        const y = padding.top + ch - h
        const isHover = hover === i
        return (
          <g key={i} className="cursor-pointer" onMouseEnter={() => setHover(i)}>
            <title>{`${p.label}\nToken: ${v.toLocaleString()}\n${t('stats.inputLabel')}: ${(p.tokens_prompt ?? 0).toLocaleString()} / ${t('stats.outputLabel')}: ${(p.tokens_completion ?? 0).toLocaleString()}`}</title>
            {/* hover 命中区（透明，覆盖柱子上方区域便于 hover） */}
            <rect x={x} y={padding.top} width={w} height={ch} fill="transparent" className="opacity-0" />
            <rect
              x={x}
              y={y}
              width={w}
              height={Math.max(0, h)}
              fill={TOKEN_COLOR}
              rx={2}
              opacity={v > 0 ? (isHover ? 1 : 0.85) : 0.25}
              className="transition-opacity"
            />
            {/* 柱顶数值：仅 hover 时显示 */}
            {isHover && v > 0 && (
              <text x={x + w / 2} y={y - 5} textAnchor="middle" fontSize={10} fontWeight={700} fill={TOKEN_COLOR}>
                {fmtNum(v, t)}
              </text>
            )}
            {i % step === 0 && (
              <text x={x + w / 2} y={H - padding.bottom + 16} textAnchor="middle" fontSize={9} fill="hsl(var(--muted-foreground))">
                {p.label}
              </text>
            )}
          </g>
        )
      })}
      {/* 全 0 空数据状态柔和提示 */}
      {points.length > 0 && points.every((p) => getTokens(p) === 0) && (
        <text
          x={W / 2}
          y={padding.top + ch / 2}
          textAnchor="middle"
          fontSize={12}
          fill="hsl(var(--muted-foreground))"
          opacity={0.6}
        >
          {t('stats.chartAllZero')}
        </text>
      )}
    </svg>
  )
}
