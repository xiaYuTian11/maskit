/**
 * 拦截审计日志页（对标旧版「拦截审计日志」）：
 * - 列表放进 query cache（组件只读 data，游标从 data 派生，不再用组件 state + ref）
 * - 游标增量轮询（3s，since=最新 seq append，去重）
 * - 筛选：类型 / 隐藏透传(sensitive) / 搜索(防抖) / 全文搜索(fulltext 性能提示)
 * - 虚拟滚动表格（@tanstack/react-virtual，长会话不卡）
 * - 详情回源弹窗（slim 列表无明文）；导出恒脱敏；清空需确认
 *
 * 设计要点（修「切菜单回来 4-5 秒空白 / 筛选乱 / 空列表」根因）：
 * 1) queryFn 从 queryClient.getQueryData 读上次的累积列表 → 合并新数据 → return 完整列表。
 *    TanStack 缓存的是「完整累积列表」，卸载重挂载立刻拿到缓存，0 空窗。
 * 2) 游标(lastSeq)从缓存数据派生，不进 queryKey 也不放 ref——避免 queryKey 变化触发重发 + 竞态。
 * 3) queryKey 含 sensitive/q/fulltext/filterType，切筛选天然换 key 换缓存，旧筛选数据各自隔离。
 * 4) staleTime: 0 + refetchOnMount: 'always'（本页不走全局 30s 缓存，挂载即发）。
 * 5) placeholderData: keepPreviousData（切筛选时保留上一份直到新数据到，不闪空）。
 * 6) 删掉所有 setEvents([]) 副作用 effect（数据跟着 queryKey 走，不再手动清空）。
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Download, Trash2, RefreshCw, Search, HelpCircle, Loader2, X } from 'lucide-react'
import { getLogs, exportLogs, clearLogs } from '@/api/logs'
import { getAuditEvents } from '@/api/audit'
import { EventTypeIcon, EVENT_TYPE_META } from '@/components/events/EventTypeIcon'
import { EventDetailDialog } from '@/components/events/EventDetailDialog'
import { AuditEventDetailDialog, severityMeta, signalInfo } from '@/components/audit/AuditEventDetailDialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  SelectGroup,
  SelectLabel,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { toast } from '@/lib/toast'
import { isTauri } from '@/lib/shield-fetch'
import type { ShieldEvent, AuditEvent, AuditSeverity } from '@/types/api'
import dayjs from 'dayjs'
import { cn } from '@/lib/utils'
import { useI18n } from '@/lib/i18n'
import { mergeMaskRestore, FILTER_ALL, type MergedEvent } from '@/lib/log-events'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { useVisibility } from '@/lib/useVisibility'

/** 审计信号行合并进主列表（AGENTS.md：auditRows 前端合并，不改 events 表） */
// 稳定空数组引用：避免 data 为 undefined 时每 render 创建新空数组导致 useMemo 失效
const EMPTY_LIST: readonly never[] = []

interface AuditRow {
  id: number
  ts: number
  type: 'SCAN_WARN'
  sid: string
  method: string
  path: string
  host: string
  items: { label: string; preview: string }[]
  msg?: string
  status?: string
  http_status?: number
  total_ms?: number
  upstream_ms?: number
  seq: number
  count?: number
  restored?: number
  /** 查不到原文、原样透传出去的占位符数。>0 通常意味着模型自造了占位符 */
  unresolved?: number
  /** 靠宽松兜底（模型剥了花括号）修回来的占位符数。成功路径，但值得看见 */
  degraded?: number
  stream_actual?: string
  model?: string
  client_app?: string | number
  upstream?: string
  /** 审计信号严重度（列表行摘要徽标 + 详情弹窗） */
  severity?: AuditSeverity
  probe_id?: string
  /** 原始审计事件：日志行点击后原地打开审计详情弹窗 */
  _auditEvent?: AuditEvent
  /** 与合并后的事件行对齐：审计行没有回源 seq，但联合类型要能统一访问 */
  _detailSeq?: number
}

/** query cache 存的形状：累积列表 + 最新游标 + tail */
interface LogsCache {
  list: ShieldEvent[]
  tail: string[]
}

type LogRow = (AuditRow & { _audit: true }) | MergedEvent

export default function LogsPage() {
  const { t, tf } = useI18n()
  const queryClient = useQueryClient()
  // 页面隐藏时停止轮询；可见时自动刷新
  const { hidden } = useVisibility()
  // 空串是 Radix Select 的保留值（它把 value === '' 当成「未选择，显示 placeholder」），
  // 用它当「全部」这个真实选项会跟组件语义打架：官方文档明确要求 SelectItem 的 value
  // 不能是空串。用哨兵值把「全部」和「未选择」区分开，符合 Radix Select 约束。
  const [filterType, setFilterType] = useState<string>(FILTER_ALL)
  const [sensitive, setSensitive] = useState(false)
  const [q, setQ] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [fulltext, setFulltext] = useState(false)
  const [detailSeq, setDetailSeq] = useState<number | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)
  // 审计行详情：原地弹窗（不再跳转审计中心）
  const [auditDetail, setAuditDetail] = useState<AuditEvent | null>(null)
  const [confirmClear, setConfirmClear] = useState(false)
  const [tailOpen, setTailOpen] = useState(false)
  const [tailData, setTailData] = useState<string[]>([])
  const [hideNoise, setHideNoise] = useState(false)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const scrollRef = useRef<HTMLDivElement>(null)

  // 保留天数配置已移至高级设置页（Logs 筛选栏只留筛选控件）

  // 搜索防抖 250ms：只更新 q（驱动 queryKey），不再手动清空列表
  useEffect(() => {
    const t = setTimeout(() => setQ(searchInput.trim()), 250)
    return () => clearTimeout(t)
  }, [searchInput])

  // —— 事件查询：累积列表放进 query cache，游标从缓存数据派生 ——
  const logsKey = useMemo(
    () => ['logs', { filterType, sensitive, q, fulltext }] as const,
    [filterType, sensitive, q, fulltext],
  )
  const logsQuery = useQuery<LogsCache>({
    queryKey: logsKey,
    queryFn: async ({ queryKey }) => {
      // 从缓存读上次的累积列表 + 游标（首次为空）
      const prev = queryClient.getQueryData<LogsCache>(queryKey)
      const prevList = prev?.list ?? []
      const since = prevList.length > 0 ? prevList[prevList.length - 1].seq : 0
      const resp = await getLogs({
        since,
        limit: 200,
        type: filterType === FILTER_ALL ? undefined : filterType,
        sensitive,
        q,
        fulltext,
        slim: true,
      })
      if (resp.tail?.length) setTailData(resp.tail)
      // 增量 append 去重（按 seq）
      const seen = new Set(prevList.map((e) => e.seq))
      const added = (resp.events as ShieldEvent[]).filter((e) => !seen.has(e.seq))
      const list = added.length > 0 ? [...prevList, ...added] : prevList
      return { list, tail: resp.tail ?? prev?.tail ?? [] }
    },
    // 本页单独配置：不走全局 30s 缓存，挂载即发
    staleTime: 0,
    refetchOnMount: 'always',
    refetchInterval: hidden ? false : 3000,
    refetchIntervalInBackground: false,
  })

  const events = logsQuery.data?.list ?? EMPTY_LIST
  const isFetching = logsQuery.isFetching

  // 导出 / 清空进行中（长耗时操作，需要即时反馈）
  const [exporting, setExporting] = useState(false)
  const [clearing, setClearing] = useState(false)

  // 审计信号合并（POISON 过滤项 = SCAN_WARN + 审计信号）
  // queryKey 与审计页分开：两处 queryFn 不同，共用 key 会被 TanStack 按 key 去重
  const auditQuery = useQuery({
    queryKey: ['auditEvents', 'logsMerge'],
    queryFn: async () => {
      const resp = await getAuditEvents()
      const mapped: AuditRow[] = (resp?.events ?? []).map((r) => ({
        id: r.seq,
        ts: r.ts,
        type: 'SCAN_WARN' as const,
        sid: r.probe_id ?? r.sid ?? 'audit',
        method: r.method ?? 'AUDIT',
        path: r.path ?? '',
        host: r.host ?? '',
        items: [{ label: r.signal_type ?? t('logs.signalLabel'), preview: r.evidence ?? r.severity ?? '' }],
        msg: r.evidence,
        severity: r.severity,
        probe_id: r.probe_id,
        seq: r.seq,
        _auditEvent: r,
      }))
      return mapped
    },
    staleTime: 0,
    refetchOnMount: 'always',
    refetchInterval: hidden ? false : 3000,
    refetchIntervalInBackground: false,
  })
  const auditRows = auditQuery.data ?? EMPTY_LIST

  // 合并展示：审计信号 + 事件按 sid 合并 MASK/RESTORE 成一条「往返链路」行，按 ts 降序
  // （用户明确要求：一次请求对应一条日志；CANCEL/DNS_ERROR/ERR 等非链路事件保持独立行）
  const merged = useMemo(() => {
    const noiseTypes = new Set(['SKIP', 'PASS', 'BYPASS', 'CANCEL', 'DNS_ERROR'])
    const audit: (AuditRow & { _audit: true })[] = auditRows
      .filter((row) => filterType === FILTER_ALL || row.type === filterType)
      .filter((row) => !hideNoise || !noiseTypes.has(row.type))
      .map((row) => ({ ...row, _audit: true as const }))
    // 普通事件：MASK/RESTORE 合并与排序交给共享函数（与 Dashboard 最近日志同口径）
    const ev = mergeMaskRestore(events, { filterType, hideNoise })
    // 按 ts 降序合并审计行与事件行
    return [...audit, ...ev].sort((a, b) => (b.ts ?? 0) - (a.ts ?? 0)) as LogRow[]
  }, [auditRows, events, filterType, hideNoise])

  // 分页切片（真实分页：对 merged 切片）
  const paged = useMemo(() => {
    const start = (page - 1) * pageSize
    return merged.slice(start, start + pageSize)
  }, [merged, page, pageSize])

  // 虚拟滚动（基于分页后的数据）
  const virtualizer = useVirtualizer({
    count: paged.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 48,
    overscan: 8,
  })

  const refresh = useCallback(() => {
    // 清缓存让下次拉全量（since=0）
    queryClient.setQueryData<LogsCache>(logsKey, { list: [], tail: [] })
    queryClient.invalidateQueries({ queryKey: ['logs'] })
  }, [queryClient, logsKey])

  const doExport = async () => {
    if (exporting) return
    setExporting(true)
    try {
      const resp = await exportLogs({
        type: filterType === FILTER_ALL ? undefined : filterType,
        sensitive,
        q,
        fulltext,
      })
      const blob = await resp.blob()
      const filename = `maskit-events-${dayjs().format('YYYY-MM-DD-HHmmss')}.json`
      if (isTauri()) {
        const { save } = await import('@tauri-apps/plugin-dialog')
        const { writeFile } = await import('@tauri-apps/plugin-fs')
        const buf = new Uint8Array(await blob.arrayBuffer())
        const path = await save({ defaultPath: filename, filters: [{ name: 'JSON', extensions: ['json'] }] })
        if (path) {
          await writeFile(path, buf)
          toast(t('logs.exported'))
        }
      } else {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
        toast(t('logs.exported'))
      }
    } catch (e) {
      toast(tf('logs.exportFail', { e: String(e) }), 'error')
    } finally {
      setExporting(false)
    }
  }

  const doClear = async () => {
    if (clearing) return
    setClearing(true)
    try {
      await clearLogs()
      toast(t('logs.cleared'))
      setConfirmClear(false)
      refresh()
    } catch (e) {
      toast(tf('logs.clearFail', { e: String(e) }), 'error')
    } finally {
      setClearing(false)
    }
  }

  const openDetail = (row: (typeof merged)[number]) => {
    // 审计行：原地打开审计详情弹窗（信号说明/危害/证据/探针 ID）
    if (row._audit) {
      setAuditDetail((row as AuditRow)._auditEvent ?? null)
      return
    }
    // 合并行优先回源 RESTORE 事件（详情弹窗同时含用户消息与助手回复，完整链路）
    setDetailSeq((row as { _detailSeq?: number })._detailSeq ?? row.seq)
    setDetailOpen(true)
  }

  // 耗时格式统一：<1s 毫秒；<60s 秒(1 位小数)；≥60s 分:秒（用户要求：时间长用分秒代替，不全是毫秒）
  const fmtMs = (ms?: number) => {
    if (ms == null) return '—'
    if (ms < 1000) return `${Math.round(ms)}ms`
    const s = ms / 1000
    if (s < 60) return `${s.toFixed(1)}s`
    const m = Math.floor(s / 60)
    return `${m}m${Math.round(s % 60)}s`
  }

  // 处理摘要列：事件行显示「脱敏 N / 还原 N」（无命中时回退路径/状态），审计行显示信号名 + 严重度
  const renderSummary = (row: (typeof merged)[number]) => {
    if (row._audit) {
      const ev = (row as AuditRow)._auditEvent
      const sig = ev?.signal_type ?? (row as AuditRow).path ?? ''
      const info = signalInfo(sig)
      const sev = (row as AuditRow).severity
      return (
        <span className="flex min-w-0 items-center gap-1.5" title={ev?.evidence ?? (row as AuditRow).msg ?? ''}>
          <span className="truncate text-[11px] font-medium text-amber-600 dark:text-amber-400">
            {t(info.labelKey ?? info.label ?? sig)}
          </span>
          {sev && (
            <Badge variant="outline" className={cn('shrink-0 rounded-full px-1 py-0 text-[9px]', severityMeta(sev).cls)}>
              {t(severityMeta(sev).labelKey)}
            </Badge>
          )}
        </span>
      )
    }
    // 普通事件：优先展示脱敏/还原计数（一次请求一条链路行的核心信息）
    const masked = (row.count ?? 0) > 0
    const restored = (row.restored ?? 0) > 0
    // 未还原的占位符：绝大多数情况是模型自己编了一个我们从没发出去过的占位符
    // （它把 {{IPPRIVATE_83fc6a}} 的后缀当成可计算的数字改写），少数是映射过期。
    // 不显示出来的话，用户只在终端里看到裸露的 {{...}} 而无从判断是谁的问题——
    // 0.1.12 就是因此误判成「还原坏了」，进而加了一段凭空推算 IP 的代码。
    const unresolved = (row.unresolved ?? 0) > 0
    // 兜底还原：模型把花括号剥了，靠宽松正则捞回来的。是成功，所以用中性色不报警，
    // 但要看得见——它是「模型正在改写输出格式」的前兆信号。
    const degraded = (row.degraded ?? 0) > 0
    if (masked || restored || unresolved || degraded) {
      return (
        <span
          className="flex min-w-0 items-center gap-1.5 text-[11px]"
          title={[row.method, row.host, row.path].filter(Boolean).join(' ')}
        >
          {masked && <span className="text-blue-600 dark:text-blue-400">{t('logs.colMasked')} {row.count}</span>}
          {restored && <span className="text-emerald-600 dark:text-emerald-400">{t('logs.colRestored')} {row.restored}</span>}
          {unresolved && (
            <span className="text-amber-600 dark:text-amber-400" title={t('logs.unresolvedHint')}>
              {t('logs.colUnresolved')} {row.unresolved}
            </span>
          )}
          {degraded && (
            <span className="text-muted-foreground" title={t('logs.degradedHint')}>
              {t('logs.colDegraded')} {row.degraded}
            </span>
          )}
        </span>
      )
    }
    // 无命中的行（PASS/BYPASS/SKIP/ERR…）：展示「—」
    const pathText = [row.method, row.host, row.path].filter(Boolean).join(' ')
    return (
      <span className="text-[11px] text-muted-foreground/50" title={pathText || row.status || ''}>
        —
      </span>
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col space-y-4">
      {/* 页头 */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t('logs.pageTitle')}</h1>
          <p className="mt-1 text-sm font-medium text-muted-foreground">
            {t('logs.subtitle')}
          </p>
        </div>
      </div>

      {/* 筛选栏 */}
      <div className="flex flex-wrap items-center gap-2">
        <Select value={filterType} onValueChange={(v) => { setFilterType(v); setPage(1) }}>
          <SelectTrigger className="h-8 w-[140px] text-xs">
            <SelectValue placeholder={t('logs.filterAll')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={FILTER_ALL}>{t('logs.filterAll')}</SelectItem>
            <SelectGroup>
              <SelectLabel>{t('logs.filterHandled')}</SelectLabel>
              <SelectItem value="MASK">{t('logs.filterMasked')}</SelectItem>
              <SelectItem value="RESTORE">{t('logs.filterRestored')}</SelectItem>
            </SelectGroup>
            <SelectGroup>
              <SelectLabel>{t('logs.filterNotMasked')}</SelectLabel>
              <SelectItem value="PASS">{t('logs.filterPass')}</SelectItem>
              <SelectItem value="BYPASS">{t('logs.filterBypass')}</SelectItem>
            </SelectGroup>
            <SelectGroup>
              <SelectLabel>{t('logs.filterMissed')}</SelectLabel>
              <SelectItem value="SKIP">{t('logs.filterSkip')}</SelectItem>
            </SelectGroup>
            <SelectGroup>
              <SelectLabel>{t('logs.filterErrors')}</SelectLabel>
              <SelectItem value="BLOCK">{t('logs.filterBlocked')}</SelectItem>
              <SelectItem value="ERR">{t('logs.filterErr')}</SelectItem>
              <SelectItem value="SCAN_WARN">{t('logs.filterScanWarn')}</SelectItem>
            </SelectGroup>
            <SelectGroup>
              <SelectLabel>{t('logs.filterNonFault')}</SelectLabel>
              <SelectItem value="CANCEL">{t('logs.filterCancel')}</SelectItem>
              <SelectItem value="DNS_ERROR">{t('logs.filterDns')}</SelectItem>
            </SelectGroup>
          </SelectContent>
        </Select>

        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder={t('logs.searchHost')}
            className="h-8 w-56 pl-8 pr-7 text-xs"
          />
          {searchInput && (
            <button
              type="button"
              onClick={() => setSearchInput('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground/60 hover:text-foreground"
              title={t('common.reset')}
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground">
          <Switch checked={fulltext} onCheckedChange={(v) => { setFulltext(v); setPage(1) }} className="scale-75" />
          <span>{t('logs.fulltext')}</span>
        </label>
        <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground">
          <Switch checked={sensitive} onCheckedChange={(v) => { setSensitive(v); setPage(1) }} className="scale-75" />
          <span>{t('logs.sensitiveOnly')}</span>
        </label>
        <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground" title={t('logs.hideNoiseTitle')}>
          <Switch checked={hideNoise} onCheckedChange={setHideNoise} className="scale-75" />
          <span>{t('logs.hideNoise')}</span>
        </label>

        <div className="ml-auto flex items-center gap-1.5">
          <Button size="sm" variant="ghost" className="h-8 px-2.5" onClick={refresh} title={t('logs.refresh')}>
            <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} />
          </Button>
          <Button size="sm" variant="outline" className="h-8 px-2.5 text-xs" onClick={doExport} loading={exporting}>
            {!exporting && <Download className="mr-1 h-3.5 w-3.5" />} {t('logs.export')}
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="h-8 px-2.5 text-xs text-red-600 hover:text-red-600 dark:text-red-400"
            onClick={() => setConfirmClear(true)}
            disabled={clearing}
          >
            {!clearing && <Trash2 className="mr-1 h-3.5 w-3.5" />} {t('common.clear')}
          </Button>
        </div>
      </div>

      {/* 状态颜色说明：问号 Tooltip（与全局统一，hover 查看） */}
      <div className="flex items-center gap-1.5 px-1">
        <TooltipProvider delayDuration={200}>
          <Tooltip>
            <TooltipTrigger asChild>
              <HelpCircle className="h-3.5 w-3.5 cursor-help text-muted-foreground/60" />
            </TooltipTrigger>
            <TooltipContent side="right" className="max-w-[320px] space-y-1">
              <div className="font-semibold">{t('logs.legendTitle')}</div>
              <div className="flex items-center gap-1.5"><Badge className="bg-blue-500/10 text-blue-600 hover:bg-blue-500/10 dark:text-blue-400">{t('logs.filterMasked')}</Badge>{t('logs.legendMasked')}</div>
              <div className="flex items-center gap-1.5"><Badge className="bg-emerald-500/10 text-emerald-600 hover:bg-emerald-500/10 dark:text-emerald-400">{t('logs.filterRestored')}</Badge>{t('logs.legendRestored')}</div>
              <div className="flex items-center gap-1.5"><Badge variant="outline">{t('logs.filterPass')}</Badge>{t('logs.legendPass')}</div>
              <div className="flex items-center gap-1.5"><Badge variant="outline">{t('logs.filterMissed')}</Badge>{t('logs.legendSkip')}</div>
              <div className="flex items-center gap-1.5"><Badge className="bg-amber-500/10 text-amber-600 hover:bg-amber-500/10 dark:text-amber-400">{t('logs.filterScanWarn')}</Badge>{t('logs.legendScanWarn')}</div>
              <div className="flex items-center gap-1.5"><Badge className="bg-red-500/10 text-red-600 hover:bg-red-500/10 dark:text-red-400">{t('logs.filterBlocked')}</Badge>{t('logs.legendBlock')}</div>
              <div className="flex items-center gap-1.5"><Badge className="bg-amber-500/15 text-amber-600 hover:bg-amber-500/15 dark:text-amber-400">{t('logs.poisonBadge')}</Badge>{t('logs.legendPoison')}</div>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>

      {/* 表格（虚拟滚动） */}
      <div
        ref={scrollRef}
        className="min-h-0 flex-1 overflow-auto rounded-xl border bg-card shadow-[var(--shadow-card)]"
      >
        {/* 表头（固定）：时间(两行 日期+时间) / 结果 / 上游 / 模型(宽列) / 处理摘要(脱敏/还原) / 状态 / 耗时 / 费用 */}
        <div className="sticky top-0 z-10 grid grid-cols-[68px_92px_88px_minmax(180px,2fr)_minmax(130px,1fr)_54px_58px_64px] gap-2 border-b bg-card px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          <span>{t('logs.colTime')}</span>
          <span>{t('logs.colResult')}</span>
          <span>{t('logs.colUpstream')}</span>
          <span>{t('logs.colModel')}</span>
          <span>{t('logs.colSummary')}</span>
          <span className="text-center">{t('logs.colStatus')}</span>
          <span className="text-right">{t('logs.colDuration')}</span>
          <span className="text-right">{t('logs.colCost')}</span>
        </div>

        <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
          {virtualizer.getVirtualItems().map((vi) => {
            const row = paged[vi.index]
            if (!row) return null
            return (
              <div
                key={`${row._audit ? 'a' : 'e'}-${row.seq}-${vi.index}`}
                className={cn(
                  'absolute left-0 top-0 grid w-full grid-cols-[68px_92px_88px_minmax(180px,2fr)_minmax(130px,1fr)_54px_58px_64px] items-center gap-2 border-b px-3 text-[12px]',
                  'transition-colors hover:bg-muted/40',
                  row._audit && 'bg-amber-500/5 hover:bg-amber-500/10',
                )}
                style={{ height: vi.size, transform: `translateY(${vi.start}px)` }}
                onClick={() => openDetail(row)}
              >
                {/* 时间：上日期下时间（用户要求，一行放不下就两行） */}
                <span className="flex flex-col leading-tight tabular-nums text-[11px] text-muted-foreground">
                  <span>{row.ts ? dayjs(row.ts * 1000).format('MM-DD') : '—'}</span>
                  <span className="opacity-70">{row.ts ? dayjs(row.ts * 1000).format('HH:mm:ss') : ''}</span>
                </span>
                {/* 结果 */}
                <span className="flex items-center gap-1">
                  <EventTypeIcon type={row.type} className="h-3.5 w-3.5 shrink-0" />
                  <span className="text-[11px] font-medium">{t(EVENT_TYPE_META[row.type]?.labelKey ?? row.type)}</span>
                </span>
                {/* 上游：优先配置名 upstream，client_app（进程探测）仅作缺失回退 */}
                <span className="truncate text-[11px] text-muted-foreground" title={String(row.upstream || row.client_app || '')}>
                  {String(row.upstream || row.client_app || '—')}
                </span>
                {/* 模型：模型名 + 流式标签，完整 host/path 放 title（悬停可见） */}
                <span
                  className="flex min-w-0 items-center gap-1.5"
                  title={`${row.host ?? ''}${row.path ?? ''}${row.model ? `\n${tf('logs.modelIn', { m: row.model })}` : ''}${(row as { _detailSeq?: number })._detailSeq ? `\n${tf('logs.restoredN', { n: row.restored ?? 0 })}` : ''}`}
                >
                  <code className="truncate font-mono text-[11px]">
                    {row.model || (row.upstream ? '—' : row.host) || '—'}
                  </code>
                  {row.stream_actual && (
                    <span className="shrink-0 rounded bg-muted/60 px-1 py-0.5 font-mono text-[9px] text-muted-foreground">
                      {row.stream_actual === 'stream' ? t('logs.streaming') : t('logs.whole')}
                    </span>
                  )}
                </span>
                {/* 处理摘要：脱敏/还原计数，审计行为信号名 + 严重度，无命中的行回退路径 */}
                {renderSummary(row)}
                {/* 状态：http_status 数字或 status 中文语义 */}
                <span className="text-center">
                  {row.http_status ? (
                    <Badge
                      variant="outline"
                      className={cn(
                        'px-1 py-0 text-[9px] font-mono',
                        row.http_status >= 400
                          ? 'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400'
                          : row.http_status >= 200 && row.http_status < 300
                            ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                            : 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400',
                      )}
                    >
                      {row.http_status}
                    </Badge>
                  ) : row.status ? (
                    <span className="truncate text-[9px] text-muted-foreground" title={String(row.status)}>
                      {row.status === 'no_placeholder_in_response' ? t('logs.statusNoRestore') : row.status === 'no_sensitive_data' ? t('logs.statusNoSensitive') : String(row.status).slice(0, 6)}
                    </span>
                  ) : '—'}
                </span>
                {/* 耗时：合并行取整链路(RESTORE)，MASK 单行(未还原/阻断)取脱敏管线耗时 */}
                <span className="text-right tabular-nums text-[11px] text-muted-foreground">
                  {fmtMs(row.total_ms ?? row.upstream_ms ?? (row as { mask_ms?: number }).mask_ms)}
                </span>
                {/* 费用（RESTORE 事件由后端按模型×usage 估算） */}
                <span className="text-right tabular-nums text-[11px]">
                  {(row as { cost_usd?: number }).cost_usd != null && (row as { cost_usd?: number }).cost_usd! > 0
                    ? <span className="text-emerald-600 dark:text-emerald-400">${(row as { cost_usd?: number }).cost_usd!.toFixed(4)}</span>
                    : <span className="text-muted-foreground/50">—</span>}
                </span>
              </div>
            )
          })}
        </div>

        {paged.length === 0 && !logsQuery.isLoading && (
          <div className="py-16 text-center text-sm text-muted-foreground">{t('logs.noEvents')}</div>
        )}
        {paged.length === 0 && logsQuery.isLoading && (
          <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            {t('logs.loading')}
          </div>
        )}
      </div>

      {/* 原始日志尾巴（引擎 stdout 白名单行） */}
      <div className="text-xs">
        <button type="button" className="text-muted-foreground hover:text-foreground" onClick={() => setTailOpen((v) => !v)}>
          {tailOpen ? '▾' : '▸'} {tf('logs.tailTitle', { n: tailData.length })}
        </button>
        {tailOpen && (
          <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg border bg-muted/30 p-3 font-mono text-[11px] leading-relaxed text-muted-foreground">
            {tailData.join(String.fromCharCode(10)) || t('logs.tailEmpty')}
          </pre>
        )}
      </div>

      {/* 底部分页栏 */}
      <div className="flex items-center justify-between rounded-xl border bg-card px-4 py-2 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">{t('logs.total')} {merged.length} {t('logs.totalAudit')} {auditRows.length} {t('logs.auditSignals')}</span>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" className="h-7 px-2.5" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>{t('logs.prev')}</Button>
          <span className="text-muted-foreground">{t('logs.page')} {page} {t('logs.pageOf')} {Math.max(1, Math.ceil(merged.length / pageSize))} {t('logs.pages')}</span>
          <Button size="sm" variant="outline" className="h-7 px-2.5" disabled={page >= Math.ceil(merged.length / pageSize)} onClick={() => setPage((p) => p + 1)}>{t('logs.next')}</Button>
          <Select value={String(pageSize)} onValueChange={(v) => { setPageSize(Number(v)); setPage(1) }}>
            <SelectTrigger className="h-7 w-[80px] text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="50">{tf('logs.pageSizeItem', { n: 50 })}</SelectItem>
              <SelectItem value="100">{tf('logs.pageSizeItem', { n: 100 })}</SelectItem>
              <SelectItem value="200">{tf('logs.pageSizeItem', { n: 200 })}</SelectItem>
              <SelectItem value="500">{tf('logs.pageSizeItem', { n: 500 })}</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* 详情弹窗 */}
      <EventDetailDialog open={detailOpen} onOpenChange={setDetailOpen} seq={detailSeq} />

      {/* 审计行详情弹窗（原地查看，不再跳转审计中心） */}
      <AuditEventDetailDialog event={auditDetail} onOpenChange={(v) => !v && setAuditDetail(null)} />

      {/* 清空确认 */}
      <Dialog open={confirmClear} onOpenChange={setConfirmClear}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t('logs.clearTitle')}</DialogTitle>
            <DialogDescription>
              {t('logs.clearDesc')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button size="sm" variant="outline" onClick={() => setConfirmClear(false)} disabled={clearing}>
              {t('common.cancel')}
            </Button>
            <Button size="sm" variant="destructive" onClick={doClear} loading={clearing}>
              {t('common.clear')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
