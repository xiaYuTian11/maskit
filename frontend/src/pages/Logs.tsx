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
import { useSearchParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Download, Trash2, RefreshCw, Search, HelpCircle, Loader2, X, Globe, FileText, History } from 'lucide-react'
import { getLogs, exportLogs, clearLogs, getLogMode, setLogMode, startLogTrace, stopLogTrace } from '@/api/logs'
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
import type { ShieldEvent, AuditEvent, AuditSeverity, LogMode, LogModeState } from '@/types/api'
import dayjs from 'dayjs'
import { cn } from '@/lib/utils'
import { useI18n } from '@/lib/i18n'
import { mergeMaskRestore, FILTER_ALL, type MergedEvent } from '@/lib/log-events'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { useVisibility } from '@/lib/useVisibility'

/** 审计信号行合并进主列表（AGENTS.md：auditRows 前端合并，不改 events 表） */
// 稳定空数组引用：避免 data 为 undefined 时每 render 创建新空数组导致 useMemo 失效
const EMPTY_LIST: readonly never[] = []

/** 秒 → mm:ss（限时排障倒计时）。超过一小时也不出现 hh：上限就是 60 分钟。 */
function fmtCountdown(sec: number): string {
  const s = Math.max(0, Math.floor(sec))
  return `${Math.floor(s / 60).toString().padStart(2, '0')}:${(s % 60).toString().padStart(2, '0')}`
}

/** 事件累积列表的内存封顶（与服务端导出上限 2000 对齐）；轮询游标另存，不受截断影响 */
const MAX_LOG_LIST = 2000

/**
 * 入口筛选的「全部」哨兵。与 FILTER_ALL 同理：Radix Select 规定 SelectItem 的 value
 * 不能是空串（空串=未选择、显示 placeholder），用它当真实选项会跟组件语义打架。
 */
const INGRESS_ALL = '__all__'

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
  /** 未还原占位符样本（引擎侧外发；仅未还原时存在，用于区分模型改写与映射丢失） */
  unresolved_samples?: string[]
  /** 5xx 归因（引擎外发）：upstream=上游返回原样透传 / engine=本机熔断 / fallback=代理未运行兜底。
   *  列表里必须看得见 —— 否则「上游返回 503」会被当成网关故障（2026-09-30 实测误判） */
  block_source?: string
  /** 靠宽松兜底（模型剥了花括号）修回来的占位符数。成功路径，但值得看见 */
  degraded?: number
  /**
   * 批次 2 统一检测口径：处置结论与完整度。列表必须能区分「已扫描未命中 / 明确直通 /
   * 已阻断 / 检测不完整」——它们此前都长得像「什么都没发生」。
   */
  decision?: 'masked' | 'scanned_clean' | 'blocked' | 'passthrough'
  completeness?: 'complete' | 'partial' | 'failed' | 'not_applicable' | 'unknown'
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
/** 日志表格列宽定义。
 *
 * **表头与数据行必须共用这一份**：两处各写一遍数值时，改一处忘一处就会让表头与内容
 * 逐列错位（此前就是这么漂移的）。同时给每个需要截断的 grid cell 都加 `min-w-0`
 * —— grid item 默认 `min-width:auto`，不加的话 `truncate` 完全不生效，长值会被
 * 行容器的 `overflow-hidden` **硬切断**（没有省略号，看着像文字被压重叠）。
 */
const LOG_GRID_COLS =
  'grid-cols-[68px_88px_112px_108px_minmax(96px,1fr)_minmax(190px,1.4fr)_54px_58px_72px]'
/** 表格最小宽度：上面这些列 + gap + 左右内边距能完整放下的下限；低于它由外层横向滚动接管。 */
const LOG_MIN_W = 'min-w-[940px]'

/** 「隐藏噪声」偏好的存储键（localStorage）：跨会话保留，重开客户端后仍生效。
 *  命名沿用 AppLayout 的 `maskit_sidebar_collapsed`（maskit_ + 模块 + 字段），
 *  不再自创 `maskit.logs.xxx` 这种点号风格。 */
const HIDE_NOISE_STORAGE_KEY = 'maskit_logs_hide_noise'

/**
 * 噪声默认隐藏。实测（2026-10-05 本机事件库）CANCEL 与 MASK 已接近 1:1，
 * 默认展示会让列表一半是客户端断开行；需要看全量时关掉开关即可（选择被记住）。
 */
const HIDE_NOISE_DEFAULT = true

/**
 * 读「隐藏噪声」偏好。localStorage 不可用（隐私模式 / 受限 webview）时退回默认值 ——
 * 偏好读不到不该让日志页报错，也不该让筛选行为变得不可预期。
 */
function readHideNoisePreference(): boolean {
  try {
    const raw = localStorage.getItem(HIDE_NOISE_STORAGE_KEY)
    if (raw === '0') return false
    if (raw === '1') return true
  } catch {
    /* 读失败按默认值处理 */
  }
  return HIDE_NOISE_DEFAULT
}

/** 写「隐藏噪声」偏好；写失败静默（与 shield-fetch 的 sessionStorage 同口径）。 */
function writeHideNoisePreference(value: boolean): void {
  try {
    localStorage.setItem(HIDE_NOISE_STORAGE_KEY, value ? '1' : '0')
  } catch {
    /* 隐私模式等场景忽略 */
  }
}

interface LogsCache {
  list: ShieldEvent[]
  tail: string[]
  /** 已消费到的最大 seq：列表被 MAX_LOG_LIST 截断后，下一轮轮询仍从这里续，不会重复拉取 */
  cursor: number
  /** 反向游标（§D3.1）：已经翻到的最早 seq（再往前翻就用它作 before_seq） */
  olderCursor?: number
  /** 更早处是否还有符合筛选的行（决定「加载更早」是否可用） */
  hasOlder?: boolean
  /** 时间锚点（epoch 秒）：非空表示当前列表来自「某时间点之前」的查询 */
  timeAnchor?: number
}

type LogRow = (AuditRow & { _audit: true }) | MergedEvent

export default function LogsPage() {
  const { t, tf } = useI18n()
  const [searchParams, setSearchParams] = useSearchParams()
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
  /** 入口维度筛选（proxy / ext）。落 URL query，可分享、可回退 —— 与词榜跳转同口径 */
  const [ingress, setIngress] = useState<string>(INGRESS_ALL)
  const [detailSeq, setDetailSeq] = useState<number | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)
  // 审计行详情：原地弹窗（不再跳转审计中心）
  const [auditDetail, setAuditDetail] = useState<AuditEvent | null>(null)
  const [confirmClear, setConfirmClear] = useState(false)
  const [tailOpen, setTailOpen] = useState(false)
  const [tailData, setTailData] = useState<string[]>([])
  // 懒初始化读本地偏好：默认开启，用户关掉后下次进来仍是关掉的（见 readHideNoisePreference）
  const [hideNoise, setHideNoise] = useState<boolean>(readHideNoisePreference)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const scrollRef = useRef<HTMLDivElement>(null)

  // —— 反向游标（§D3.1）：往回翻历史 ——
  // 必须声明在 useQuery 之前：查询配置里的 refetchInterval 会引用 historyMode，
  // 写在后面就是渲染期的 TDZ（Cannot access before initialization）。
  const [historyMode, setHistoryMode] = useState(false)
  const [olderLoading, setOlderLoading] = useState(false)
  const [hasOlder, setHasOlder] = useState(false)
  /** 时间锚点（epoch 秒）：只看这个时间**之前**的记录；null = 不限时间 */
  const [timeAnchor, setTimeAnchor] = useState<number | null>(null)
  /** datetime-local 输入框的值（本地时间字符串），仅作为输入缓存 */
  const [beforeTsInput, setBeforeTsInput] = useState('')

  // 从 URL searchParams 同步初始筛选条件（支持外部/首页携带参数跳转）
  // 筛选变化时重置反向翻页状态：历史游标是「当前筛选下」的定位，
  // 换了筛选器还沿用旧游标会把两个口径的页拼在一起（条数对不上）。
  useEffect(() => {
    setHistoryMode(false)
    setHasOlder(false)
    // 时间锚点也是「当前筛选下」的定位：换了筛选器还沿用旧锚点，会得到一个
    // 既不是新筛选的全部、也不是旧筛选的全部的中间集合（用户看到条数莫名变化）。
    setTimeAnchor(null)
    setBeforeTsInput('')
  }, [filterType, sensitive, q, fulltext, ingress])

  useEffect(() => {
    const urlQ = (searchParams.get('q') || '').trim()
    const urlType = (searchParams.get('type') || '').trim().toUpperCase()
    const urlFulltext = searchParams.get('fulltext') === '1'
    if (urlQ) {
      setSearchInput(urlQ)
      setQ(urlQ)
    }
    if (urlType) {
      setFilterType(urlType)
    }
    if (urlFulltext) {
      setFulltext(true)
    }
    // 入口维度**按 URL 原值镜像**（而不是「有才设」）：它只由本页写入 URL，
    // 镜像才能让浏览器前进/后退真的切换筛选，也才能让「词条 ×N → 日志条数」对得上。
    const urlIngress = (searchParams.get('ingress') || '').trim().toLowerCase()
    setIngress(urlIngress === 'proxy' || urlIngress === 'ext' ? urlIngress : INGRESS_ALL)
  }, [searchParams])

  // 保留天数配置已移至高级设置页（Logs 筛选栏只留筛选控件）

  // 搜索防抖 250ms：只更新 q（驱动 queryKey），不再手动清空列表
  useEffect(() => {
    const t = setTimeout(() => setQ(searchInput.trim()), 250)
    return () => clearTimeout(t)
  }, [searchInput])

  // —— 事件查询：累积列表放进 query cache，游标从缓存数据派生 ——
  const logsKey = useMemo(
    () => ['logs', { filterType, sensitive, q, fulltext, ingress }] as const,
    [filterType, sensitive, q, fulltext, ingress],
  )
  // 筛选参数只写一份（轮询/前缀/加载更早/按时间回看四处共用）：
  // 各写各的必然漂移——实测教训就是导出一致性（列表只看扩展、导出却是全量）。
  const filterParams = useMemo(() => ({
    type: filterType === FILTER_ALL || filterType === 'EXT_ALL' || filterType === 'PASS_COMBINED'
      ? undefined : filterType,
    sensitive,
    q,
    fulltext,
    ingress: (filterType === 'EXT_ALL'
      ? 'ext'
      : ingress === INGRESS_ALL ? undefined : ingress) as 'proxy' | 'ext' | undefined,
  }), [filterType, sensitive, q, fulltext, ingress])

  const logsQuery = useQuery<LogsCache>({
    queryKey: logsKey,
    queryFn: async ({ queryKey, signal }) => {
      // 从缓存读上次的累积列表 + 游标（首次为空）
      const prev = queryClient.getQueryData<LogsCache>(queryKey)
      const prevList = prev?.list ?? []
      // 续拉锚点优先取持久化游标：列表可能被 MAX_LOG_LIST 截断，末元素的 seq 已不再等于最大 seq
      let since = prev?.cursor ?? (prevList.length > 0 ? prevList[prevList.length - 1].seq : 0)
      let list = prevList
      let tail = prev?.tail ?? []
      const seen = new Set(prevList.map((e) => e.seq))
      // Catch up after backgrounding without skipping records. Bound each poll so
      // sustained traffic cannot keep it running forever; the next poll continues.
      let cursor = since
      for (let batch = 0; batch < 5; batch++) {
        const resp = await getLogs({
          since,
          limit: 200,
          ...filterParams,
          slim: true,
        }, signal)
        tail = resp.tail ?? tail
        // 游标重置：清空日志/库隔离重建后自增 id 从 1 重新开始，旧 cursor（高值）
        // 永远拉不到新记录——丢弃累积列表与游标，从 0 重新拉取。
        // 页码必须一并归位：用户停在第 2 页时列表骤减会渲染出空页 + 错误的分页条。
        if (resp.reset && since > 0) {
          since = 0
          cursor = 0
          list = []
          seen.clear()
          setPage(1)
          continue
        }
        const added = resp.events.filter((e) => {
          if (seen.has(e.seq)) return false
          seen.add(e.seq)
          return true
        })
        if (added.length) list = [...list, ...added]
        const next = resp.next_since ?? resp.events.at(-1)?.seq ?? since
        // 无论本轮是否还有更多（has_more=false 时同样已消费到 next），都把游标推进到
        // 实际看到的最后一个 seq，保证下轮 from cursor 续接。
        if (next > cursor) cursor = next
        if (!resp.has_more || next <= since) break
        since = next
      }
      if (tail.length) setTailData(tail)
      // 内存封顶：长时悬挂的 Logs 页无限累积会持续涨内存，且与服务端导出上限（2000）对齐。
      // 只截断展示窗口，不丢轮询游标（cursor 单独存），也不会因此重复拉取历史。
      if (list.length > MAX_LOG_LIST) list = list.slice(list.length - MAX_LOG_LIST)
      // 反向翻页游标必须原样带回去：轮询每 3s 重写一次缓存，漏带等于把用户刚
      // 翻出来的历史位置每次重置回顶部。
      return { list, tail, cursor, olderCursor: prev?.olderCursor, hasOlder: prev?.hasOlder,
               timeAnchor: prev?.timeAnchor }
    },
    // 本页单独配置：不走全局 30s 缓存，挂载即发
    staleTime: 0,
    refetchOnMount: 'always',
    // 历史模式下暂停实时轮询：用户在往回翻历史时，轮询会持续往尾部追加新事件，
    // 把刚翻出来的旧页从展示窗口里挤出去（旧页会被 2000 条上限截掉）。
    // 「往回看」与「盯实时」两个诉求本身互斥，暂停是诚实的选择，
    // UI 上有明确的「回到实时」按钮，不是静默停更。
    refetchInterval: hidden || historyMode ? false : 3000,
    refetchIntervalInBackground: false,
  })

  const events = logsQuery.data?.list ?? EMPTY_LIST
  const isFetching = logsQuery.isFetching

  // 导出 / 清空进行中（长耗时操作，需要即时反馈）
  const [exporting, setExporting] = useState(false)
  const [clearing, setClearing] = useState(false)

  // —— 日志写入模式（§D1）——
  // 模式必须作为「当前生效的事实」展示：最小模式下库里本来就没存正文，
  // 用户不看到这个状态就会以为“详情弹窗空白”是 bug。
  // 存整个 state（不只存模式名）：限时排障的**剩余时间**也在里面。
  const [modeInfo, setModeInfo] = useState<LogModeState | null>(null)
  const modeState: LogMode | null = modeInfo?.effective ?? null
  const [modeBusy, setModeBusy] = useState(false)

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
      .filter((row) => {
        if (filterType === FILTER_ALL) return true
        if (filterType === 'EXT_ALL') return (row as { ingress?: string }).ingress === 'ext'
        if (filterType === 'PASS_COMBINED') return ['PASS', 'BYPASS', 'SKIP'].includes(row.type)
        return row.type === filterType
      })
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
    queryClient.setQueryData<LogsCache>(logsKey, { list: [], tail: [], cursor: 0 })
    queryClient.invalidateQueries({ queryKey: ['logs'] })
  }, [queryClient, logsKey])

  // 写入模式（§D1）：进页拉一次，不在 3s 轮询里带（模式是慢变量，
  // 且它由本页自己改，改完当场刷新）。
  const refreshMode = useCallback(() => {
    getLogMode()
      .then((s) => setModeInfo(s ?? null))
      .catch(() => setModeInfo(null))
  }, [])
  useEffect(() => { refreshMode() }, [refreshMode])

  // 限时排障的剩余倒计时：`trace_until` 由后端给出，前端只负责显示。
  // 归零后**重新向后端问一次**而不是自己改状态：窗口结束可能是到点了，
  // 也可能是用户在别处手动关的，前端猜一个都不如问一句准。
  const [traceLeft, setTraceLeft] = useState<number | null>(null)
  useEffect(() => {
    const until = modeInfo?.effective === 'trace' ? Number(modeInfo.trace_until || 0) : 0
    if (!until) {
      setTraceLeft(null)
      return
    }
    let timer: number | undefined
    const tick = () => {
      const left = Math.max(0, Math.floor(until - Date.now() / 1000))
      setTraceLeft(left)
      if (left <= 0) {
        if (timer !== undefined) clearInterval(timer)
        refreshMode()
      }
    }
    tick()
    timer = window.setInterval(tick, 1000)
    return () => { if (timer !== undefined) clearInterval(timer) }
  }, [modeInfo, refreshMode])

  const changeMode = async (next: 'summary' | 'detailed') => {
    if (modeBusy) return
    setModeBusy(true)
    try {
      const s = await setLogMode(next)
      setModeInfo(s ?? null)
      toast(t(next === 'summary' ? 'logs.modeSummaryOn' : 'logs.modeDetailedOn'))
      refresh()
    } catch (e) {
      toast(tf('logs.modeFail', { e: String(e) }), 'error')
    } finally {
      setModeBusy(false)
    }
  }

  const toggleTrace = async () => {
    if (modeBusy) return
    setModeBusy(true)
    try {
      const was = modeState === 'trace'
      const s = was ? await stopLogTrace() : await startLogTrace(15)
      setModeInfo(s ?? null)
      toast(t(was ? 'logs.traceOff' : 'logs.traceOn'))
    } catch (e) {
      toast(tf('logs.modeFail', { e: String(e) }), 'error')
    } finally {
      setModeBusy(false)
    }
  }

  const backToLive = useCallback(() => {
    // 时间锚点下必须**丢弃列表缓存**：那时 cache 里是一段不连续的历史切片，
    // 而 `cursor` 还是实时值。直接 invalidate 会让 queryFn 拿「历史列表 + 从 cursor
    // 增量拉取」拼在一起 —— 列表里同时躺着锚点前后的两批数据（实测会重现）。
    // `loadOlder` 路径不需要这么做：它的列表是连续的，从 cursor 继续是对的。
    if (timeAnchor) queryClient.setQueryData<LogsCache>(logsKey, undefined)
    setHistoryMode(false)
    setTimeAnchor(null)
    setBeforeTsInput('')
    setHasOlder(false)
    // 回到实时就重新拉一遍，不依赖暂停期间漏掉的轮询
    queryClient.invalidateQueries({ queryKey: ['logs'] })
  }, [queryClient, timeAnchor, logsKey])

  const loadOlder = useCallback(async () => {
    if (olderLoading) return
    const prev = queryClient.getQueryData<LogsCache>(logsKey)
    const prevList = prev?.list ?? []
    const oldest = prev?.olderCursor ?? prevList[0]?.seq
    if (!oldest) return
    setOlderLoading(true)
    setHistoryMode(true)
    try {
      // 同 applyTimeAnchor：先取消在途轮询，否则它的写回会盖掉刚翻出来的旧页
      // （轮询是向后累积，旧页会被写回到集的尾部或直接被截掉）。
      await queryClient.cancelQueries({ queryKey: logsKey, exact: true })
      const resp = await getLogs({
        before_seq: oldest,
        limit: 200,
        ...filterParams,
        slim: true,
      })
      const seen = new Set(prevList.map((e) => e.seq))
      const older = resp.events.filter((e) => !seen.has(e.seq))
      // 展示窗口上限与服务端导出上限对齐；满了就停在当前窗口并告知，
      // 不静默裁掉一端又假装列表完整。
      let list = [...older, ...prevList]
      const capped = list.length > MAX_LOG_LIST
      if (capped) list = list.slice(0, MAX_LOG_LIST)
      queryClient.setQueryData<LogsCache>(logsKey, {
        list,
        tail: prev?.tail ?? [],
        cursor: prev?.cursor ?? 0,
        olderCursor: resp.before_cursor ?? oldest,
        hasOlder: Boolean(resp.has_older) && !capped,
        // 时间锚点下继续往前翻时，锚点本身**不能丢**：横幅要一直显示“正在查看
        // X 之前的记录”，丢了就摊平成普通历史模式（用户会以为再往前的翻页失效了）。
        timeAnchor: prev?.timeAnchor,
      })
      setHasOlder(Boolean(resp.has_older) && !capped)
      if (resp.events.length === 0) toast(t('logs.olderNone'))
    } catch (e) {
      toast(tf('logs.olderFail', { e: String(e) }), 'error')
    } finally {
      setOlderLoading(false)
    }
  }, [olderLoading, queryClient, logsKey, filterParams, t, tf])

  /**
   * 按时间区间回看（§D3.1 的时间游标）：只在 `ts < anchor` 的记录里取最新一页。
   * 与「加载更早」共用同一条历史通道，区别只是钡点：一个按 seq 往前翻，
   * 一个直接跳到某个时间点之前。清空钡点（传 null）即回到实时。
   */
  const applyTimeAnchor = useCallback(async (ts: number | null) => {
    if (ts === null) {
      backToLive()
      return
    }
    if (olderLoading) return
    setOlderLoading(true)
    setHistoryMode(true)
    setTimeAnchor(ts)
    try {
      // 先取消在途的实时轮询：本函数用 `setQueryData` 直写缓存，而在途的 queryFn
      // 完成后 React Query 会自己写回同一 key —— 两个写入顺序不定，
      // 输给轮询时用户会看到「钡点设了但列表还是实时的」（实测会重现）。
      // `cancelQueries` 会把已发出的请求 abort（queryFn 已把 signal 传给 getLogs）。
      await queryClient.cancelQueries({ queryKey: logsKey, exact: true })
      const resp = await getLogs({ before_ts: ts, limit: 200, ...filterParams, slim: true })
      // 服务端返回的是一页（≤200），永远不会碰到 MAX_LOG_LIST，不写无效的截断分支。
      queryClient.setQueryData<LogsCache>(logsKey, {
        list: resp.events,
        tail: resp.tail ?? [],
        // 时间锚点下不参与实时轮询（historyMode 已暂停），cursor 保留原值即可；
        // 回到实时时 backToLive 会把整份缓存丢掉重拉。
        cursor: queryClient.getQueryData<LogsCache>(logsKey)?.cursor ?? 0,
        olderCursor: resp.before_cursor ?? undefined,
        hasOlder: Boolean(resp.has_older),
        timeAnchor: ts,
      })
      setHasOlder(Boolean(resp.has_older))
      if (resp.events.length === 0) toast(t('logs.timeAnchorEmpty'))
      else toast(t('logs.timeAnchorApplied'))
    } catch (e) {
      toast(tf('logs.olderFail', { e: String(e) }), 'error')
    } finally {
      setOlderLoading(false)
    }
  }, [olderLoading, queryClient, logsKey, filterParams, backToLive, t, tf])

  const doExport = async () => {
    if (exporting) return
    setExporting(true)
    try {
      const resp = await exportLogs({
        type: filterType === FILTER_ALL || filterType === 'EXT_ALL' || filterType === 'PASS_COMBINED' ? undefined : filterType,
        sensitive,
        q,
        fulltext,
        // 入口筛选必须传：不传就会“列表只看扩展、导出却是全量”，两边条数对不上
        ingress: filterType === 'EXT_ALL' ? 'ext' : ingress === INGRESS_ALL ? undefined : (ingress as 'proxy' | 'ext'),
      })
      // 截断状态从**响应头**读：文件是下载走的，body 里的 truncated 用户看不到。
      // 不告知的后果实测过：用户导出一天日志，只拿到上限条数却以为拿到了全部。
      const exportedN = resp.headers.get('X-Maskit-Exported') || ''
      const matchedN = resp.headers.get('X-Maskit-Matched') || ''
      const wasTruncated = resp.headers.get('X-Maskit-Truncated') === '1'
      const doneMsg = wasTruncated
        ? tf('logs.exportedTruncated', { n: exportedN, total: matchedN })
        : t('logs.exported')
      const blob = await resp.blob()
      const filename = `maskit-events-${dayjs().format('YYYY-MM-DD-HHmmss')}.json`
      if (isTauri()) {
        const { save } = await import('@tauri-apps/plugin-dialog')
        const { writeFile } = await import('@tauri-apps/plugin-fs')
        const buf = new Uint8Array(await blob.arrayBuffer())
        const path = await save({ defaultPath: filename, filters: [{ name: 'JSON', extensions: ['json'] }] })
        if (path) {
          await writeFile(path, buf)
          toast(doneMsg)
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
        toast(doneMsg)
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
      setPage(1)  // 清空后列表骤减，停留高页码会渲染空页 + 错误的分页条
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
    // 批次 2：处置结论/完整度的紧凑呈现（与详情弹窗同一口径，见 inspection.py）。
    // 只收「一眼需要看出来的三种」：检测不完整（可能漏码）、明确直通（未脱敏）、
    // 已阻断。正常脱敏/扫描未命中不额外加噪声。
    const stateChip =
      row.completeness === 'partial' || row.completeness === 'failed'
        ? { text: t('logs.stateIncomplete'), cls: 'text-amber-600 dark:text-amber-400' }
        : row.decision === 'passthrough'
          ? { text: t('logs.statePassthrough'), cls: 'text-muted-foreground' }
          : row.decision === 'blocked'
            ? { text: t('logs.stateBlocked'), cls: 'text-red-600 dark:text-red-400' }
            : null
    // 提取本条记录捕获的敏感词类型标签（如 PHONE, CONNSTR 等），让列表直观展现脱敏项类别
    const itemLabels = Array.from(
      new Set(
        (((row as MergedEvent).items || []) as { label?: string; preview?: string }[])
          .map((it) => it.label)
          .filter((l): l is string => Boolean(l))
      )
    )
    const itemsPreviewText = (((row as MergedEvent).items || []) as { label?: string; preview?: string }[])
      .map((it) => (it.label ? `${it.label}: ${it.preview || '—'}` : ''))
      .filter(Boolean)
      .join(' | ')

    if (masked || restored || unresolved || degraded || stateChip) {
      return (
        // 拆成上下两行（计数 / 标签）是**为根治重叠**：此前挤在单行里，标签组一旦被压缩，
        // 内部 `whitespace-nowrap` 的子元素会溢出自身边界，与后面的「未还原 N」糊在一起
        // （实测截图：`API_KEY` 与橙色 `未还原 4` 直接重叠）。拆行后同一行内不再存在
        // 「可收缩元素 与 shrink-0 元素 抢宽度」的竞争，溢出统一由 overflow-hidden 裁切。
        <span
          className="flex min-w-0 flex-col justify-center gap-0.5 text-[11px]"
          title={[itemsPreviewText, row.method, row.host, row.path].filter(Boolean).join(' · ')}
        >
          {/* 第一行：计数。关键数字，永不与标签抢宽度 */}
          <span className="flex min-w-0 items-center gap-1.5 overflow-hidden">
            {masked && <span className="shrink-0 whitespace-nowrap text-blue-600 dark:text-blue-400">{t('logs.colMasked')} {row.count}</span>}
            {restored && <span className="shrink-0 whitespace-nowrap text-emerald-600 dark:text-emerald-400">{t('logs.colRestored')} {row.restored}</span>}
            {unresolved && (
              <span className="shrink-0 whitespace-nowrap text-amber-600 dark:text-amber-400" title={t('logs.unresolvedHint')}>
                {t('logs.colUnresolved')} {row.unresolved}
              </span>
            )}
            {degraded && (
              <span className="shrink-0 whitespace-nowrap text-muted-foreground" title={t('logs.degradedHint')}>
                {t('logs.colDegraded')} {row.degraded}
              </span>
            )}
            {stateChip && (
              <span className={`shrink-0 whitespace-nowrap ${stateChip.cls}`}>{stateChip.text}</span>
            )}
          </span>
          {/* 第二行：命中标签。超出仅显示前两个 + 折叠计数 */}
          {itemLabels.length > 0 && (
            <span className="flex min-w-0 items-center gap-1 overflow-hidden">
              {itemLabels.slice(0, 2).map((lb) => (
                <span key={lb} className="shrink-0 whitespace-nowrap rounded bg-muted px-1 py-0.2 font-mono text-[9px] text-muted-foreground">
                  {lb}
                </span>
              ))}
              {itemLabels.length > 2 && (
                <span className="shrink-0 whitespace-nowrap text-[9px] text-muted-foreground">+{itemLabels.length - 2}</span>
              )}
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
          <SelectTrigger className="h-8 w-[156px] text-xs">
            <SelectValue placeholder={t('logs.filterAll')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={FILTER_ALL}>{t('logs.filterAll')}</SelectItem>
            <SelectItem value="EXT_ALL" className="font-medium text-blue-600 dark:text-blue-400">
              <div className="flex items-center gap-1.5">
                <Globe className="h-3.5 w-3.5" />
                <span>{t('logs.filterExt')}</span>
              </div>
            </SelectItem>
            <SelectGroup>
              <SelectLabel>{t('logs.filterHandled')}</SelectLabel>
              <SelectItem value="MASK">{t('logs.filterMasked')}</SelectItem>
              <SelectItem value="RESTORE">{t('logs.filterRestored')}</SelectItem>
            </SelectGroup>
            <SelectGroup>
              <SelectLabel>{t('logs.filterErrors')}</SelectLabel>
              <SelectItem value="BLOCK">{t('logs.filterBlocked')}</SelectItem>
              <SelectItem value="ERR">{t('logs.filterErr')}</SelectItem>
              <SelectItem value="SCAN_WARN">{t('logs.filterScanWarn')}</SelectItem>
            </SelectGroup>
            <SelectGroup>
              <SelectLabel>{t('logs.filterPassedCombined')}</SelectLabel>
              <SelectItem value="PASS_COMBINED">{t('logs.filterPassedAll')}</SelectItem>
            </SelectGroup>
            <SelectGroup>
              <SelectLabel className="text-[10px] text-muted-foreground">{t('logs.filterAdvanced')}</SelectLabel>
              <SelectItem value="PASS">{t('logs.filterPass')}</SelectItem>
              <SelectItem value="BYPASS">{t('logs.filterBypass')}</SelectItem>
              <SelectItem value="SKIP">{t('logs.filterSkip')}</SelectItem>
              <SelectItem value="CANCEL">{t('logs.filterCancel')}</SelectItem>
              <SelectItem value="DNS_ERROR">{t('logs.filterDns')}</SelectItem>
            </SelectGroup>
          </SelectContent>
        </Select>

        {/* 入口维度筛选：与首页/统计页的词榜分组**同一个值**，跳转时带着走 */}
        <Select
          value={ingress}
          onValueChange={(v) => {
            setIngress(v)
            setPage(1)
            // 落 URL query（可分享/可回退）——只做组件内 state 的话，
            // 首页词条按入口分组、日志列表却不认这个参数，又回到「数字对不上」。
            setSearchParams(
              (prev) => {
                const next = new URLSearchParams(prev)
                if (v === INGRESS_ALL) next.delete('ingress')
                else next.set('ingress', v)
                return next
              },
              { replace: false },
            )
          }}
        >
          <SelectTrigger className="h-8 w-[132px] text-xs" data-testid="ingress-filter">
            <SelectValue placeholder={t('logs.ingress.all')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={INGRESS_ALL}>{t('logs.ingress.all')}</SelectItem>
            <SelectItem value="proxy">{t('logs.ingress.proxy')}</SelectItem>
            <SelectItem value="ext">{t('logs.ingress.ext')}</SelectItem>
          </SelectContent>
        </Select>

        {/* 时间锚点（§D3.1 时间游标）：只看这个时间点**之前**的记录。
            用原生 datetime-local：它不引入新依赖，且浏览器自带时区处理——
            自己拼时区串是这类功能最常见的一类错。 */}
        <div className="flex items-center gap-1">
          <Input
            type="datetime-local"
            className="h-8 w-[196px] text-xs"
            value={beforeTsInput}
            onChange={(e) => {
              const v = e.target.value
              setBeforeTsInput(v)
              if (!v) {
                // 清空输入框 = 取消时间锚点，回到实时
                if (timeAnchor) applyTimeAnchor(null)
                return
              }
              const ts = dayjs(v).unix()
              // 无效日期（dayjs 不抛错，只会给 NaN）一律不提交，避免把 NaN 发给后端
              if (!Number.isFinite(ts) || ts <= 0) return
              applyTimeAnchor(ts)
            }}
            title={t('logs.timeAnchorTitle')}
            data-testid="logs-time-anchor"
          />
          {timeAnchor && (
            <Button size="sm" variant="ghost" className="h-8 px-2 text-xs"
              onClick={() => applyTimeAnchor(null)} title={t('logs.timeAnchorClear')}>
              <X className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>

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
              onClick={() => {
                setSearchInput('')
                setQ('')
                // 只清「跳转带过来的搜索参数」（q/type/fulltext），**保留 ingress**：
                // 这个按钮的语义是清搜索框，不是把入口筛选也一起重置。
                setSearchParams(
                  (prev) => {
                    const next = new URLSearchParams(prev)
                    next.delete('q')
                    next.delete('type')
                    next.delete('fulltext')
                    return next
                  },
                  { replace: true },
                )
              }}
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
        {/* 切开关会改变列表行数：重置页码，避免停留在越界的空页（与全文搜索/仅敏感同口径） */}
        <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground" title={t('logs.hideNoiseTitle')}>
          <Switch
            checked={hideNoise}
            onCheckedChange={(v) => { setHideNoise(v); setPage(1); writeHideNoisePreference(v) }}
            className="scale-75"
          />
          <span>{t('logs.hideNoise')}</span>
        </label>

        {/* 日志写入模式（§D1）：把「当前生效的记录粒度」摆在筛选栏，
            用户不必去设置页猜为什么详情弹窗是空的。 */}
        <div className="flex items-center gap-1.5">
          <Select
            value={modeState === 'trace' ? 'detailed' : (modeState ?? 'detailed')}
            onValueChange={(v) => changeMode(v as 'summary' | 'detailed')}
            disabled={modeBusy || modeState === 'trace'}
          >
            <SelectTrigger className="h-8 w-[136px] text-xs" title={t('logs.modeTitle')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="summary">{t('logs.modeSummary')}</SelectItem>
              <SelectItem value="detailed">{t('logs.modeDetailed')}</SelectItem>
            </SelectContent>
          </Select>
          <Button
            size="sm"
            variant={modeState === 'trace' ? 'default' : 'outline'}
            className="h-8 px-2.5 text-xs"
            onClick={toggleTrace}
            disabled={modeBusy}
            title={t('logs.traceTitle')}
          >
            {modeState === 'trace'
              ? tf('logs.traceLeft', { t: traceLeft === null ? '—' : fmtCountdown(traceLeft) })
              : t('logs.traceStart')}
          </Button>
        </div>

        <div className="ml-auto flex items-center gap-1.5">
          <Button size="sm" variant="ghost" className="h-8 px-2.5" onClick={refresh} title={t('logs.refresh')}>
            <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} />
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="h-8 px-2.5 text-xs"
            onClick={loadOlder}
            loading={olderLoading}
            disabled={!events.length || olderLoading || (historyMode && !hasOlder)}
            title={t('logs.olderTitle')}
          >
            {!olderLoading && <History className="mr-1 h-3.5 w-3.5" />} {t('logs.older')}
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

      {historyMode && (
        <div className="flex items-center justify-between gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-700 dark:text-amber-400">
          <span>
            {timeAnchor
              ? tf('logs.historyBannerAt', { t: dayjs(timeAnchor * 1000).format('YYYY-MM-DD HH:mm') })
              : t('logs.historyBanner')}
          </span>
          <Button size="sm" variant="ghost" className="h-6 px-2 text-xs" onClick={backToLive}>
            {t('logs.backToLive')}
          </Button>
        </div>
      )}

      {/* 表格（虚拟滚动） */}
      <div
        ref={scrollRef}
        className="min-h-0 flex-1 overflow-auto rounded-xl border bg-card shadow-[var(--shadow-card)]"
      >
        <div className={LOG_MIN_W}>
        {/* 表头（固定）：时间(两行 日期+时间) / 结果 / 入口 / 上游 / 模型(收紧) / 处理摘要(脱敏/还原 宽列) / 状态 / 耗时 / 费用 */}
        <div
          className={cn(
            'sticky top-0 z-10 grid gap-2 border-b bg-card px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground',
            LOG_GRID_COLS,
          )}
        >
          <span>{t('logs.colTime')}</span>
          <span>{t('logs.colResult')}</span>
          <span>{t('logs.colIngress')}</span>
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
                  'absolute left-0 top-0 grid w-full items-center gap-2 overflow-hidden border-b px-3 text-[12px]',
                  LOG_GRID_COLS,
                  'transition-colors hover:bg-muted/40',
                  row._audit && 'bg-amber-500/5 hover:bg-amber-500/10',
                )}
                style={{ height: vi.size, transform: `translateY(${vi.start}px)` }}
                onClick={() => openDetail(row)}
              >
                {/* 时间：上日期下时间（用户要求，一行放不下就两行） */}
                <span className="flex flex-col leading-tight tabular-nums text-[11px] text-muted-foreground shrink-0">
                  <span>{row.ts ? dayjs(row.ts * 1000).format('MM-DD') : '—'}</span>
                  <span className="opacity-70">{row.ts ? dayjs(row.ts * 1000).format('HH:mm:ss') : ''}</span>
                </span>
                {/* 结果 */}
                <span className="flex items-center gap-1 min-w-0">
                  <EventTypeIcon type={row.type} className="h-3.5 w-3.5 shrink-0" />
                  <span className="truncate text-[11px] font-medium">{t(EVENT_TYPE_META[row.type]?.labelKey ?? row.type)}</span>
                </span>
                {/* 入口：proxy=CLI 代理链路；ext=浏览器扩展。如果是文档脱敏，同时显式标注 📄 文档脱敏 */}
                <div className="flex flex-col justify-center min-w-0">
                  {(row as { ingress?: string }).ingress === 'ext' ? (
                    <div className="flex flex-col gap-0.5">
                      <span className="inline-flex w-fit items-center gap-1 whitespace-nowrap rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-600 dark:text-blue-400">
                        <Globe className="h-3 w-3 shrink-0" />
                        <span>{t('logs.badgeExt')}</span>
                      </span>
                      {(!row._audit && (row.path === '/ext/mask-file' || (row.dialog && row.dialog.includes('文件脱敏')))) && (
                        <span className="inline-flex w-fit items-center gap-0.5 whitespace-nowrap text-[9px] font-medium text-amber-600 dark:text-amber-400" title={(!row._audit && row.dialog) ? row.dialog : t('logs.badgeDoc')}>
                          <FileText className="h-2.5 w-2.5 shrink-0" />
                          <span>{t('logs.badgeDoc')}</span>
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="min-w-0 truncate whitespace-nowrap text-[10px] text-muted-foreground">
                      {t('logs.ingress.proxy')}
                    </span>
                  )}
                </div>
                {/* 上游：优先配置名 upstream，client_app（进程探测）仅作缺失回退；扩展行展示目标站点 host */}
                <span className="min-w-0 truncate text-[11px] font-medium text-foreground/85" title={String(row.upstream || row.client_app || row.host || '')}>
                  {(row as { ingress?: string }).ingress === 'ext'
                    ? (row.host || 'Web AI')
                    : String(row.upstream || row.client_app || '—')}
                </span>
                {/* 模型：模型名 + 流式标签，完整 host/path 放 title（悬停可见）；扩展行展示模型或 Web 对话 */}
                <span
                  className="flex min-w-0 items-center gap-1.5"
                  title={`${row.host ?? ''}${row.path ?? ''}${row.model ? `\n${tf('logs.modelIn', { m: row.model })}` : ''}${(row as { _detailSeq?: number })._detailSeq ? `\n${tf('logs.restoredN', { n: row.restored ?? 0 })}` : ''}`}
                >
                  <code className="truncate font-mono text-[11px]">
                    {row.model || ((row as { ingress?: string }).ingress === 'ext' ? t('logs.webChat') : (row.upstream ? '—' : row.host) || '—')}
                  </code>
                  {row.stream_actual && (
                    <span className="shrink-0 rounded bg-muted/60 px-1 py-0.5 font-mono text-[9px] text-muted-foreground">
                      {row.stream_actual === 'stream' ? t('logs.streaming') : t('logs.whole')}
                    </span>
                  )}
                </span>
                {/* 处理摘要：脱敏/还原计数，审计行为信号名 + 严重度，无命中的行回退路径 */}
                {renderSummary(row)}
                {/* 状态：http_status 数字或 status 中文语义。
                    5xx 必须标出**来源**：上游返回的 503 与网关熔断的 503 在列表里
                    原本长得一模一样，实测被当成"网关坏了"（2026-09-30）。 */}
                <span className="flex min-w-0 flex-col items-center gap-0.5">
                  {row.http_status ? (
                    <>
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
                      {row.http_status >= 500 && (
                        <span
                          className="max-w-[6.5rem] truncate text-[9px] text-muted-foreground"
                          title={t(`logs.status5xx.${row.block_source || 'unknown'}`)}
                        >
                          {t(`logs.status5xx.${row.block_source || 'unknown'}`)}
                        </span>
                      )}
                    </>
                  ) : row.status ? (
                    <span className="min-w-0 truncate text-[9px] text-muted-foreground" title={String(row.status)}>
                      {row.status === 'no_placeholder_in_response' ? t('logs.statusNoRestore') : row.status === 'no_sensitive_data' ? t('logs.statusNoSensitive') : String(row.status).slice(0, 6)}
                    </span>
                  ) : (row as { ingress?: string }).ingress === 'ext' ? (
                    <Badge
                      variant="outline"
                      className="border-emerald-500/30 bg-emerald-500/10 px-1 py-0 text-[9px] font-mono text-emerald-600 dark:text-emerald-400"
                    >
                      200
                    </Badge>
                  ) : '—'}
                  {'transport' in row && row.transport && <span className="max-w-[6.5rem] truncate text-[9px] text-muted-foreground" title={t('transport.caution')}>{t(`transport.phase.${row.transport.phase || 'unknown'}`)}</span>}
                </span>
                {/* 耗时：合并行取整链路(RESTORE)，MASK 单行(未还原/阻断)取脱敏管线耗时 */}
                <span className="text-right tabular-nums text-[11px] text-muted-foreground">
                  {fmtMs(row.total_ms ?? row.upstream_ms ?? (row as { mask_ms?: number }).mask_ms)}
                </span>
                {/* 费用（RESTORE 事件由后端按模型×usage 估算） */}
                <span className="text-right tabular-nums text-[11px]">
                  {(row as { cost_usd?: number }).cost_usd != null && (row as { cost_usd?: number }).cost_usd! > 0
                    ? <span className="text-emerald-600 dark:text-emerald-400">${(row as { cost_usd?: number }).cost_usd!.toFixed(4)}</span>
                    : (row as { ingress?: string }).ingress === 'ext'
                      ? <span className="text-[10px] text-muted-foreground/40 font-mono">{t('logs.free')}</span>
                      : <span className="text-muted-foreground/50">—</span>}
                </span>
              </div>
            )
          })}
        </div>

        {paged.length === 0 && !logsQuery.isLoading && (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-2xl bg-muted/60 text-muted-foreground/70">
              <Search className="h-5 w-5 stroke-[1.5]" />
            </div>
            <p className="text-sm font-semibold text-foreground/80">{t('logs.noEvents')}</p>
            <p className="mt-1 max-w-sm text-xs text-muted-foreground/70">{t('logs.noEventsHint')}</p>
          </div>
        )}
        {paged.length === 0 && logsQuery.isLoading && (
          <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            {t('logs.loading')}
          </div>
        )}
        </div>
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
      <EventDetailDialog open={detailOpen} onOpenChange={setDetailOpen} seq={detailSeq} logMode={modeState ?? undefined} />

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
