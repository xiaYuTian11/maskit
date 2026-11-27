/**
 * 文件脱敏工作台（T4）
 *
 * 只做「确认与下载」：识别与脱敏全在引擎（T1-T3），本页不复制任何规则。
 * 所有请求经 @/api/files（shieldFetch）；不触碰代理配置/规则/事件库。
 *
 * @guard G810 可见文案全部走 t()，中英词条成对
 * @guard G812 只依赖 @/api/files，链路隔离
 */
// @guard G810 可见文案全部走 t()，中英词条成对
// @guard G812 只依赖 @/api/files，链路隔离
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { DragEvent, MouseEvent } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import {
  UploadCloud,
  RefreshCw,
  FileLock2,
  Download,
  FolderOpen,
  History,
  RotateCcw,
  Trash2,
  Ban,
  ShieldCheck,
  Square,
  Brush,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Loader2,
  Search,
  X,
  Layers,
  Archive,
  Play,
} from 'lucide-react'
import { PageHeader } from '@/components/patterns/PageHeader'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { useI18n } from '@/lib/i18n'
import {
  applyJob, cancelJob, createJob, createJobFromPath, deleteJob, downloadJob,
  downloadJobsZip, getCapabilities, getHits, getJob, getMergedHits, getPreview,
  isDesktopApp, listHistory, listJobs, pickDesktopDirectory, pickDesktopFiles,
  saveJob, scanJob,
  type ApplyOptions, type FileHistoryEntry, type FileHitView, type FileJobView,
  type FilesCapabilities, type MergedFileHitView, type PreviewBox,
  type Redaction, type TextEdit,
} from '@/api/files'

const NON_TERMINAL = new Set(['created', 'probing', 'ready', 'queued', 'scanning', 'applying', 'canceling'])
const TERMINAL = new Set(['done', 'failed', 'canceled', 'expired'])
const VISUAL = new Set(['pdf', 'image'])
const TEXT_CARRIERS = new Set(['ooxml', 'text'])
const PROGRESS_STAGES = new Set([
  'pdf_pages', 'pdf_hidden', 'ooxml_parts', 'ooxml_media', 'text_chunks', 'image_ocr',
])

const defaultOptions = (): ApplyOptions => ({
  clear_docinfo: true,
  keep_attachments: false,
  keep_embedded_objects: false,
  keep_icc: false,
  strip_non_image_media: false,
  dismissed_boxes: [],
})

const EMPTY_STR_MAP: Record<string, string> = {}
const EMPTY_BOOL_MAP: Record<string, boolean> = {}
const EMPTY_REDACTIONS: Redaction[] = []
const DEFAULT_APPLY_OPTIONS: ApplyOptions = defaultOptions()

function statusTone(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
  if (status === 'done') return 'default'
  if (status === 'failed' || status === 'expired') return 'destructive'
  if (status === 'awaiting_review') return 'secondary'
  return 'outline'
}

type TranslateF = ReturnType<typeof useI18n>['tf']

const ERROR_KEYS: Record<string, string> = {
  FILE_7401: 'files.err.state',
  FILE_7402: 'files.err.queueFull',
  FILE_7403: 'files.err.tooLarge',
  FILE_7408: 'files.err.saveDest',
  FILE_7410: 'files.err.failClosed',
  FILE_7411: 'files.err.pathModeDisabled',
  FILE_7601: 'files.err.officeUnsupported',
  FILE_7602: 'files.err.zipBomb',
  FILE_7610: 'files.err.tooManyHits',
  FILE_7801: 'files.err.visualUnsupported',
  FILE_7802: 'files.err.diskFull',
  FILE_7803: 'files.err.badCoords',
  FILE_7804: 'files.err.ocrUnavailable',
  FILE_7808: 'files.err.rasterFailed',
  FILE_7811: 'files.err.imageMetaFailed',
  office_parse_failed: 'files.err.parseFailed',
  pdf_parse_failed: 'files.err.parseFailed',
  file_type_unsupported: 'files.err.typeUnsupported',
  engine_restart: 'files.err.engineRestart',
  invalid_batch_id: 'files.err.invalidBatch',
  invalid_job_ids: 'files.err.invalidJobs',
  no_output: 'files.err.noOutput',
}

function describeError(code: string, tf: TranslateF): string {
  const key = ERROR_KEYS[code]
  if (key) return tf(key)
  return tf('files.error', { code })
}

function describeRequestError(err: unknown, tf: TranslateF): string {
  const code = (err as { code?: string })?.code
  if (code && ERROR_KEYS[code]) return describeError(code, tf)
  return String((err as Error)?.message || err)
}

// 引擎的覆盖计数是按载体各报一份的字典（text: scanned/masked，pdf: rendered_pages/…）；
// 直接 JSON.stringify 给用户看等于把内部字段名糊在界面上。这里只保留非零项并翻成人话，
// 零值/不适用字段不显示，避免「跳过 OCR 0 页」这类噪声。
function describeCoverage(
  coverage: Record<string, unknown>,
  carrier: string,
  tf: TranslateF,
): string[] {
  const lines: string[] = []
  const n = (k: string) => {
    const v = Number(coverage?.[k] ?? 0)
    return Number.isFinite(v) ? v : 0
  }
  const has = (k: string) => Object.prototype.hasOwnProperty.call(coverage || {}, k)
  const add = (k: string, key: string) => {
    if (n(k) > 0) lines.push(tf(key, { n: n(k) }))
  }
  if (has('scanned')) {
    if (carrier === 'text') lines.push(tf('files.cov.fullText'))
    else if (n('scanned') > 0) lines.push(tf('files.cov.scanned', { n: n('scanned') }))
  }
  add('masked', 'files.cov.masked')
  add('rendered_pages', 'files.cov.pages')
  add('rasterized_pages', 'files.cov.rasterized')
  add('text_layer_hits', 'files.cov.textLayerHits')
  add('hidden_hits', 'files.cov.hiddenHits')
  add('skipped_ocr_pages', 'files.cov.skippedOcr')
  add('scanned_embedded_images', 'files.cov.scannedEmbeddedImages')
  add('masked_embedded_images', 'files.cov.maskedEmbeddedImages')
  add('covered_embedded_images', 'files.cov.coveredEmbeddedImages')
  add('skipped_embedded_images', 'files.cov.skippedEmbeddedImages')
  add('embedded_objects_present', 'files.cov.embeddedPresent')
  add('embedded_objects_stripped', 'files.cov.embeddedStripped')
  add('embedded_objects_kept_unscanned', 'files.cov.embeddedKept')
  add('non_image_media_present', 'files.cov.nonImageMediaPresent')
  add('non_image_media_stripped', 'files.cov.nonImageMediaStripped')
  add('ner_skipped_chunks', 'files.cov.nerSkippedChunks')
  add('attachments_stripped', 'files.cov.attachmentsStripped')
  add('attachments_kept_unscanned', 'files.cov.attachmentsKept')
  return lines
}

// 告警码是引擎内部标识（`page_3_full_cover` 等），不能原样给用户看；
// 未知码保留原码作为尾巴，方便报告问题时定位，但不让整行变成乱码。
const PAGE_WARN_RX = /^page_(\d+)_(full_cover|ocr_failed_full_cover|kept_with_unmasked_hits)$/

function describeWarnings(warnings: string[], tf: TranslateF): string[] {
  return (warnings || []).map((code) => {
    if (code === 'embedded_objects_kept_unscanned') return tf('files.warn.embeddedKept')
    if (code === 'attachments_kept_unscanned') return tf('files.warn.attachmentsKept')
    if (code === 'non_image_media_unscanned') return tf('files.warn.nonImageMediaUnscanned')
    if (code === 'ner_degraded') return tf('files.warn.nerDegraded')
    if (code === 'text_encoding_fallback') return tf('files.warn.textEncodingFallback')
    if (code === 'text_encoding_utf8_fallback') return tf('files.warn.textEncodingUtf8Fallback')
    if (code === 'embedded_images_ocr_unavailable') return tf('files.warn.embeddedOcrUnavailable')
    if (code === 'embedded_images_covered') return tf('files.warn.embeddedCovered')
    if (code === 'image_ocr_failed_full_cover') return tf('files.warn.imageOcrFailed')
    if (code === 'page_kept_with_unmasked_hits') return tf('files.warn.pagesKeptUnmasked')
    const m = PAGE_WARN_RX.exec(code)
    if (m) {
      const page = Number(m[1])
      if (m[2] === 'full_cover') return tf('files.warn.pageFullCover', { page })
      if (m[2] === 'ocr_failed_full_cover') return tf('files.warn.pageOcrFailed', { page })
      return tf('files.warn.pageKeptUnmasked', { page })
    }
    return tf('files.warn.unknown', { code })
  })
}

function calcProgressPct(progress: Record<string, unknown> | undefined): {
  stage: string
  cur: number
  total: number
  pct: number
  indeterminate: boolean
} {
  const stage = typeof progress?.stage === 'string' ? progress.stage : ''
  const cur = Number(progress?.current || 0)
  const total = Number(progress?.total || 0)
  const indeterminate = Boolean(progress?.indeterminate)
  const rawPct = progress?.pct
  const pct = typeof rawPct === 'number' && Number.isFinite(rawPct)
    ? Math.max(0, Math.min(99, Math.round(rawPct)))
    : (total > 0 ? Math.max(0, Math.min(99, Math.round((cur / total) * 100))) : 0)
  return { stage, cur, total, pct, indeterminate }
}

export default function FilesPage() {
  const { t, tf } = useI18n()
  const [caps, setCaps] = useState<FilesCapabilities | null>(null)
  const [capsError, setCapsError] = useState('')
  const [loading, setLoading] = useState(true)
  const [jobs, setJobs] = useState<FileJobView[]>([])
  const [selected, setSelected] = useState<FileJobView | null>(null)
  const [viewMode, setViewMode] = useState<'single' | 'merged'>('single')

  // 单文件命中与跨文件去重命中
  const [hits, setHits] = useState<FileHitView[]>([])
  const [hitsBusy, setHitsBusy] = useState(false)
  const [hitsError, setHitsError] = useState('')
  const [mergedHits, setMergedHits] = useState<MergedFileHitView[]>([])
  const [mergedTotalOcc, setMergedTotalOcc] = useState(0)
  const [mergedBusy, setMergedBusy] = useState(false)
  const [mergedError, setMergedError] = useState('')

  // 按 jobId 持久化编辑态，切换任务或往返统一视图不丢改动
  const [replacesByJob, setReplacesByJob] = useState<Record<string, Record<string, string>>>({})
  const [keepsByJob, setKeepsByJob] = useState<Record<string, Record<string, boolean>>>({})
  const [redactionsByJob, setRedactionsByJob] = useState<Record<string, Redaction[]>>({})
  const [dismissedByJob, setDismissedByJob] = useState<Record<string, Record<string, boolean>>>({})
  const [optionsByJob, setOptionsByJob] = useState<Record<string, ApplyOptions>>({})

  // 命中清单筛选
  const [hitSearch, setHitSearch] = useState('')
  const [hitLabelFilter, setHitLabelFilter] = useState('ALL')
  const [hitStatusFilter, setHitStatusFilter] = useState<'all' | 'edited' | 'kept'>('all')

  const [page, setPage] = useState(1)
  const [preview, setPreview] = useState('')
  const [autoBoxes, setAutoBoxes] = useState<PreviewBox[]>([])
  const [previewError, setPreviewError] = useState('')
  const [previewBusy, setPreviewBusy] = useState(false)
  const [previewTick, setPreviewTick] = useState(0)
  const [tool, setTool] = useState<'rect' | 'brush'>('rect')
  const [mode, setMode] = useState<'manual' | 'auto'>('manual')
  const modeTouchedRef = useRef(false)

  const [notice, setNotice] = useState('')
  const [savedPath, setSavedPath] = useState('')
  const [uploadError, setUploadError] = useState('')
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState<{ cur: number; total: number } | null>(null)
  const [busy, setBusy] = useState(false)
  const [history, setHistory] = useState<FileHistoryEntry[]>([])
  const [historyOpen, setHistoryOpen] = useState(false)

  const dragRef = useRef<{ x: number; y: number } | null>(null)
  const brushRef = useRef<[number, number][]>([])
  const [draft, setDraft] = useState<Redaction | null>(null)
  const inputRef = useRef<HTMLInputElement | null>(null)
  const hitScrollRef = useRef<HTMLDivElement | null>(null)

  // 自动批量扫描队列与自动进入统一清单开关
  const autoScanIdsRef = useRef<Set<string>>(new Set())
  const dispatchingIdsRef = useRef<Set<string>>(new Set())
  const retryTimerRef = useRef<number | null>(null)
  const autoSwitchMergedRef = useRef(false)
  const [queueTick, setQueueTick] = useState(0)

  useEffect(() => () => {
    if (retryTimerRef.current !== null) window.clearTimeout(retryTimerRef.current)
  }, [])

  // 能力探测（G801）
  // @guard G801 关闭/探测失败只给空态，不渲染上传与列表
  const loadCaps = useCallback(() => {
    setLoading(true)
    getCapabilities()
      .then((res) => {
        setCaps(res)
        setCapsError('')
        if (!modeTouchedRef.current) {
          setMode(res.ocr_available ? 'auto' : 'manual')
        }
      })
      .catch((e: unknown) => {
        setCaps(null)
        setCapsError(String((e as Error)?.message || e))
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { loadCaps() }, [loadCaps])

  const refreshHistory = useCallback(() => {
    listHistory()
      .then((res) => setHistory(res.history || []))
      .catch(() => { /* 历史读取失败不阻断当前队列视图 */ })
  }, [])

  const refreshJobs = useCallback(() => {
    listJobs()
      .then((res) => {
        const nextJobs = res.jobs || []
        setJobs(nextJobs)
        setSelected((prev) => (prev ? nextJobs.find((j) => j.id === prev.id) || prev : prev))
      })
      .catch(() => { /* 列表失败保留旧值 */ })
    refreshHistory()
  }, [refreshHistory])

  useEffect(() => {
    if (!caps?.enabled) return
    refreshJobs()
  }, [caps?.enabled, refreshJobs])

  // 轮询选中任务：非终态 1s；终态停止（G803）
  // @guard G803 状态徽标 + 终态停轮询
  const jobId = selected?.id
  const jobStatus = selected?.status
  const jobCarrier = selected?.carrier
  const jobPages = selected?.page_count
  useEffect(() => {
    if (!jobId || !jobStatus || !NON_TERMINAL.has(jobStatus)) return
    const timer = window.setInterval(() => {
      getJob(jobId)
        .then((res) => {
          setSelected(res.job)
          setJobs((prev) => prev.map((j) => (j.id === res.job.id ? res.job : j)))
          if (!NON_TERMINAL.has(res.job.status)) refreshHistory()
        })
        .catch(() => { /* 轮询失败不打断页面 */ })
    }, 1000)
    return () => window.clearInterval(timer)
  }, [jobId, jobStatus, refreshHistory])

  // 后台其他活跃任务同步轮询（仅当存在排队/扫描/生成中任务或本地待派发队列时运行）
  const hasActiveJobs = jobs.some((j) => NON_TERMINAL.has(j.status) && j.status !== 'ready')
    || autoScanIdsRef.current.size > 0
    || dispatchingIdsRef.current.size > 0
  useEffect(() => {
    if (!caps?.enabled || !hasActiveJobs) return
    const timer = window.setInterval(() => {
      listJobs()
        .then((res) => {
          const nextJobs = res.jobs || []
          setJobs(nextJobs)
          setSelected((prev) => (prev ? nextJobs.find((j) => j.id === prev.id) || prev : prev))
          if (!nextJobs.some((j) => NON_TERMINAL.has(j.status) && j.status !== 'ready')) {
            refreshHistory()
          }
        })
        .catch(() => {})
    }, 1000)
    return () => window.clearInterval(timer)
  }, [caps?.enabled, hasActiveJobs, refreshHistory])

  // 自动队列调度：同时计入本地在飞 POST /scan，避免并发刷新触发后端 queue_max 429 误报
  useEffect(() => {
    if (!caps?.enabled) return
    const queueLimit = Math.max(1, Number(caps.queue_max || 8))
    const activeIds = new Set<string>(dispatchingIdsRef.current)
    for (const j of jobs) {
      if (j.status === 'queued' || j.status === 'scanning') activeIds.add(j.id)
    }
    const avail = queueLimit - activeIds.size
    if (avail <= 0) return
    const readyToStart = jobs
      .filter((j) => j.status === 'ready' && autoScanIdsRef.current.has(j.id) && !dispatchingIdsRef.current.has(j.id))
      .slice(0, avail)
    if (readyToStart.length === 0) return
    for (const j of readyToStart) {
      autoScanIdsRef.current.delete(j.id)
      dispatchingIdsRef.current.add(j.id)
      let rateLimited = false
      void scanJob(j.id, mode)
        .then((res) => {
          setJobs((prev) => prev.map((x) => (x.id === res.job.id ? res.job : x)))
          setSelected((prev) => (prev?.id === res.job.id ? res.job : prev))
        })
        .catch((e: unknown) => {
          if ((e as { code?: string })?.code === 'FILE_7402') {
            rateLimited = true
            autoScanIdsRef.current.add(j.id)
            if (retryTimerRef.current === null) {
              retryTimerRef.current = window.setTimeout(() => {
                retryTimerRef.current = null
                setQueueTick((n) => n + 1)
              }, 1000)
            }
            return
          }
          setNotice(describeRequestError(e, tf))
        })
        .finally(() => {
          dispatchingIdsRef.current.delete(j.id)
          if (!rateLimited && autoScanIdsRef.current.size > 0) {
            setQueueTick((n) => n + 1)
          }
        })
    }
  }, [caps?.enabled, caps?.queue_max, jobs, mode, queueTick, tf])

  const reviewJobs = useMemo(() => jobs.filter((j) => j.status === 'awaiting_review'), [jobs])
  const readyJobs = useMemo(() => jobs.filter((j) => j.status === 'ready'), [jobs])
  const doneJobs = useMemo(() => jobs.filter((j) => j.status === 'done'), [jobs])
  const finishedJobs = useMemo(() => jobs.filter((j) => TERMINAL.has(j.status)), [jobs])

  // 批次自动扫描全部完成后，自动展开跨文件统一清单
  useEffect(() => {
    if (!autoSwitchMergedRef.current) return
    const stillPending = jobs.some((j) => ['created', 'probing', 'ready', 'queued', 'scanning'].includes(j.status))
    if (!stillPending && reviewJobs.length >= 2) {
      autoSwitchMergedRef.current = false
      setViewMode('merged')
    }
  }, [jobs, reviewJobs.length])

  // 当待确认文件不足 2 个时，如果停在统一视图则回到单文件视图
  useEffect(() => {
    if (viewMode === 'merged' && reviewJobs.length < 2) {
      setViewMode('single')
    }
  }, [viewMode, reviewJobs.length])

  // 命中清单（G804）
  // @guard G804 凭据只读，非凭据才渲染输入与保留开关
  useEffect(() => {
    if (!jobId || jobStatus !== 'awaiting_review') return
    setHitsBusy(true)
    setHitsError('')
    getHits(jobId)
      .then((res) => {
        setHits(res.hits || [])
      })
      .catch((e: unknown) => setHitsError(String((e as Error)?.message || e)))
      .finally(() => setHitsBusy(false))
  }, [jobId, jobStatus])

  // 跨文件统一去重命中清单
  const reviewJobIdsKey = useMemo(() => reviewJobs.map((j) => j.id).join(','), [reviewJobs])
  useEffect(() => {
    if (viewMode !== 'merged' || reviewJobs.length === 0) return
    const ids = reviewJobIdsKey ? reviewJobIdsKey.split(',') : []
    if (ids.length === 0) return
    setMergedBusy(true)
    setMergedError('')
    getMergedHits(ids)
      .then((res) => {
        setMergedHits(res.hits || [])
        setMergedTotalOcc(Number(res.total_occurrences || 0))
      })
      .catch((e: unknown) => setMergedError(describeRequestError(e, tf)))
      .finally(() => setMergedBusy(false))
  }, [viewMode, reviewJobIdsKey, reviewJobs.length, tf])

  // 切换任务或视图模式时重置标签筛选，防旧标签把新文件清空
  useEffect(() => {
    setHitLabelFilter('ALL')
  }, [jobId, viewMode])

  // 预览（G805）
  // @guard G805 页码夹在 1..page_count，失败给占位
  useEffect(() => {
    if (viewMode !== 'single' || !jobId || !jobCarrier || !VISUAL.has(jobCarrier) || jobStatus !== 'awaiting_review') {
      setPreview('')
      setAutoBoxes([])
      return
    }
    if (!jobPages || page < 1 || page > Number(jobPages)) return
    setPreviewBusy(true)
    setPreviewError('')
    getPreview(jobId, page)
      .then((res) => {
        setPreview(res.data)
        setAutoBoxes(res.boxes || [])
      })
      .catch((e: unknown) => {
        setPreview('')
        setAutoBoxes([])
        setPreviewError(describeRequestError(e, tf))
      })
      .finally(() => setPreviewBusy(false))
  }, [viewMode, jobId, jobStatus, jobCarrier, jobPages, page, previewTick, tf])

  const replaces = useMemo(
    () => (jobId ? replacesByJob[jobId] || EMPTY_STR_MAP : EMPTY_STR_MAP),
    [jobId, replacesByJob],
  )
  const keeps = useMemo(
    () => (jobId ? keepsByJob[jobId] || EMPTY_BOOL_MAP : EMPTY_BOOL_MAP),
    [jobId, keepsByJob],
  )
  const redactions = useMemo(
    () => (jobId ? redactionsByJob[jobId] || EMPTY_REDACTIONS : EMPTY_REDACTIONS),
    [jobId, redactionsByJob],
  )
  const dismissedBoxes = useMemo(
    () => (jobId ? dismissedByJob[jobId] || EMPTY_BOOL_MAP : EMPTY_BOOL_MAP),
    [jobId, dismissedByJob],
  )
  const options = useMemo(
    () => (jobId ? optionsByJob[jobId] || DEFAULT_APPLY_OPTIONS : DEFAULT_APPLY_OPTIONS),
    [jobId, optionsByJob],
  )

  const setJobReplace = (jid: string, hitId: string, val: string) => {
    setReplacesByJob((prev) => ({
      ...prev,
      [jid]: { ...(prev[jid] || {}), [hitId]: val },
    }))
  }
  const setJobKeep = (jid: string, hitId: string, val: boolean) => {
    setKeepsByJob((prev) => ({
      ...prev,
      [jid]: { ...(prev[jid] || {}), [hitId]: val },
    }))
  }
  const setSelectedOptions = (updater: (cur: ApplyOptions) => ApplyOptions) => {
    if (!selected) return
    const jid = selected.id
    setOptionsByJob((prev) => ({
      ...prev,
      [jid]: updater(prev[jid] || defaultOptions()),
    }))
  }

  const select = (job: FileJobView) => {
    autoSwitchMergedRef.current = false
    setViewMode('single')
    setSelected(job)
    setPage(1)
    setNotice('')
    setSavedPath('')
    setHits([])
    setPreview('')
    setAutoBoxes([])
  }

  const validateClientFile = (file: File): string | null => {
    if (!caps) return null
    // @guard G802 超上限前端先拦，不发请求
    const limit = (caps.max_size_mb || 1024) * 1024 * 1024
    if (file.size > limit) {
      return `${file.name}: ${tf('files.tooLarge', { mb: caps.max_size_mb })}`
    }
    const dot = file.name.lastIndexOf('.')
    const ext = dot >= 0 ? file.name.slice(dot + 1).toLowerCase() : ''
    if ((caps.text_extensions || []).includes(ext)) {
      const textLimit = (caps.max_text_mb || 128) * 1024 * 1024
      if (file.size > textLimit) {
        return `${file.name}: ${tf('files.textTooLarge', { mb: caps.max_text_mb })}`
      }
    }
    return null
  }

  const makeBatchId = () => `fb_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`

  const enqueueBatchCreated = (created: FileJobView[], autoScan: boolean) => {
    if (created.length === 0) return
    setJobs((prev) => {
      const seen = new Set(created.map((c) => c.id))
      return [...created, ...prev.filter((j) => !seen.has(j.id))]
    })
    setSelected(created[0])
    setPage(1)
    setNotice('')
    setSavedPath('')
    if (autoScan) {
      autoSwitchMergedRef.current = created.length >= 2
      for (const j of created) {
        if (j.status === 'ready') autoScanIdsRef.current.add(j.id)
      }
      setQueueTick((n) => n + 1)
    } else {
      setViewMode('single')
    }
    refreshJobs()
  }

  const uploadFiles = async (fileList: File[]) => {
    if (!caps || uploading || fileList.length === 0) return
    setUploadError('')
    setUploading(true)
    const isMulti = fileList.length > 1
    const batchId = isMulti ? makeBatchId() : undefined
    const created: FileJobView[] = []
    const errs: string[] = []
    try {
      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i]
        setUploadProgress(isMulti ? { cur: i + 1, total: fileList.length } : null)
        const vErr = validateClientFile(file)
        if (vErr) {
          errs.push(vErr)
          continue
        }
        try {
          const res = await createJob(file, batchId)
          created.push(res.job)
        } catch (e: unknown) {
          errs.push(`${file.name}: ${describeRequestError(e, tf)}`)
        }
      }
      enqueueBatchCreated(created, isMulti)
      if (errs.length > 0) {
        setUploadError(
          errs.length === 1 && created.length === 0
            ? errs[0]
            : tf('files.uploadPartialFail', { msg: errs.slice(0, 3).join('; ') }),
        )
      }
    } finally {
      setUploading(false)
      setUploadProgress(null)
    }
  }

  const pickLocalFiles = async () => {
    if (!caps || uploading) return
    setUploadError('')
    try {
      const paths = await pickDesktopFiles(caps.extensions || [])
      if (paths.length === 0) return
      setUploading(true)
      const isMulti = paths.length > 1
      const batchId = isMulti ? makeBatchId() : undefined
      const created: FileJobView[] = []
      const errs: string[] = []
      for (let i = 0; i < paths.length; i++) {
        setUploadProgress(isMulti ? { cur: i + 1, total: paths.length } : null)
        try {
          const res = await createJobFromPath(paths[i], batchId)
          created.push(res.job)
        } catch (e: unknown) {
          errs.push(describeRequestError(e, tf))
        }
      }
      enqueueBatchCreated(created, isMulti)
      if (errs.length > 0) {
        setUploadError(
          errs.length === 1 && created.length === 0
            ? errs[0]
            : tf('files.uploadPartialFail', { msg: errs.slice(0, 3).join('; ') }),
        )
      }
    } catch (e: unknown) {
      setUploadError(describeRequestError(e, tf))
    } finally {
      setUploading(false)
      setUploadProgress(null)
    }
  }

  const onDragOver = (e: DragEvent) => {
    e.preventDefault()
  }
  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    const files = Array.from(e.dataTransfer.files || [])
    if (files.length > 0) void uploadFiles(files)
  }

  const clearJobDraft = (jid: string) => {
    setReplacesByJob((prev) => {
      if (!(jid in prev)) return prev
      const next = { ...prev }
      delete next[jid]
      return next
    })
    setKeepsByJob((prev) => {
      if (!(jid in prev)) return prev
      const next = { ...prev }
      delete next[jid]
      return next
    })
    setRedactionsByJob((prev) => {
      if (!(jid in prev)) return prev
      const next = { ...prev }
      delete next[jid]
      return next
    })
    setDismissedByJob((prev) => {
      if (!(jid in prev)) return prev
      const next = { ...prev }
      delete next[jid]
      return next
    })
    setOptionsByJob((prev) => {
      if (!(jid in prev)) return prev
      const next = { ...prev }
      delete next[jid]
      return next
    })
  }

  const doScan = async () => {
    if (!selected) return
    setBusy(true)
    setNotice('')
    clearJobDraft(selected.id)
    try {
      const res = await scanJob(selected.id, mode)
      setSelected(res.job)
      refreshJobs()
    } catch (e: unknown) {
      setNotice(describeRequestError(e, tf))
    } finally {
      setBusy(false)
    }
  }

  const doScanAllReady = () => {
    if (readyJobs.length === 0) return
    setNotice('')
    autoSwitchMergedRef.current = readyJobs.length + reviewJobs.length >= 2
    for (const j of readyJobs) {
      autoScanIdsRef.current.add(j.id)
    }
    setQueueTick((n) => n + 1)
  }

  const buildEditsForJob = (jid: string): { edits: TextEdit[]; valid: boolean } => {
    const rep = replacesByJob[jid] || {}
    const kp = keepsByJob[jid] || {}
    const edits: TextEdit[] = []
    const seenIds = new Set<string>()
    for (const [hid, kept] of Object.entries(kp)) {
      if (kept) {
        edits.push({ hit_id: hid, action: 'keep' })
        seenIds.add(hid)
      }
    }
    for (const [hid, rawText] of Object.entries(rep)) {
      if (seenIds.has(hid)) continue
      const text = (rawText || '').trim()
      if (!text) continue
      if (text.length > 64 || /[\r\n]/.test(text) || text.includes('{{') || text.includes('}}')) {
        return { edits: [], valid: false }
      }
      edits.push({ hit_id: hid, action: 'replace', text })
    }
    return { edits, valid: true }
  }

  const doApply = async () => {
    // @guard G807 edits/redactions/options 一次提交，失败按 code 提示
    if (!selected) return
    const edits: TextEdit[] = []
    for (const hit of hits) {
      if (!hit.editable) continue
      if (keeps[hit.hit_id]) {
        edits.push({ hit_id: hit.hit_id, action: 'keep' })
        continue
      }
      const text = (replaces[hit.hit_id] || '').trim()
      if (!text) continue
      if (text.length > 64 || /[\r\n]/.test(text) || text.includes('{{') || text.includes('}}')) {
        setNotice(t('files.badReplacement'))
        return
      }
      edits.push({ hit_id: hit.hit_id, action: 'replace', text })
    }
    setBusy(true)
    setNotice('')
    try {
      const res = await applyJob(selected.id, edits, redactions, options)
      setSelected(res.job)
      refreshJobs()
    } catch (e: unknown) {
      setNotice(describeRequestError(e, tf))
    } finally {
      setBusy(false)
    }
  }

  const doApplyAll = async () => {
    if (reviewJobs.length === 0) return
    const payloads: { job: FileJobView; edits: TextEdit[] }[] = []
    for (const j of reviewJobs) {
      const built = buildEditsForJob(j.id)
      if (!built.valid) {
        setNotice(t('files.badReplacement'))
        return
      }
      payloads.push({ job: j, edits: built.edits })
    }
    setBusy(true)
    setNotice('')
    setSavedPath('')
    let okCount = 0
    const errs: string[] = []
    try {
      for (const { job, edits } of payloads) {
        try {
          const res = await applyJob(
            job.id,
            edits,
            redactionsByJob[job.id] || [],
            optionsByJob[job.id] || defaultOptions(),
          )
          okCount += 1
          setJobs((prev) => prev.map((x) => (x.id === res.job.id ? res.job : x)))
          setSelected((prev) => (prev?.id === res.job.id ? res.job : prev))
        } catch (e: unknown) {
          errs.push(`${job.filename}: ${describeRequestError(e, tf)}`)
        }
      }
      refreshJobs()
      if (errs.length > 0) {
        setNotice(tf('files.batchApplyPartial', {
          ok: okCount,
          fail: errs.length,
          msg: errs.slice(0, 2).join('; '),
        }))
      }
    } finally {
      setBusy(false)
    }
  }

  const doCancel = async () => {
    // @guard G811 仅允许态可取消，取消后轮询自然停止
    if (!selected) return
    autoScanIdsRef.current.delete(selected.id)
    dispatchingIdsRef.current.delete(selected.id)
    try {
      const res = await cancelJob(selected.id)
      setSelected(res.job)
      refreshJobs()
    } catch (e: unknown) {
      setNotice(describeRequestError(e, tf))
    }
  }

  const doDelete = async () => {
    if (!selected) return
    if (!window.confirm(t('files.deleteConfirm'))) return
    const delId = selected.id
    autoScanIdsRef.current.delete(delId)
    dispatchingIdsRef.current.delete(delId)
    try {
      await deleteJob(delId)
      clearJobDraft(delId)
      setSelected(null)
      setJobs((prev) => prev.filter((j) => j.id !== delId))
    } catch (e: unknown) {
      setNotice(describeRequestError(e, tf))
    }
  }

  const doClearFinished = async () => {
    if (finishedJobs.length === 0) return
    if (!window.confirm(t('files.clearFinishedConfirm'))) return
    const targetIds = finishedJobs.map((j) => j.id)
    for (const jid of targetIds) {
      try {
        await deleteJob(jid)
        clearJobDraft(jid)
      } catch {
        // 单个清理失败继续其余任务
      }
    }
    setJobs((prev) => prev.filter((j) => !targetIds.includes(j.id)))
    if (selected && targetIds.includes(selected.id)) {
      setSelected(null)
    }
    refreshJobs()
  }

  const doDownload = async () => {
    // @guard G808 仅 done 可下载；nonce 换 URL，token 不进 URL
    if (!selected || selected.status !== 'done') return
    try {
      const dot = selected.filename.lastIndexOf('.')
      const suffix = t('files.maskedSuffix')
      const name = dot > 0
        ? `${selected.filename.slice(0, dot)}-${suffix}${selected.filename.slice(dot)}`
        : `${selected.filename}-${suffix}`
      await downloadJob(selected.id, name)
    } catch (e: unknown) {
      setNotice(describeRequestError(e, tf))
    }
  }

  const doDownloadZip = async () => {
    if (doneJobs.length === 0) return
    setNotice('')
    try {
      await downloadJobsZip(doneJobs.map((j) => j.id))
    } catch (e: unknown) {
      setNotice(describeRequestError(e, tf))
    }
  }

  const doSaveAs = async () => {
    if (!selected || selected.status !== 'done') return
    setNotice('')
    setSavedPath('')
    try {
      const dir = await pickDesktopDirectory()
      if (!dir) return
      const res = await saveJob(selected.id, dir, false)
      setSavedPath(tf('files.savedTo', { path: res.path || dir }))
    } catch (e: unknown) {
      setNotice(describeRequestError(e, tf))
    }
  }

  const doSaveAllAs = async () => {
    if (doneJobs.length === 0) return
    setNotice('')
    setSavedPath('')
    try {
      const dir = await pickDesktopDirectory()
      if (!dir) return
      let okCount = 0
      const errs: string[] = []
      for (const j of doneJobs) {
        try {
          await saveJob(j.id, dir, false)
          okCount += 1
        } catch (e: unknown) {
          errs.push(`${j.filename}: ${describeRequestError(e, tf)}`)
        }
      }
      if (errs.length === 0) {
        setSavedPath(tf('files.savedBatch', { ok: okCount, path: dir }))
      } else {
        setNotice(tf('files.savedBatchPartial', {
          ok: okCount,
          path: dir,
          fail: errs.length,
          msg: errs.slice(0, 2).join('; '),
        }))
      }
    } catch (e: unknown) {
      setNotice(describeRequestError(e, tf))
    }
  }

  // 画布（G806）：坐标 0~1
  const pointOf = (e: MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    return [
      Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width)),
      Math.max(0, Math.min(1, (e.clientY - rect.top) / rect.height)),
    ] as [number, number]
  }

  const pageAreas = useMemo(
    () => redactions.filter((r) => r.page === page),
    [redactions, page],
  )
  const visibleAutoBoxes = useMemo(() => {
    if (!selected || !autoBoxes.length) return []
    return autoBoxes.filter((b) => {
      if (!b.hit_id || !keeps[b.hit_id]) return true
      if (selected.carrier === 'pdf') return b.source !== 'text_layer'
      return false
    })
  }, [autoBoxes, keeps, selected])
  const hasFull = pageAreas.some((r) => r.kind === 'full')

  const onDown = (e: MouseEvent<SVGSVGElement>) => {
    // @guard G806 归一化坐标、rect/path 双工具、500 上限、整页遮盖互斥
    if (!selected || selected.status !== 'awaiting_review') return
    if (hasFull) {
      setNotice(t('files.fullCoverWarn'))
      return
    }
    if (pageAreas.length >= 500) {
      setNotice(t('files.tooManyAreas'))
      return
    }
    const p = pointOf(e)
    dragRef.current = { x: p[0], y: p[1] }
    if (tool === 'brush') brushRef.current = [p]
  }

  const onMove = (e: MouseEvent<SVGSVGElement>) => {
    if (!dragRef.current) return
    const p = pointOf(e)
    if (tool === 'rect') {
      const start = dragRef.current
      const rect: [number, number, number, number] = [
        Math.min(start.x, p[0]), Math.min(start.y, p[1]),
        Math.max(0.001, Math.abs(p[0] - start.x)), Math.max(0.001, Math.abs(p[1] - start.y)),
      ]
      setDraft({ id: 'draft', page, kind: 'rect', rect, source: 'manual' })
    } else {
      brushRef.current = [...brushRef.current, p]
      setDraft({ id: 'draft', page, kind: 'path', points: brushRef.current, width: 0.006, source: 'manual' })
    }
  }

  const toggleDismissAutoBox = (boxId: string) => {
    if (!selected) return
    const jid = selected.id
    setDismissedByJob((prev) => {
      const cur = prev[jid] || {}
      const nextJob = { ...cur, [boxId]: !cur[boxId] }
      const list = Object.keys(nextJob).filter((k) => nextJob[k])
      setOptionsByJob((opPrev) => ({
        ...opPrev,
        [jid]: { ...(opPrev[jid] || defaultOptions()), dismissed_boxes: list },
      }))
      return { ...prev, [jid]: nextJob }
    })
  }

  const restorePageAutoBoxes = () => {
    if (!selected) return
    const jid = selected.id
    setDismissedByJob((prev) => {
      const nextJob = { ...(prev[jid] || {}) }
      for (const b of visibleAutoBoxes) {
        delete nextJob[b.id]
      }
      const list = Object.keys(nextJob).filter((k) => nextJob[k])
      setOptionsByJob((opPrev) => ({
        ...opPrev,
        [jid]: { ...(opPrev[jid] || defaultOptions()), dismissed_boxes: list },
      }))
      return { ...prev, [jid]: nextJob }
    })
  }

  const pageDismissedCount = visibleAutoBoxes.filter((b) => dismissedBoxes[b.id]).length

  const onUp = (allowClick = true) => {
    const startPt = dragRef.current
    const hadRectDraft = draft?.kind === 'rect' && (draft.rect?.[2] || 0) > 0.002 && (draft.rect?.[3] || 0) > 0.002
    const hadPathDraft = draft?.kind === 'path' && (draft.points?.length || 0) >= 2
    if (selected && (hadRectDraft || hadPathDraft) && draft) {
      const jid = selected.id
      setRedactionsByJob((prev) => {
        const list = prev[jid] || []
        return { ...prev, [jid]: [...list, { ...draft, id: 'r' + (list.length + 1) }] }
      })
    } else if (allowClick && startPt) {
      const matched = visibleAutoBoxes.filter((b) => {
        if (b.kind !== 'rect' || b.can_dismiss === false || !b.rect) return false
        const [bx, by, bw, bh] = b.rect
        return startPt.x >= bx && startPt.x <= bx + bw && startPt.y >= by && startPt.y <= by + bh
      })
      if (matched.length > 0) {
        const target = matched[matched.length - 1]
        toggleDismissAutoBox(target.id)
      }
    }
    setDraft(null)
    dragRef.current = null
    brushRef.current = []
  }

  const clearAreas = () => {
    if (!selected) return
    const jid = selected.id
    setRedactionsByJob((prev) => ({
      ...prev,
      [jid]: (prev[jid] || []).filter((r) => r.page !== page),
    }))
  }

  // 单文件 / 统一视图的当前命中列表与双向同步读写
  const isMergedView = viewMode === 'merged' && reviewJobs.length >= 2

  const getSingleReplace = useCallback(
    (h: FileHitView) => replaces[h.hit_id] || '',
    [replaces],
  )
  const getSingleKeep = useCallback(
    (h: FileHitView) => !!keeps[h.hit_id],
    [keeps],
  )

  const getMergedReplace = useCallback((m: MergedFileHitView) => {
    for (const f of m.files) {
      const v = replacesByJob[f.job_id]?.[f.hit_id]
      if (v) return v
    }
    return ''
  }, [replacesByJob])

  const getMergedKeep = useCallback(
    (m: MergedFileHitView) => m.files.length > 0 && m.files.every((f) => !!keepsByJob[f.job_id]?.[f.hit_id]),
    [keepsByJob],
  )

  const setMergedReplace = (m: MergedFileHitView, val: string) => {
    setReplacesByJob((prev) => {
      const next = { ...prev }
      for (const f of m.files) {
        next[f.job_id] = { ...(next[f.job_id] || {}), [f.hit_id]: val }
      }
      return next
    })
  }

  const setMergedKeep = (m: MergedFileHitView, val: boolean) => {
    setKeepsByJob((prev) => {
      const next = { ...prev }
      for (const f of m.files) {
        next[f.job_id] = { ...(next[f.job_id] || {}), [f.hit_id]: val }
      }
      return next
    })
  }

  const labelCounts = useMemo(() => {
    const map = new Map<string, number>()
    const list = isMergedView ? mergedHits : hits
    for (const item of list) {
      const lbl = item.label || '—'
      map.set(lbl, (map.get(lbl) || 0) + 1)
    }
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1])
  }, [isMergedView, mergedHits, hits])

  const filteredSingleHits = useMemo(() => {
    if (isMergedView) return []
    const q = hitSearch.trim().toLowerCase()
    return hits.filter((hit) => {
      const lbl = hit.label || '—'
      if (hitLabelFilter !== 'ALL' && lbl !== hitLabelFilter) return false
      const rep = getSingleReplace(hit)
      const kept = getSingleKeep(hit)
      if (hitStatusFilter === 'kept' && !kept) return false
      if (hitStatusFilter === 'edited' && (kept || !rep.trim())) return false
      if (!q) return true
      const hay = [
        hit.original || '',
        hit.preview || '',
        lbl,
        rep,
        ...(hit.locations || []),
      ].join(' ').toLowerCase()
      return hay.includes(q)
    })
  }, [isMergedView, hits, hitSearch, hitLabelFilter, hitStatusFilter, getSingleReplace, getSingleKeep])

  const filteredMergedHits = useMemo(() => {
    if (!isMergedView) return []
    const q = hitSearch.trim().toLowerCase()
    return mergedHits.filter((hit) => {
      const lbl = hit.label || '—'
      if (hitLabelFilter !== 'ALL' && lbl !== hitLabelFilter) return false
      const rep = getMergedReplace(hit)
      const kept = getMergedKeep(hit)
      if (hitStatusFilter === 'kept' && !kept) return false
      if (hitStatusFilter === 'edited' && (kept || !rep.trim())) return false
      if (!q) return true
      const hay = [
        hit.original || '',
        hit.preview || '',
        lbl,
        rep,
        ...(hit.locations || []),
        ...hit.files.map((f) => f.filename),
      ].join(' ').toLowerCase()
      return hay.includes(q)
    })
  }, [isMergedView, mergedHits, hitSearch, hitLabelFilter, hitStatusFilter, getMergedReplace, getMergedKeep])

  const activeTotalCount = isMergedView ? mergedHits.length : hits.length
  const activeFilteredCount = isMergedView ? filteredMergedHits.length : filteredSingleHits.length
  const singleTotalOcc = useMemo(
    () => hits.reduce((sum, h) => sum + Number(h.count || 1), 0),
    [hits],
  )

  const hitVirtualizer = useVirtualizer({
    count: activeFilteredCount,
    getScrollElement: () => hitScrollRef.current,
    estimateSize: () => 56,
    overscan: 8,
  })

  const bulkUpdateFiltered = (action: 'keep' | 'mask' | 'clear') => {
    if (isMergedView) {
      const targets = filteredMergedHits.filter((h) => h.editable)
      if (targets.length === 0) return
      if (action === 'clear') {
        setReplacesByJob((prev) => {
          const next = { ...prev }
          for (const h of targets) {
            for (const f of h.files) {
              if (!next[f.job_id]) continue
              const copy = { ...next[f.job_id] }
              delete copy[f.hit_id]
              next[f.job_id] = copy
            }
          }
          return next
        })
        return
      }
      const keepVal = action === 'keep'
      setKeepsByJob((prev) => {
        const next = { ...prev }
        for (const h of targets) {
          if (keepVal && !h.can_keep) continue
          for (const f of h.files) {
            next[f.job_id] = { ...(next[f.job_id] || {}), [f.hit_id]: keepVal }
          }
        }
        return next
      })
      return
    }
    if (!selected) return
    const jid = selected.id
    const targets = filteredSingleHits.filter((h) => h.editable)
    if (targets.length === 0) return
    if (action === 'clear') {
      setReplacesByJob((prev) => {
        const copy = { ...(prev[jid] || {}) }
        for (const h of targets) delete copy[h.hit_id]
        return { ...prev, [jid]: copy }
      })
      return
    }
    const keepVal = action === 'keep'
    setKeepsByJob((prev) => {
      const copy = { ...(prev[jid] || {}) }
      for (const h of targets) {
        if (keepVal && !h.can_keep) continue
        copy[h.hit_id] = keepVal
      }
      return { ...prev, [jid]: copy }
    })
  }

  const desktopMode = isDesktopApp()
  const canScan = selected?.status === 'ready'
  const canApply = selected?.status === 'awaiting_review'
  const showApplyOptions = canApply && (
    selected?.carrier === 'pdf'
    || selected?.carrier === 'image'
    || (selected?.carrier === 'ooxml' && (
      Number(selected.coverage?.embedded_objects_present || 0) > 0
      || Number(selected.coverage?.non_image_media_present || 0) > 0
    ))
  )
  const canDownload = selected?.status === 'done'
  const canCancel = selected ? ['queued', 'scanning', 'applying'].includes(selected.status) : false
  const coverageLines = selected ? describeCoverage(selected.coverage || {}, selected.carrier, tf) : []
  const warningLines = selected ? describeWarnings(selected.warnings || [], tf) : []
  const embeddedHandled = Number(selected?.coverage?.masked_embedded_images || 0) > 0
    || Number(selected?.coverage?.covered_embedded_images || 0) > 0
  const selProg = calcProgressPct(selected ? selected.progress : undefined)

  if (loading) {
    // @guard G809 加载态有骨架/文案，不渲染空白表格
    return (
      <div className="space-y-4">
        <PageHeader title={t('nav.files')} subtitle={t('files.subtitle')} />
        <Card><CardContent className="flex items-center gap-2 p-6 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> {t('files.loading')}
        </CardContent></Card>
      </div>
    )
  }

  if (capsError || !caps?.enabled) {
    return (
      <div className="space-y-4">
        <PageHeader title={t('nav.files')} subtitle={t('files.subtitle')} />
        <Card><CardContent className="space-y-3 p-6">
          <div className="flex items-center gap-2 text-sm font-medium">
            <AlertTriangle className="h-4 w-4" /> {t('files.disabled')}
          </div>
          <p className="text-[13px] text-muted-foreground">{t('files.disabledHint')}</p>
          <Button variant="outline" onClick={loadCaps}>
            <RefreshCw className="mr-1.5 h-4 w-4" /> {t('files.retry')}
          </Button>
          {capsError ? <p className="text-[12px] text-muted-foreground">{capsError}</p> : null}
        </CardContent></Card>
      </div>
    )
  }

  const accept = (caps.extensions || []).map((x) => '.' + x).join(',')

  const renderHitFilterBar = () => (
    <div className="space-y-2 pb-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="relative min-w-[200px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            className="h-8 pl-8 pr-7 text-[12px]"
            placeholder={t('files.searchPlaceholder')}
            value={hitSearch}
            onChange={(e) => setHitSearch(e.target.value)}
          />
          {hitSearch ? (
            <button
              type="button"
              onClick={() => setHitSearch('')}
              className="absolute right-2 top-2 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          ) : null}
        </div>
        <Select value={hitStatusFilter} onValueChange={(v) => setHitStatusFilter(v as 'all' | 'edited' | 'kept')}>
          <SelectTrigger className="h-8 w-[124px] text-[12px]"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('files.filterStatusAll')}</SelectItem>
            <SelectItem value="edited">{t('files.filterStatusEdited')}</SelectItem>
            <SelectItem value="kept">{t('files.filterStatusKept')}</SelectItem>
          </SelectContent>
        </Select>
        <div className="flex flex-wrap items-center gap-1">
          <Button type="button" variant="outline" size="sm" className="h-8 px-2 text-[11px]"
            onClick={() => bulkUpdateFiltered('keep')}>
            {t('files.bulkKeepAll')}
          </Button>
          <Button type="button" variant="outline" size="sm" className="h-8 px-2 text-[11px]"
            onClick={() => bulkUpdateFiltered('mask')}>
            {t('files.bulkMaskAll')}
          </Button>
          <Button type="button" variant="ghost" size="sm" className="h-8 px-2 text-[11px]"
            onClick={() => bulkUpdateFiltered('clear')}>
            {t('files.bulkClearReplace')}
          </Button>
        </div>
      </div>

      {labelCounts.length > 1 ? (
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={() => setHitLabelFilter('ALL')}
            className={`rounded-full border px-2.5 py-0.5 text-[11px] transition ${
              hitLabelFilter === 'ALL'
                ? 'border-primary bg-primary/10 font-medium text-primary-ink'
                : 'border-border/70 text-muted-foreground hover:bg-muted/60 hover:text-foreground'
            }`}
          >
            {t('files.filterAll')} ({activeTotalCount})
          </button>
          {labelCounts.map(([lbl, cnt]) => (
            <button
              key={lbl}
              type="button"
              onClick={() => setHitLabelFilter(lbl)}
              className={`rounded-full border px-2.5 py-0.5 text-[11px] transition ${
                hitLabelFilter === lbl
                  ? 'border-primary bg-primary/10 font-medium text-primary-ink'
                  : 'border-border/70 text-muted-foreground hover:bg-muted/60 hover:text-foreground'
              }`}
            >
              {lbl} ({cnt})
            </button>
          ))}
        </div>
      ) : null}
    </div>
  )

  return (
    <div className="space-y-4">
      <PageHeader
        title={t('nav.files')}
        subtitle={t('files.subtitle')}
        actions={(
          <div className="flex flex-wrap items-center gap-2">
            {readyJobs.length >= 2 ? (
              <Button variant="outline" size="sm" onClick={doScanAllReady}>
                <Play className="mr-1.5 h-3.5 w-3.5" /> {tf('files.scanAll', { n: readyJobs.length })}
              </Button>
            ) : null}
            {reviewJobs.length >= 2 ? (
              <Button size="sm" onClick={doApplyAll} disabled={busy}>
                <ShieldCheck className="mr-1.5 h-4 w-4" /> {tf('files.applyAll', { n: reviewJobs.length })}
              </Button>
            ) : null}
            {doneJobs.length >= 2 ? (
              <Button variant="outline" size="sm" onClick={doDownloadZip}>
                <Archive className="mr-1.5 h-4 w-4" /> {tf('files.downloadZip', { n: doneJobs.length })}
              </Button>
            ) : null}
            {doneJobs.length >= 2 && caps.path_source && desktopMode ? (
              <Button variant="outline" size="sm" onClick={doSaveAllAs}>
                <FolderOpen className="mr-1.5 h-4 w-4" /> {tf('files.saveAllAs', { n: doneJobs.length })}
              </Button>
            ) : null}
            <Button variant="outline" size="sm" onClick={() => { refreshJobs(); loadCaps() }}>
              <RefreshCw className="mr-1.5 h-4 w-4" /> {t('files.refresh')}
            </Button>
          </div>
        )}
      />

      <Card data-feature-id="files-dropzone">
        <CardContent className="p-4">
          <div
            className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-border/70 px-4 py-6 text-center transition hover:bg-muted/40"
            onDragOver={onDragOver}
            onDrop={onDrop}
            onClick={() => inputRef.current?.click()}
          >
            <UploadCloud className="h-8 w-8 text-muted-foreground" />
            <div className="text-sm font-medium">{t('files.dropTitle')}</div>
            <div className="text-[12px] text-muted-foreground">
              {tf('files.dropHint', { mb: caps.max_size_mb, exts: accept || '—' })}
            </div>
            {caps.path_source && desktopMode ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={uploading}
                onClick={(e) => {
                  e.stopPropagation()
                  void pickLocalFiles()
                }}
              >
                <FolderOpen className="mr-1.5 h-4 w-4" /> {t('files.pickLocalFile')}
              </Button>
            ) : null}
            {uploading ? (
              <div className="flex items-center gap-1.5 text-[12px] text-muted-foreground">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                <span>
                  {uploadProgress
                    ? tf('files.uploadingProgress', uploadProgress)
                    : t('files.uploading')}
                </span>
              </div>
            ) : null}
            {uploadError ? <div className="text-[12px] text-destructive">{uploadError}</div> : null}
            <input
              ref={inputRef}
              type="file"
              multiple
              className="hidden"
              accept={accept}
              onChange={(e) => {
                const files = Array.from(e.target.files || [])
                if (files.length > 0) void uploadFiles(files)
                e.currentTarget.value = ''
              }}
            />
          </div>
        </CardContent>
      </Card>

      {jobs.length === 0 ? (
        <Card><CardContent className="p-8 text-center text-sm text-muted-foreground">
          {t('files.empty')}
        </CardContent></Card>
      ) : (
        <div className="grid items-start gap-4 lg:grid-cols-12">
          <Card className="flex flex-col lg:sticky lg:top-4 lg:col-span-4 lg:max-h-[calc(100vh-11rem)]">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="flex items-center gap-2 text-sm">
                <span>{t('files.list')}</span>
                <Badge variant="outline">{jobs.length}</Badge>
              </CardTitle>
              {finishedJobs.length > 0 ? (
                <Button variant="ghost" size="sm" className="h-7 px-2 text-[11px] text-muted-foreground"
                  onClick={doClearFinished}>
                  {t('files.clearFinished')}
                </Button>
              ) : null}
            </CardHeader>
            <CardContent className="flex-1 space-y-1.5 overflow-y-auto p-2">
              {reviewJobs.length >= 2 ? (
                <button
                  type="button"
                  onClick={() => setViewMode('merged')}
                  className={`w-full rounded-lg border px-3 py-2 text-left transition ${
                    isMergedView
                      ? 'border-primary/50 bg-primary/10'
                      : 'border-border/60 bg-muted/30 hover:bg-muted/60'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="flex items-center gap-1.5 text-[13px] font-semibold text-primary-ink">
                      <Layers className="h-3.5 w-3.5 shrink-0" />
                      {t('files.unifiedEntry')}
                    </span>
                    <Badge variant="secondary">{reviewJobs.length}</Badge>
                  </div>
                  <div className="mt-0.5 text-[11px] text-muted-foreground">
                    {tf('files.unifiedEntryDesc', { files: reviewJobs.length })}
                  </div>
                </button>
              ) : null}

              {jobs.map((job) => {
                const jp = calcProgressPct(job.progress)
                const active = !isMergedView && selected?.id === job.id
                return (
                  <button
                    key={job.id}
                    type="button"
                    onClick={() => select(job)}
                    className={`w-full rounded-lg px-3 py-2 text-left transition ${active ? 'bg-muted' : 'hover:bg-muted/50'}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="min-w-0 flex-1 truncate text-[13px] font-medium">{job.filename}</span>
                      <div className="flex shrink-0 items-center gap-1">
                        {job.status === 'scanning' && !jp.indeterminate && jp.pct > 0 ? (
                          <span className="tabular-nums text-[10px] text-muted-foreground">{jp.pct}%</span>
                        ) : null}
                        <Badge variant={statusTone(job.status)}>{t(`files.status.${job.status}`)}</Badge>
                      </div>
                    </div>
                    <div className="mt-1 flex items-center gap-2 text-[11px] text-muted-foreground">
                      <span>{tf('files.size', { n: (job.size / 1024).toFixed(0) })}</span>
                      {job.page_count ? <span>{tf('files.pages', { n: job.page_count })}</span> : null}
                      {job.hit_count ? <span>{tf('files.hitCount', { n: job.hit_count })}</span> : null}
                    </div>
                  </button>
                )
              })}
            </CardContent>
          </Card>

          <div className="min-w-0 space-y-4 lg:col-span-8">
            {isMergedView ? (
              <Card>
                <CardHeader className="space-y-2 pb-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <CardTitle className="flex items-center gap-2 text-sm">
                      <Layers className="h-4 w-4 text-primary-ink" />
                      <span>{t('files.unifiedTitle')}</span>
                      <Badge variant="secondary">
                        {tf('files.hitsSummaryMerged', {
                          items: mergedHits.length,
                          occ: mergedTotalOcc,
                          files: reviewJobs.length,
                        })}
                      </Badge>
                    </CardTitle>
                    <div className="flex flex-wrap items-center gap-2">
                      {selected ? (
                        <Button variant="outline" size="sm" onClick={() => setViewMode('single')}>
                          {t('files.backToSingle')}
                        </Button>
                      ) : null}
                      <Button size="sm" onClick={doApplyAll} disabled={busy}>
                        <ShieldCheck className="mr-1.5 h-4 w-4" /> {tf('files.applyAll', { n: reviewJobs.length })}
                      </Button>
                    </div>
                  </div>
                  <p className="text-[12px] text-muted-foreground">
                    {tf('files.unifiedSubtitle', { n: reviewJobs.length })}
                  </p>
                </CardHeader>
                <CardContent className="space-y-2">
                  {notice ? <p className="text-[12px] text-destructive">{notice}</p> : null}
                  {savedPath ? (
                    <p className="text-[12px] text-emerald-600 dark:text-emerald-400">{savedPath}</p>
                  ) : null}
                  {mergedBusy ? (
                    <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin" /> {t('files.loading')}
                    </div>
                  ) : mergedError ? (
                    <div className="text-[12px] text-destructive">{mergedError}</div>
                  ) : mergedHits.length === 0 ? (
                    <div className="py-6 text-[13px] text-muted-foreground">{t('files.noHits')}</div>
                  ) : (
                    <>
                      {renderHitFilterBar()}
                      {filteredMergedHits.length === 0 ? (
                        <div className="rounded-lg border border-border/60 p-6 text-center text-[12px] text-muted-foreground">
                          {t('files.noFilteredHits')}
                        </div>
                      ) : (
                        <div
                          ref={hitScrollRef}
                          className="max-h-[520px] min-h-[120px] overflow-y-auto rounded-lg border border-border/60"
                        >
                          <div className="relative" style={{ height: hitVirtualizer.getTotalSize() }}>
                            {hitVirtualizer.getVirtualItems().map((vi) => {
                              const hit = filteredMergedHits[vi.index]
                              if (!hit) return null
                              const repVal = getMergedReplace(hit)
                              const kept = getMergedKeep(hit)
                              const filesTitle = hit.files.map((f) => `${f.filename} (×${f.count})`).join('\n')
                              return (
                                <div
                                  key={hit.merge_id}
                                  data-index={vi.index}
                                  ref={hitVirtualizer.measureElement}
                                  className="absolute left-0 top-0 flex w-full flex-wrap items-center gap-2 border-b border-border/50 bg-card px-3 py-2"
                                  style={{ transform: `translateY(${vi.start}px)` }}
                                >
                                  <div className="flex min-w-0 flex-1 items-center gap-2">
                                    <Badge variant="secondary" className="shrink-0 text-[10px]">{hit.label || '—'}</Badge>
                                    <span
                                      className="min-w-0 flex-1 truncate font-mono text-[12.5px]"
                                      title={hit.editable ? (hit.original || '') : (hit.preview || '')}
                                    >
                                      {hit.editable ? (hit.original || '') : (hit.preview || '')}
                                    </span>
                                    <span
                                      className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-[10.5px] text-muted-foreground"
                                      title={filesTitle}
                                    >
                                      {tf('files.filesBadge', { n: hit.files.length })}
                                    </span>
                                    <span className="shrink-0 tabular-nums text-[11px] text-muted-foreground">×{hit.count}</span>
                                  </div>
                                  {hit.editable ? (
                                    <div className="flex shrink-0 items-center gap-2">
                                      <Input
                                        className="h-7 w-[180px] text-[12px]"
                                        placeholder={t('files.replacement')}
                                        value={repVal}
                                        disabled={kept}
                                        onChange={(e) => setMergedReplace(hit, e.target.value)}
                                      />
                                      {hit.can_keep ? (
                                        <label className="flex shrink-0 items-center gap-1.5 text-[11.5px]">
                                          <Switch
                                            className="scale-75"
                                            checked={kept}
                                            onCheckedChange={(v) => setMergedKeep(hit, v)}
                                          />
                                          {t('files.keep')}
                                        </label>
                                      ) : null}
                                    </div>
                                  ) : (
                                    <span className="shrink-0 text-[11px] text-muted-foreground">
                                      {tf('files.credential', { digest: hit.digest || '' })}
                                    </span>
                                  )}
                                </div>
                              )
                            })}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </CardContent>
              </Card>
            ) : !selected ? (
              <Card><CardContent className="space-y-2 p-8 text-center text-sm text-muted-foreground">
                {notice ? <p className="text-[12px] text-destructive">{notice}</p> : null}
                {savedPath ? (
                  <p className="text-[12px] text-emerald-600 dark:text-emerald-400">{savedPath}</p>
                ) : null}
                <p>{doneJobs.length >= 2 ? t('files.batchZipNotice') : t('files.selectJob')}</p>
              </CardContent></Card>
            ) : (
              <>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
                      <FileLock2 className="h-4 w-4 shrink-0" />
                      <span className="min-w-0 truncate">{selected.filename}</span>
                      <Badge variant={statusTone(selected.status)}>{t(`files.status.${selected.status}`)}</Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {selected.status === 'failed' && selected.error ? (
                      <p className="text-[12px] text-destructive">{describeError(selected.error, tf)}</p>
                    ) : null}
                    {notice ? <p className="text-[12px] text-destructive">{notice}</p> : null}
                    {savedPath ? (
                      <p className="text-[12px] text-emerald-600 dark:text-emerald-400">{savedPath}</p>
                    ) : null}
                    {selected.status === 'queued' && selected.position ? (
                      <p className="text-[12px] text-muted-foreground">
                        {tf('files.queuePos', { pos: selected.position })}
                      </p>
                    ) : null}
                    {selected.status === 'scanning' ? (
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-[12px] text-muted-foreground">
                          <span>
                            {selProg.total > 0 && PROGRESS_STAGES.has(selProg.stage)
                              ? tf(`files.progress.${selProg.stage}`, { cur: selProg.cur, total: selProg.total })
                              : t('files.progressPreparing')}
                          </span>
                          <span className="tabular-nums">
                            {selProg.indeterminate || !PROGRESS_STAGES.has(selProg.stage)
                              ? t('files.progressIndeterminate')
                              : `${selProg.pct}%`}
                          </span>
                        </div>
                        <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                          {selProg.indeterminate || !PROGRESS_STAGES.has(selProg.stage) ? (
                            <div className="h-full w-1/3 animate-[indeterminate_1.4s_ease-in-out_infinite] rounded-full bg-primary" />
                          ) : (
                            <div className="h-full bg-primary transition-all" style={{ width: `${selProg.pct}%` }} />
                          )}
                        </div>
                      </div>
                    ) : null}
                    <div className="flex flex-wrap items-center gap-2">
                      {TEXT_CARRIERS.has(selected.carrier) && canScan ? (
                        <Button size="sm" onClick={doScan} disabled={busy}>
                          <ShieldCheck className="mr-1.5 h-4 w-4" /> {t('files.scan')}
                        </Button>
                      ) : null}
                      {VISUAL.has(selected.carrier) && canScan ? (
                        <>
                          <Select
                            value={mode}
                            onValueChange={(v) => {
                              modeTouchedRef.current = true
                              setMode(v as 'manual' | 'auto')
                            }}
                          >
                            <SelectTrigger className="h-8 w-[150px]"><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="manual">{t('files.scanManual')}</SelectItem>
                              <SelectItem value="auto">{t('files.scanAuto')}</SelectItem>
                            </SelectContent>
                          </Select>
                          <Button size="sm" onClick={doScan} disabled={busy}>
                            <ShieldCheck className="mr-1.5 h-4 w-4" /> {t('files.scan')}
                          </Button>
                        </>
                      ) : null}
                      {canApply ? (
                        <Button size="sm" onClick={doApply} disabled={busy}>
                          <ShieldCheck className="mr-1.5 h-4 w-4" /> {t('files.apply')}
                        </Button>
                      ) : null}
                      {canDownload ? (
                        <Button size="sm" onClick={doDownload}>
                          <Download className="mr-1.5 h-4 w-4" /> {t('files.download')}
                        </Button>
                      ) : null}
                      {canDownload && caps.path_source && desktopMode ? (
                        <Button size="sm" variant="outline" onClick={doSaveAs}>
                          <FolderOpen className="mr-1.5 h-4 w-4" /> {t('files.saveAs')}
                        </Button>
                      ) : null}
                      {canCancel ? (
                        <Button size="sm" variant="outline" onClick={doCancel}>
                          <Ban className="mr-1.5 h-4 w-4" /> {t('files.cancel')}
                        </Button>
                      ) : null}
                      <Button size="sm" variant="ghost" onClick={doDelete}>
                        <Trash2 className="mr-1.5 h-4 w-4" /> {t('files.delete')}
                      </Button>
                    </div>
                    {showApplyOptions ? (
                      <div className="flex flex-wrap items-center gap-4 rounded-lg bg-muted/40 px-3 py-2 text-[12px]">
                        {selected.carrier === 'pdf' ? (
                          <label className="flex items-center gap-2">
                            <Switch checked={!!options.clear_docinfo}
                              onCheckedChange={(v) => setSelectedOptions((o) => ({ ...o, clear_docinfo: v }))} />
                            {t('files.clearDocinfo')}
                          </label>
                        ) : null}
                        {selected.carrier === 'pdf' ? (
                          <label className="flex items-center gap-2">
                            <Switch checked={!!options.keep_attachments}
                              onCheckedChange={(v) => setSelectedOptions((o) => ({ ...o, keep_attachments: v }))} />
                            {t('files.keepAttachments')}
                          </label>
                        ) : null}
                        {selected.carrier === 'ooxml' && Number(selected.coverage?.embedded_objects_present || 0) > 0 ? (
                          <label className="flex items-center gap-2">
                            <Switch checked={!!options.keep_embedded_objects}
                              onCheckedChange={(v) => setSelectedOptions((o) => ({ ...o, keep_embedded_objects: v }))} />
                            {t('files.keepEmbeddedObjects')}
                          </label>
                        ) : null}
                        {selected.carrier === 'ooxml' && Number(selected.coverage?.non_image_media_present || 0) > 0 ? (
                          <label className="flex items-center gap-2">
                            <Switch checked={!!options.strip_non_image_media}
                              onCheckedChange={(v) => setSelectedOptions((o) => ({ ...o, strip_non_image_media: v }))} />
                            {t('files.stripNonImageMedia')}
                          </label>
                        ) : null}
                        {selected.carrier === 'image' ? (
                          <label className="flex items-center gap-2">
                            <Switch checked={!!options.keep_icc}
                              onCheckedChange={(v) => setSelectedOptions((o) => ({ ...o, keep_icc: v }))} />
                            {t('files.keepIcc')}
                          </label>
                        ) : null}
                      </div>
                    ) : null}
                    {coverageLines.length ? (
                      <p className="text-[11px] text-muted-foreground">
                        {t('files.coverage')}: {coverageLines.join(' · ')}
                      </p>
                    ) : null}
                    {warningLines.length ? (
                      <p className="text-[11px] text-amber-600 dark:text-amber-400">
                        {t('files.warnings')}: {warningLines.join(' · ')}
                      </p>
                    ) : null}
                  </CardContent>
                </Card>

                {VISUAL.has(selected.carrier) && selected.status === 'awaiting_review' ? (
                  <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                      <CardTitle className="text-sm">{t('files.preview')}</CardTitle>
                      <div className="flex items-center gap-1">
                        <Button variant={tool === 'rect' ? 'default' : 'outline'} size="sm"
                          onClick={() => setTool('rect')}>
                          <Square className="mr-1 h-3.5 w-3.5" /> {t('files.toolRect')}
                        </Button>
                        <Button variant={tool === 'brush' ? 'default' : 'outline'} size="sm"
                          onClick={() => setTool('brush')}>
                          <Brush className="mr-1 h-3.5 w-3.5" /> {t('files.toolBrush')}
                        </Button>
                        <Button variant="ghost" size="sm" onClick={clearAreas}>
                          {t('files.clearRedactions')}
                        </Button>
                        {pageDismissedCount > 0 ? (
                          <Button variant="ghost" size="sm" onClick={restorePageAutoBoxes}>
                            <RotateCcw className="mr-1 h-3.5 w-3.5" /> {t('files.restoreAutoBoxes')}
                          </Button>
                        ) : null}
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      {previewBusy ? (
                        <div className="flex h-48 items-center justify-center text-sm text-muted-foreground">
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" /> {t('files.loading')}
                        </div>
                      ) : previewError ? (
                        <div className="flex h-48 flex-col items-center justify-center gap-2 text-sm text-muted-foreground">
                          <span>{t('files.previewFailed')}</span>
                          <span className="text-[11px]">{previewError}</span>
                          <Button variant="outline" size="sm" onClick={() => setPreviewTick((n) => n + 1)}>
                            <RefreshCw className="mr-1 h-3.5 w-3.5" /> {t('files.retry')}
                          </Button>
                        </div>
                      ) : preview ? (
                        <>
                          {visibleAutoBoxes.length > 0 ? (
                            <p className="text-[11px] text-muted-foreground">
                              {tf('files.autoBoxesCount', { n: visibleAutoBoxes.length })}
                            </p>
                          ) : null}
                          <div className="relative overflow-hidden rounded-lg border border-border/60">
                            {/* eslint-disable-next-line jsx-a11y/img-redundant-alt */}
                            <img src={preview} alt="" className="block w-full select-none" draggable={false} />
                            <svg
                              className="absolute inset-0 h-full w-full cursor-crosshair"
                              viewBox="0 0 1 1"
                              preserveAspectRatio="none"
                              onMouseDown={onDown}
                              onMouseMove={onMove}
                              onMouseUp={() => onUp(true)}
                              onMouseLeave={() => onUp(false)}
                            >
                              {visibleAutoBoxes.map((b) => {
                                if (b.kind === 'full') {
                                  return <rect key={b.id} x={0} y={0} width={1} height={1} fill="rgba(245,158,11,0.22)" />
                                }
                                const isDismissed = !!dismissedBoxes[b.id]
                                return (
                                  <rect
                                    key={b.id}
                                    x={b.rect?.[0] || 0}
                                    y={b.rect?.[1] || 0}
                                    width={b.rect?.[2] || 0}
                                    height={b.rect?.[3] || 0}
                                    fill={isDismissed ? 'rgba(148,163,184,0.08)' : 'rgba(239,68,68,0.26)'}
                                    stroke={isDismissed ? 'rgba(148,163,184,0.75)' : 'rgba(220,38,38,0.85)'}
                                    strokeDasharray={isDismissed ? '0.01 0.008' : undefined}
                                    strokeWidth={0.0025}
                                  />
                                )
                              })}
                              {[...pageAreas, ...(draft ? [draft] : [])].map((r) => {
                                if (r.kind === 'full') {
                                  return <rect key={r.id} x={0} y={0} width={1} height={1} fill="rgba(15,23,42,0.55)" />
                                }
                                if (r.kind === 'path') {
                                  return (
                                    <polyline
                                      key={r.id}
                                      points={(r.points || []).map((p) => `${p[0]},${p[1]}`).join(' ')}
                                      stroke="rgba(15,23,42,0.75)"
                                      strokeWidth={r.width || 0.006}
                                      fill="none"
                                    />
                                  )
                                }
                                return (
                                  <rect
                                    key={r.id}
                                    x={r.rect?.[0] || 0}
                                    y={r.rect?.[1] || 0}
                                    width={r.rect?.[2] || 0}
                                    height={r.rect?.[3] || 0}
                                    fill="rgba(15,23,42,0.65)"
                                  />
                                )
                              })}
                            </svg>
                          </div>
                        </>
                      ) : (
                        <div className="flex h-48 items-center justify-center text-sm text-muted-foreground">
                          {t('files.noPreview')}
                        </div>
                      )}
                      {selected.page_count ? (
                        <div className="flex items-center justify-between text-[12px]">
                          <Button variant="ghost" size="sm" disabled={page <= 1}
                            onClick={() => setPage((p) => Math.max(1, p - 1))}>
                            <ChevronLeft className="mr-1 h-3.5 w-3.5" /> {t('files.prevPage')}
                          </Button>
                          <span>{tf('files.page', { n: page, total: Number(selected.page_count) })}</span>
                          <Button variant="ghost" size="sm" disabled={page >= Number(selected.page_count)}
                            onClick={() => setPage((p) => Math.min(Number(selected.page_count), p + 1))}>
                            {t('files.nextPage')} <ChevronRight className="ml-1 h-3.5 w-3.5" />
                          </Button>
                        </div>
                      ) : null}
                    </CardContent>
                  </Card>
                ) : null}

                {selected.status === 'awaiting_review' ? (
                  <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                      <CardTitle className="flex items-center gap-2 text-sm">
                        <span>{t('files.hits')}</span>
                        {hits.length > 0 ? (
                          <Badge variant="outline" className="font-normal">
                            {tf('files.hitsSummary', { items: hits.length, occ: singleTotalOcc })}
                          </Badge>
                        ) : null}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      {hitsBusy ? (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <Loader2 className="h-4 w-4 animate-spin" /> {t('files.loading')}
                        </div>
                      ) : hitsError ? (
                        <div className="text-[12px] text-destructive">{hitsError}</div>
                      ) : hits.length === 0 ? (
                        <div className="text-[13px] text-muted-foreground">
                          {embeddedHandled ? t('files.noTextHitsEmbeddedMasked') : t('files.noHits')}
                        </div>
                      ) : (
                        <>
                          {renderHitFilterBar()}
                          {filteredSingleHits.length === 0 ? (
                            <div className="rounded-lg border border-border/60 p-6 text-center text-[12px] text-muted-foreground">
                              {t('files.noFilteredHits')}
                            </div>
                          ) : (
                            <div
                              ref={hitScrollRef}
                              className="max-h-[520px] min-h-[120px] overflow-y-auto rounded-lg border border-border/60"
                            >
                              <div className="relative" style={{ height: hitVirtualizer.getTotalSize() }}>
                                {hitVirtualizer.getVirtualItems().map((vi) => {
                                  const hit = filteredSingleHits[vi.index]
                                  if (!hit) return null
                                  return (
                                    <div
                                      key={hit.hit_id}
                                      data-index={vi.index}
                                      ref={hitVirtualizer.measureElement}
                                      className="absolute left-0 top-0 flex w-full flex-wrap items-center gap-2 border-b border-border/50 bg-card px-3 py-2"
                                      style={{ transform: `translateY(${vi.start}px)` }}
                                    >
                                      <div className="flex min-w-0 flex-1 items-center gap-2">
                                        <Badge variant="secondary" className="shrink-0 text-[10px]">
                                          {hit.label || '—'}
                                        </Badge>
                                        <span
                                          className="min-w-0 flex-1 truncate font-mono text-[12.5px]"
                                          title={hit.editable ? (hit.original || '') : (hit.preview || '')}
                                        >
                                          {hit.editable ? (hit.original || '') : (hit.preview || '')}
                                        </span>
                                        <span
                                          className="hidden max-w-[140px] shrink-0 truncate text-[11px] text-muted-foreground sm:inline"
                                          title={(hit.locations || []).join(' / ')}
                                        >
                                          {(hit.locations || []).join(' / ') || '—'}
                                        </span>
                                        <span className="shrink-0 tabular-nums text-[11px] text-muted-foreground">
                                          ×{hit.count}
                                        </span>
                                      </div>
                                      {hit.editable ? (
                                        <div className="flex shrink-0 items-center gap-2">
                                          <Input
                                            className="h-7 w-[180px] text-[12px]"
                                            placeholder={t('files.replacement')}
                                            value={getSingleReplace(hit)}
                                            disabled={getSingleKeep(hit)}
                                            onChange={(e) => setJobReplace(selected.id, hit.hit_id, e.target.value)}
                                          />
                                          {hit.can_keep ? (
                                            <label className="flex shrink-0 items-center gap-1.5 text-[11.5px]">
                                              <Switch
                                                className="scale-75"
                                                checked={getSingleKeep(hit)}
                                                onCheckedChange={(v) => setJobKeep(selected.id, hit.hit_id, v)}
                                              />
                                              {t('files.keep')}
                                            </label>
                                          ) : null}
                                        </div>
                                      ) : (
                                        <span className="shrink-0 text-[11px] text-muted-foreground">
                                          {tf('files.credential', { digest: hit.digest || '' })}
                                        </span>
                                      )}
                                    </div>
                                  )
                                })}
                              </div>
                            </div>
                          )}
                        </>
                      )}
                    </CardContent>
                  </Card>
                ) : null}
              </>
            )}
          </div>
        </div>
      )}

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <History className="h-4 w-4" />
            <span>{t('files.historyTitle')}</span>
            <Badge variant="outline">{history.length}</Badge>
          </CardTitle>
          <Button variant="ghost" size="sm" onClick={() => setHistoryOpen((v) => !v)}>
            {historyOpen ? t('files.historyHide') : t('files.historyShow')}
          </Button>
        </CardHeader>
        {historyOpen ? (
          <CardContent className="space-y-1.5 pt-1">
            {history.length === 0 ? (
              <p className="text-[12px] text-muted-foreground">{t('files.historyEmpty')}</p>
            ) : (
              history.slice().reverse().slice(0, 30).map((item) => (
                <div
                  key={`${item.id}-${item.ts}`}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/50 px-3 py-1.5 text-[12px]"
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-medium">{item.name_preview}</span>
                    <Badge variant={statusTone(item.status)}>{t(`files.status.${item.status}`)}</Badge>
                    <span className="text-muted-foreground">{tf('files.size', { n: (item.size / 1024).toFixed(0) })}</span>
                    {item.hit_count ? <span className="text-muted-foreground">{tf('files.hitCount', { n: item.hit_count })}</span> : null}
                  </div>
                  <span className="text-[11px] text-muted-foreground">
                    {new Date(item.ts * 1000).toLocaleString()}
                  </span>
                </div>
              ))
            )}
          </CardContent>
        ) : null}
      </Card>
    </div>
  )
}
