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
import {
  UploadCloud,
  RefreshCw,
  FileLock2,
  Download,
  Trash2,
  Ban,
  ShieldCheck,
  Square,
  Brush,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Loader2,
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
  applyJob, cancelJob, createJob, deleteJob, downloadJob, getCapabilities, getHits,
  getJob, getPreview, listJobs, scanJob,
  type ApplyOptions, type FileHitView, type FileJobView, type FilesCapabilities,
  type Redaction, type TextEdit,
} from '@/api/files'

const NON_TERMINAL = new Set(['created', 'probing', 'ready', 'queued', 'scanning', 'applying', 'canceling'])
const VISUAL = new Set(['pdf', 'image'])
const TEXT_CARRIERS = new Set(['ooxml', 'text'])

function statusTone(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
  if (status === 'done') return 'default'
  if (status === 'failed' || status === 'expired') return 'destructive'
  if (status === 'awaiting_review') return 'secondary'
  return 'outline'
}

export default function FilesPage() {
  const { t, tf } = useI18n()
  const [caps, setCaps] = useState<FilesCapabilities | null>(null)
  const [capsError, setCapsError] = useState('')
  const [loading, setLoading] = useState(true)
  const [jobs, setJobs] = useState<FileJobView[]>([])
  const [selected, setSelected] = useState<FileJobView | null>(null)
  const [hits, setHits] = useState<FileHitView[]>([])
  const [hitsBusy, setHitsBusy] = useState(false)
  const [hitsError, setHitsError] = useState('')
  const [replaces, setReplaces] = useState<Record<string, string>>({})
  const [keeps, setKeeps] = useState<Record<string, boolean>>({})
  const [redactions, setRedactions] = useState<Redaction[]>([])
  const [page, setPage] = useState(1)
  const [preview, setPreview] = useState('')
  const [previewError, setPreviewError] = useState('')
  const [previewBusy, setPreviewBusy] = useState(false)
  const [previewTick, setPreviewTick] = useState(0)
  const [tool, setTool] = useState<'rect' | 'brush'>('rect')
  const [mode, setMode] = useState<'manual' | 'auto'>('manual')
  const [options, setOptions] = useState<ApplyOptions>({
    clear_docinfo: true, keep_attachments: false, keep_icc: false,
  })
  const [notice, setNotice] = useState('')
  const [uploadError, setUploadError] = useState('')
  const [uploading, setUploading] = useState(false)
  const [busy, setBusy] = useState(false)
  const dragRef = useRef<{ x: number; y: number } | null>(null)
  const brushRef = useRef<[number, number][]>([])
  const [draft, setDraft] = useState<Redaction | null>(null)
  const inputRef = useRef<HTMLInputElement | null>(null)

  // 能力探测（G801）
  // @guard G801 关闭/探测失败只给空态，不渲染上传与列表
  const loadCaps = useCallback(() => {
    setLoading(true)
    getCapabilities()
      .then((res) => {
        setCaps(res)
        setCapsError('')
      })
      .catch((e: unknown) => {
        setCaps(null)
        setCapsError(String((e as Error)?.message || e))
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { loadCaps() }, [loadCaps])

  const refreshJobs = useCallback(() => {
    listJobs()
      .then((res) => setJobs(res.jobs || []))
      .catch(() => { /* 列表失败保留旧值，错误由 selected 区呈现 */ })
  }, [])

  useEffect(() => {
    if (!caps?.enabled) return
    refreshJobs()
  }, [caps?.enabled, refreshJobs])

  // 轮询：非终态 1s；终态停止（G803）
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
        })
        .catch(() => { /* 轮询失败不打断页面 */ })
    }, 1000)
    return () => window.clearInterval(timer)
  }, [jobId, jobStatus])

  // 命中清单（G804）
  // @guard G804 凭据只读，非凭据才渲染输入与保留开关
  useEffect(() => {
    if (!jobId || jobStatus !== 'awaiting_review') return
    setHitsBusy(true)
    setHitsError('')
    getHits(jobId)
      .then((res) => {
        setHits(res.hits || [])
        setReplaces({})
        setKeeps({})
      })
      .catch((e: unknown) => setHitsError(String((e as Error)?.message || e)))
      .finally(() => setHitsBusy(false))
  }, [jobId, jobStatus])

  // 预览（G805）
  // @guard G805 页码夹在 1..page_count，失败给占位
  useEffect(() => {
    if (!jobId || !jobCarrier || !VISUAL.has(jobCarrier) || jobStatus !== 'awaiting_review') {
      setPreview('')
      return
    }
    if (!jobPages || page < 1 || page > Number(jobPages)) return
    setPreviewBusy(true)
    setPreviewError('')
    getPreview(jobId, page)
      .then((res) => setPreview(res.data))
      .catch((e: unknown) => {
        setPreview('')
        setPreviewError(String((e as Error)?.message || e))
      })
      .finally(() => setPreviewBusy(false))
  }, [jobId, jobStatus, jobCarrier, jobPages, page, previewTick])

  const select = (job: FileJobView) => {
    setSelected(job)
    setPage(1)
    setRedactions([])
    setNotice('')
    setHits([])
    setPreview('')
  }

  const upload = async (file: File) => {
    if (!caps) return
    setUploadError('')
    // @guard G802 超上限前端先拦，不发请求
    const limit = (caps.max_size_mb || 1024) * 1024 * 1024
    if (file.size > limit) {
      setUploadError(tf('files.tooLarge', { mb: caps.max_size_mb }))
      return
    }
    setUploading(true)
    try {
      const res = await createJob(file)
      setJobs((prev) => [res.job, ...prev])
      select(res.job)
      refreshJobs()
    } catch (e: unknown) {
      setUploadError(String((e as Error)?.message || e))
    } finally {
      setUploading(false)
    }
  }

  const onDragOver = (e: DragEvent) => {
    e.preventDefault()
  }
  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    const file = e.dataTransfer.files?.[0]
    if (file) void upload(file)
  }

  const doScan = async () => {
    if (!selected) return
    setBusy(true)
    setNotice('')
    try {
      const res = await scanJob(selected.id, mode)
      setSelected(res.job)
      refreshJobs()
    } catch (e: unknown) {
      setNotice(String((e as Error)?.message || e))
    } finally {
      setBusy(false)
    }
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
      setNotice(String((e as Error)?.message || e))
    } finally {
      setBusy(false)
    }
  }

  const doCancel = async () => {
    // @guard G811 仅允许态可取消，取消后轮询自然停止
    if (!selected) return
    try {
      const res = await cancelJob(selected.id)
      setSelected(res.job)
      refreshJobs()
    } catch (e: unknown) {
      setNotice(String((e as Error)?.message || e))
    }
  }

  const doDelete = async () => {
    if (!selected) return
    if (!window.confirm(t('files.deleteConfirm'))) return
    try {
      await deleteJob(selected.id)
      setSelected(null)
      setJobs((prev) => prev.filter((j) => j.id !== selected.id))
    } catch (e: unknown) {
      setNotice(String((e as Error)?.message || e))
    }
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
      setNotice(String((e as Error)?.message || e))
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

  const onUp = () => {
    if (!draft) {
      dragRef.current = null
      brushRef.current = []
      return
    }
    if (draft.kind === 'rect' && (draft.rect?.[2] || 0) > 0.002 && (draft.rect?.[3] || 0) > 0.002) {
      setRedactions((prev) => [...prev, { ...draft, id: 'r' + (prev.length + 1) }])
    }
    if (draft.kind === 'path' && (draft.points?.length || 0) >= 2) {
      setRedactions((prev) => [...prev, { ...draft, id: 'r' + (prev.length + 1) }])
    }
    setDraft(null)
    dragRef.current = null
    brushRef.current = []
  }

  const clearAreas = () => setRedactions((prev) => prev.filter((r) => r.page !== page))

  const canScan = selected?.status === 'ready'
  const canApply = selected?.status === 'awaiting_review'
  const canDownload = selected?.status === 'done'
  const canCancel = selected ? ['queued', 'scanning', 'applying'].includes(selected.status) : false

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

  return (
    <div className="space-y-4">
      <PageHeader
        title={t('nav.files')}
        subtitle={t('files.subtitle')}
        actions={(
          <Button variant="outline" size="sm" onClick={() => { refreshJobs(); loadCaps() }}>
            <RefreshCw className="mr-1.5 h-4 w-4" /> {t('files.refresh')}
          </Button>
        )}
      />

      <Card>
        <CardContent className="p-4">
          <div
            className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-border/70 px-4 py-8 text-center transition hover:bg-muted/40"
            onDragOver={onDragOver}
            onDrop={onDrop}
            onClick={() => inputRef.current?.click()}
          >
            <UploadCloud className="h-8 w-8 text-muted-foreground" />
            <div className="text-sm font-medium">{t('files.dropTitle')}</div>
            <div className="text-[12px] text-muted-foreground">
              {tf('files.dropHint', { mb: caps.max_size_mb, exts: accept || '—' })}
            </div>
            {uploading ? <div className="text-[12px]">{t('files.uploading')}</div> : null}
            {uploadError ? <div className="text-[12px] text-destructive">{uploadError}</div> : null}
            <input
              ref={inputRef}
              type="file"
              className="hidden"
              accept={accept}
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) void upload(f)
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
        <div className="grid gap-4 lg:grid-cols-12">
          <Card className="lg:col-span-4">
            <CardHeader className="pb-2"><CardTitle className="text-sm">{t('files.list')}</CardTitle></CardHeader>
            <CardContent className="space-y-1 p-2">
              {jobs.map((job) => (
                <button
                  key={job.id}
                  type="button"
                  onClick={() => select(job)}
                  className={`w-full rounded-lg px-3 py-2 text-left transition ${selected?.id === job.id ? 'bg-muted' : 'hover:bg-muted/50'}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-[13px] font-medium">{job.filename}</span>
                    <Badge variant={statusTone(job.status)}>{t(`files.status.${job.status}`)}</Badge>
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-[11px] text-muted-foreground">
                    <span>{tf('files.size', { n: (job.size / 1024).toFixed(0) })}</span>
                    {job.page_count ? <span>{tf('files.pages', { n: job.page_count })}</span> : null}
                    {job.hit_count ? <span>{tf('files.hitCount', { n: job.hit_count })}</span> : null}
                  </div>
                </button>
              ))}
            </CardContent>
          </Card>

          <div className="space-y-4 lg:col-span-8">
            {!selected ? (
              <Card><CardContent className="p-8 text-center text-sm text-muted-foreground">
                {t('files.selectJob')}
              </CardContent></Card>
            ) : (
              <>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
                      <FileLock2 className="h-4 w-4" />
                      <span className="truncate">{selected.filename}</span>
                      <Badge variant={statusTone(selected.status)}>{t(`files.status.${selected.status}`)}</Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {selected.status === 'failed' && selected.error ? (
                      <p className="text-[12px] text-destructive">{tf('files.error', { code: selected.error })}</p>
                    ) : null}
                    {notice ? <p className="text-[12px] text-destructive">{notice}</p> : null}
                    <div className="flex flex-wrap items-center gap-2">
                      {TEXT_CARRIERS.has(selected.carrier) && canScan ? (
                        <Button size="sm" onClick={doScan} disabled={busy}>
                          <ShieldCheck className="mr-1.5 h-4 w-4" /> {t('files.scan')}
                        </Button>
                      ) : null}
                      {VISUAL.has(selected.carrier) && canScan ? (
                        <>
                          <Select value={mode} onValueChange={(v) => setMode(v as 'manual' | 'auto')}>
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
                      {canCancel ? (
                        <Button size="sm" variant="outline" onClick={doCancel}>
                          <Ban className="mr-1.5 h-4 w-4" /> {t('files.cancel')}
                        </Button>
                      ) : null}
                      <Button size="sm" variant="ghost" onClick={doDelete}>
                        <Trash2 className="mr-1.5 h-4 w-4" /> {t('files.delete')}
                      </Button>
                    </div>
                    {canApply ? (
                      <div className="flex flex-wrap items-center gap-4 rounded-lg bg-muted/40 px-3 py-2 text-[12px]">
                        {selected.carrier === 'pdf' ? (
                          <label className="flex items-center gap-2">
                            <Switch checked={!!options.clear_docinfo}
                              onCheckedChange={(v) => setOptions((o) => ({ ...o, clear_docinfo: v }))} />
                            {t('files.clearDocinfo')}
                          </label>
                        ) : null}
                        {selected.carrier === 'pdf' ? (
                          <label className="flex items-center gap-2">
                            <Switch checked={!!options.keep_attachments}
                              onCheckedChange={(v) => setOptions((o) => ({ ...o, keep_attachments: v }))} />
                            {t('files.keepAttachments')}
                          </label>
                        ) : null}
                        {selected.carrier === 'image' ? (
                          <label className="flex items-center gap-2">
                            <Switch checked={!!options.keep_icc}
                              onCheckedChange={(v) => setOptions((o) => ({ ...o, keep_icc: v }))} />
                            {t('files.keepIcc')}
                          </label>
                        ) : null}
                      </div>
                    ) : null}
                    {selected.coverage && Object.keys(selected.coverage).length > 0 ? (
                      <p className="text-[11px] text-muted-foreground">
                        {t('files.coverage')}: {JSON.stringify(selected.coverage)}
                      </p>
                    ) : null}
                    {selected.warnings?.length ? (
                      <p className="text-[11px] text-amber-600 dark:text-amber-400">
                        {t('files.warnings')}: {selected.warnings.join(' · ')}
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
                        <div className="relative overflow-hidden rounded-lg border border-border/60">
                          {/* eslint-disable-next-line jsx-a11y/img-redundant-alt */}
                          <img src={preview} alt="" className="block w-full select-none" draggable={false} />
                          <svg
                            className="absolute inset-0 h-full w-full cursor-crosshair"
                            viewBox="0 0 1 1"
                            preserveAspectRatio="none"
                            onMouseDown={onDown}
                            onMouseMove={onMove}
                            onMouseUp={onUp}
                            onMouseLeave={onUp}
                          >
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
                    <CardHeader className="pb-2"><CardTitle className="text-sm">{t('files.hits')}</CardTitle></CardHeader>
                    <CardContent className="space-y-2">
                      {hitsBusy ? (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <Loader2 className="h-4 w-4 animate-spin" /> {t('files.loading')}
                        </div>
                      ) : hitsError ? (
                        <div className="text-[12px] text-destructive">{hitsError}</div>
                      ) : hits.length === 0 ? (
                        <div className="text-[13px] text-muted-foreground">{t('files.noHits')}</div>
                      ) : (
                        <div className="space-y-2">
                          {hits.map((hit) => (
                            <div key={hit.hit_id} className="rounded-lg border border-border/60 p-3">
                              <div className="flex flex-wrap items-center gap-2 text-[12px]">
                                <Badge variant="secondary">{hit.label || '—'}</Badge>
                                <span className="text-muted-foreground">
                                  {(hit.locations || []).join(' / ') || '—'}
                                </span>
                                <span className="text-muted-foreground">×{hit.count}</span>
                              </div>
                              <div className="mt-2 flex flex-wrap items-center gap-2">
                                <span className="min-w-0 flex-1 truncate text-[13px]">
                                  {hit.editable ? (hit.original || '') : (hit.preview || '')}
                                </span>
                                {hit.editable ? (
                                  <>
                                    <Input
                                      className="h-8 w-[220px]"
                                      placeholder={t('files.replacement')}
                                      value={replaces[hit.hit_id] || ''}
                                      disabled={!!keeps[hit.hit_id]}
                                      onChange={(e) => setReplaces((prev) => ({ ...prev, [hit.hit_id]: e.target.value }))}
                                    />
                                    {hit.can_keep ? (
                                      <label className="flex items-center gap-1.5 text-[12px]">
                                        <Switch checked={!!keeps[hit.hit_id]}
                                          onCheckedChange={(v) => setKeeps((prev) => ({ ...prev, [hit.hit_id]: v }))} />
                                        {t('files.keep')}
                                      </label>
                                    ) : null}
                                  </>
                                ) : (
                                  <span className="text-[11px] text-muted-foreground">
                                    {tf('files.credential', { digest: hit.digest || '' })}
                                  </span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ) : null}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
