/**
 * 事件详情弹窗：/api/logs/detail 单条回源（slim 列表无明文，仅此处展示）
 * 明文只进详情（AGENTS.md 红线）；MASK 行 dialog=用户消息，RESTORE 行 dialog=助手回复
 */
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getLogDetail } from '@/api/logs'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { EventTypeIcon, getEventTypeMeta } from '@/components/events/EventTypeIcon'
import { CheckCircle2 } from 'lucide-react'
import type { ShieldEvent, LogMode } from '@/types/api'
import dayjs from 'dayjs'
import { cn, copyText } from '@/lib/utils'
import { useI18n } from '@/lib/i18n'

function MetaItem({ k, v, wide }: { k: string; v: React.ReactNode; wide?: boolean }) {
  return (
    <div className={cn('rounded-lg bg-muted/50 p-2.5', wide && 'col-span-2')}>
      <div className="text-[11px] text-muted-foreground">{k}</div>
      <div className="mt-0.5 break-all text-[13px]">{v}</div>
    </div>
  )
}

function formatDuration(ms?: number | null): string {
  if (ms == null) return '—'
  if (ms < 1000) return `${Math.round(ms)}ms`
  const s = ms / 1000
  if (s < 60) return `${s.toFixed(1)}s`
  const m = Math.floor(s / 60)
  const rest = Math.round(s % 60)
  return `${m}m ${rest}s`
}

/**
 * 语义识别（NER）降级原因 → i18n 键。
 *
 * **只用 `settings.sw.nerSkip*` 这一套标签**：设置页与详情弹窗共用同一份文案，
 * 避免两处各维护一份又互相漂移（当初就是设置页列了 6 个键、其中一个早已不产生、
 * 而真在产生的两个没列，界面上直接看不到）。
 *
 * 键的空间（引擎侧当前会产生的）：`budget_exhausted` / `infer_failed` / `deadline` /
 * `model_unavailable`，以及 transparent 经 `record_skip` 上报的 `model_missing` /
 * `om_compose` / `runtime`。`too_long` 是 0.6.1 前的**历史键**（当时超长文本整条跳过，
 * 现在改为分段识别），标签保留是为了渲染旧库里已有的事件。未知原因（后端将来新增）
 * 直接回退到原始键名 —— 降级信息宁可粗糙也绝不能不显示（不显示就等于静默降级）。
 * 一致性由 tests/test_regressions.py::NerSkipReasonSurfacesTests 守。
 */
const NER_SKIP_LABELS: Record<string, string> = {
  too_long: 'settings.sw.nerSkipTooLong',
  budget_exhausted: 'settings.sw.nerSkipBudget',
  cancelled: 'settings.sw.nerSkipCancelled',
  infer_failed: 'settings.sw.nerSkipInfer',
  deadline: 'settings.sw.nerSkipDeadline',
  model_unavailable: 'settings.sw.nerSkipModelUnavailable',
  model_missing: 'settings.sw.nerSkipModelMissing',
  om_compose: 'settings.sw.nerSkipCompose',
  runtime: 'settings.sw.nerSkipRuntime',
  // B-2（0.6.0）：治理器新增的两个降级原因。加它们不是"多列两项"——
  // 契约测试（test_regressions.NerSkipReasonSurfacesTests）会要求引擎报出的
  // 每个键在两个界面上都有落点，否则用户看到的又是静默降级。
  global_throttled: 'settings.sw.nerSkipGlobalThrottled',
  sem_timeout: 'settings.sw.nerSkipSemTimeout',
  // 批次 2（统一检测口径）：`reason_codes` 里可能出现的非 NER 原因码。
  // 与 `inspection.REASON_CODES` 同源；新增码必须同时在这里与 i18n 里落地，
  // 否则用户在详情里看到的是裸键名（等价于“看不懂的降级”）。
  signed_blocks_skipped: 'reason.signedBlocksSkipped',
  unresolved_tokens: 'reason.unresolvedTokens',
  semantic_incomplete: 'reason.semanticIncomplete',
  request_too_large: 'reason.requestTooLarge',
  engine_busy: 'reason.engineBusy',
  engine_timeout: 'reason.engineTimeout',
  pipeline_error: 'reason.pipelineError',
  audit_truncated: 'reason.auditTruncated',
  command_blocked: 'reason.commandBlocked',
  response_too_large: 'reason.responseTooLarge',
  not_target: 'reason.notTarget',
  host_not_configured: 'reason.hostNotConfigured',
  path_not_configured: 'reason.pathNotConfigured',
  no_reverse_route: 'reason.noReverseRoute',
}

/** 处置结论 → i18n 键（批次 2 统一口径，见引擎 `inspection.DECISION_*`）。 */
const DECISION_LABELS: Record<string, string> = {
  masked: 'detail.decisionMasked',
  scanned_clean: 'detail.decisionScannedClean',
  blocked: 'detail.decisionBlocked',
  passthrough: 'detail.decisionPassthrough',
}

/** 完整度 → i18n 键（`complete` 只表示“所配置的检测已执行完”，不保证现实无漏检）。 */
const COMPLETENESS_LABELS: Record<string, string> = {
  complete: 'detail.completenessComplete',
  partial: 'detail.completenessPartial',
  failed: 'detail.completenessFailed',
  not_applicable: 'detail.completenessNotApplicable',
  unknown: 'detail.completenessUnknown',
}

/**
 * 在正文里高亮「被还原回来的原文」。
 *
 * 存在的理由：还原是这个软件的核心动作，但对着一段几千字的回复，
 * 用户根本看不出哪几个字是刚被换回来的。上面的对照表告诉你「换了什么」，
 * 这里告诉你「换在哪」——两者合起来才构成一次可核对的还原。
 *
 * 只高亮 items 里带 original 的项：凭据类只有 preview + sha256 摘要，
 * 本来就没有明文可匹配（AGENTS.md 红线，凭据永不明文落库）。
 */
function highlightOriginals(text: string, originals: string[]): React.ReactNode {
  const uniq = [...new Set(originals.filter(Boolean))]
  if (!uniq.length) return text
  // 长的排前面：「张三丰」和「张三」同时存在时，先匹配长的，
  // 否则短的会把长的切成两半，高亮范围就错了
  uniq.sort((a, b) => b.length - a.length)
  const rx = new RegExp(uniq.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'g')
  const out: React.ReactNode[] = []
  let last = 0
  for (const m of text.matchAll(rx)) {
    const i = m.index ?? 0
    if (i > last) out.push(text.slice(last, i))
    out.push(
      <mark
        key={`${i}-${m[0]}`}
        className="rounded bg-emerald-500/25 px-0.5 text-foreground ring-1 ring-emerald-500/40"
      >
        {m[0]}
      </mark>,
    )
    last = i + m[0].length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

function CopyBtn({ text }: { text: string }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  return (
    <Button
      size="sm"
      variant="ghost"
      className="h-6 px-2 text-[11px]"
      onClick={async () => {
        try {
          await copyText(text)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        } catch {
          // 剪贴板不可用时静默
        }
      }}
    >
      {copied ? t('detail.copied') : t('detail.copy')}
    </Button>
  )
}

export function EventDetailDialog({
  open,
  onOpenChange,
  seq,
  logMode,
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
  seq: number | null
  /** 当前生效的日志写入模式：summary 下正文本来就没落盘，要明确告知 */
  logMode?: LogMode
}) {
  const { t, tf } = useI18n()
  // Translate only known enums. New backend codes stay visible verbatim rather
  // than becoming a missing translation key or an invented failure diagnosis.
  const transportLabel = (kind: 'phase' | 'reason', value?: string | null) => {
    if (!value) return t('transport.unknown')
    const key = `transport.${kind}.${value}`
    const label = t(key)
    return label === key ? value : label
  }
  // 高亮默认关：先让用户看到未加工的原文，要核对时再点开。
  // 默认开会让每次打开详情都是一片荧光绿，反而看不出重点。
  const [hl, setHl] = useState(false)
  const { data, isLoading } = useQuery({
    queryKey: ['logDetail', seq],
    queryFn: () => getLogDetail(seq!),
    enabled: open && seq != null,
    retry: 1,
  })

  const event: ShieldEvent | undefined = data?.ok ? data.event : undefined

  // 本次检测的可读原因码（批次 2）：`reason_codes` 与 `ner_skip_reasons` 合并展示，
  // 两处的键空间相同（NER 降级 + 协议契约豁免 + 阻断原因），同一个标签表渲染。
  const reasonCodes = useMemo(
    () =>
      Object.entries({ ...(event?.reason_codes ?? {}), ...(event?.ner_skip_reasons ?? {}) })
        .map(([k, n]) => [k, Number(n || 0)] as [string, number])
        .filter(([, n]) => n > 0),
    [event],
  )

  // 可高亮的原文：凭据类只有 preview + sha256，没有明文可匹配
  const originals = useMemo(
    () => ((event?.items ?? []) as { original?: string }[])
      .map((i) => i.original)
      .filter((s): s is string => typeof s === 'string' && s.length > 0),
    [event],
  )

  const stageInfo = useMemo(() => {
    if (!event) return null
    const meta = getEventTypeMeta(event.type)
    switch (event.type) {
      case 'RESTORE':
        return {
          label: t('detail.stageRestore'),
          className: 'bg-emerald-600 text-white hover:bg-emerald-600',
          desc: t('detail.stageRestoreDesc'),
        }
      case 'MASK':
        return {
          label: t('detail.stageMask'),
          className: 'bg-blue-600 text-white hover:bg-blue-600',
          desc: t('detail.stageMaskDesc'),
        }
      case 'BLOCK':
        return {
          label: t('evt.block'),
          className: 'bg-red-600 text-white hover:bg-red-600',
          desc: t('detail.stageBlockDesc'),
        }
      case 'ERR':
        return {
          label: t('evt.err'),
          className: 'bg-red-600 text-white hover:bg-red-600',
          desc: t('detail.stageErrDesc'),
        }
      case 'SCAN_WARN':
        return {
          label: t('evt.scanWarn'),
          className: 'bg-amber-600 text-white hover:bg-amber-600',
          desc: t('detail.stageScanWarnDesc'),
        }
      default:
        return {
          label: meta.labelKey ? t(meta.labelKey) : (meta.label || event.type),
          className: 'bg-slate-600 text-white hover:bg-slate-600',
          desc: t('detail.stageOtherDesc'),
        }
    }
  }, [event, t])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-3xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {event && <EventTypeIcon type={event.type} className="h-4 w-4" />}
            {t('detail.title')}
            {event && (
              <span className="text-xs font-normal text-muted-foreground">#{event.seq}</span>
            )}
          </DialogTitle>
        </DialogHeader>

        {isLoading && (
          <div className="space-y-3">
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-40 w-full" />
          </div>
        )}

        {!isLoading && !event && (
          <p className="py-8 text-center text-sm text-muted-foreground">
            {t('detail.notFound')}
          </p>
        )}

        {event && (
          <div className="space-y-5">
            <section aria-label={t('p6.journey.title')} className="rounded-lg border p-3 text-xs">
              <h3 className="mb-2 font-medium">{t('p6.journey.title')}</h3>
              <ol className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                {[
                  [t('p6.journey.ingress'), t(event.ingress === 'ext' ? 'p6.verify.ext' : 'p6.verify.proxy')],
                  [t('p6.journey.inspect'), event.decision ? t(DECISION_LABELS[event.decision] ?? event.decision) : t('p6.journey.missing')],
                  [t('p6.journey.forward'), typeof event.upstream_ms === 'number' ? formatDuration(event.upstream_ms) : t('p6.journey.missing')],
                  [t('p6.journey.restore'), typeof event.restored === 'number' ? String(event.restored) : t('p6.journey.missing')],
                ].map(([label, value], index) => <li key={label}>
                  <p className="text-muted-foreground">{index + 1}. {label}</p><p className="mt-1 break-words">{value}</p>
                </li>)}
              </ol>
            </section>
            {/* 基本信息 */}
            <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
              <MetaItem
                k={t('detail.type')}
                v={
                  <span className="font-mono text-xs font-semibold">{event.type}</span>
                }
              />
              <MetaItem k={t('detail.time')} v={dayjs(event.ts * 1000).format('YYYY-MM-DD HH:mm:ss')} />
              <MetaItem k={t('detail.session')} v={<code className="text-xs">{(event.sid || '—').slice(0, 16)}{event.sid ? '…' : ''}</code>} />
              <MetaItem k={t('detail.upstream')} v={<span className="text-xs font-medium">{event.upstream || (event as { client_app?: string }).client_app || '—'}</span>} />
              <MetaItem k={t('detail.model')} v={<code className="text-xs">{event.model || '—'}</code>} />
              <MetaItem
                k={t('detail.status')}
                v={
                  <Badge variant={event.http_status && event.http_status >= 400 ? 'destructive' : 'outline'}>
                    {event.http_status ?? event.status ?? '-'}
                  </Badge>
                }
              />
              <MetaItem
                k={t('detail.path')}
                wide
                v={<code className="text-xs">{event.method} {event.host}{event.path}</code>}
              />
              <MetaItem k={t('detail.duration')} v={formatDuration(event.total_ms ?? event.upstream_ms ?? event.first_byte_ms)} />
            </div>

            <section className="space-y-2 rounded-lg border bg-muted/20 p-3 text-xs" aria-label={t('transport.title')}>
              <h3 className="font-medium">{t('transport.title')}</h3>
              <dl className="grid grid-cols-2 gap-2">
                {[
                  [t('transport.phase'), transportLabel('phase', event.transport?.phase)],
                  [t('transport.reason'), transportLabel('reason', event.transport?.reason)],
                  [t('transport.connection'), event.transport?.server_conn_id || t('transport.unknown')],
                  [t('transport.protocol'), !event.transport?.protocol || event.transport.protocol === 'unknown' ? t('transport.unknown') : event.transport.protocol],
                  [t('transport.reused'), event.transport?.reused == null ? t('transport.unknown') : t(event.transport.reused ? 'transport.yes' : 'transport.no')],
                  [t('transport.proxy'), event.transport?.via_proxy == null ? t('transport.unknown') : t(event.transport.via_proxy ? 'transport.yes' : 'transport.no')],
                  [t('transport.idle'), event.transport?.idle_s == null ? t('transport.unknown') : String(event.transport.idle_s)],
                  [t('transport.connect'), event.transport?.connect_ms == null ? t('transport.unknown') : formatDuration(event.transport.connect_ms)],
                  [t('transport.tls'), event.transport?.tls_ms == null ? t('transport.unknown') : formatDuration(event.transport.tls_ms)],
                  [t('transport.evidence'), event.transport?.evidence_complete == null ? t('transport.unknown') : t(event.transport.evidence_complete ? 'transport.complete' : 'transport.partial')],
                ].map(([label, value]) => <div key={label} className="min-w-0"><dt className="text-muted-foreground">{label}</dt><dd className="break-all">{value}</dd></div>)}
              </dl>
              <p className="text-muted-foreground">{t('transport.caution')}</p>
              {event.failure_phase && <p>{t('transport.localPhase')}: {transportLabel('phase', event.failure_phase)}</p>}
              {event.upstream_may_have_executed && <p>{t('transport.executed')}</p>}
            </section>
            {(event.ner_init_ms != null || event.ner_infer_ms != null || event.ner_budget_wait_ms != null) && (
              <p className="text-xs text-muted-foreground">{t('detail.nerTiming')}: {[event.ner_init_ms, event.ner_infer_ms, event.ner_budget_wait_ms].map((v) => v == null ? t('transport.unknown') : formatDuration(v)).join(' / ')}</p>
            )}

            {/* 流式信息（stream_actual 与 stream_mode 背离提示） */}
            {event.stream_mode && (
              <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/40 p-2.5 text-xs">
                <span className="text-muted-foreground">{t('detail.stream')}</span>
                <Badge variant="outline">{event.stream_mode}</Badge>
                {event.stream_actual && (
                  <>
                    <span className="text-muted-foreground">{t('detail.actual')}</span>
                    <Badge
                      variant={event.stream_actual === 'stream' ? 'outline' : 'secondary'}
                      className={cn(
                        event.stream_actual === 'stream_error' &&
                          'border-amber-500/40 text-amber-600 dark:text-amber-400',
                      )}
                    >
                      {event.stream_actual === 'stream'
                        ? t('detail.streamMode')
                        : event.stream_actual === 'whole'
                          ? t('detail.wholeFallback')
                          : t('detail.streamError')}
                    </Badge>
                  </>
                )}
              </div>
            )}

            {/* A-7 / C-1：503 归因 + 队列现场 + 语义识别降级计数。
                这是"503 到底怪谁"这个问题的唯一答案来源——字段一直进了事件库与导出，
                但此前**前端一个都没渲染**（等于用户看不到），所以在这里按"有则显示"补齐。
                注意：审计耗时/扫描字节那三个字段**不属于这里** —— 它们只存在于
                audit_events 表，渲染在 AuditEventDetailDialog；挂在这里是死分支
                （真这么写过一次：永远读到 undefined，比不渲染更糟）。 */}
            {(event.block_source || event.engine_busy || event.ner_global_throttled
              // 等待类指标必须单独放行：它们由不同的事件发出（aux 等待是
              // reason=response_offload_wait 的 ERR，只带 client 来源字段），
              // 挂在上面那三个字段的 gate 里就永远渲染不出来（死分支）。
              || typeof event.aux_wait_ms === 'number'
              || typeof event.ner_sem_wait_ms === 'number') && (
              <div className="space-y-1 rounded-lg border bg-muted/30 p-2.5 text-xs">
                {event.block_source && (
                  <div>
                    <span className="text-muted-foreground">{t('detail.blockSource')}：</span>
                    {t(`detail.blockSource.${event.block_source}`) === `detail.blockSource.${event.block_source}`
                      ? event.block_source
                      : t(`detail.blockSource.${event.block_source}`)}
                  </div>
                )}
                {event.engine_busy && (
                  <div className="text-amber-700 dark:text-amber-400">
                    {tf('detail.engineBusy', {
                      d: String(event.engine_queue_depth ?? '-'),
                      b: String(event.engine_queue_bytes ?? '-'),
                    })}
                  </div>
                )}
                {typeof event.ner_global_throttled === 'number' && event.ner_global_throttled > 0 && (
                  <div className="text-amber-700 dark:text-amber-400">
                    {tf('detail.nerGlobalThrottled', { n: String(event.ner_global_throttled) })}
                  </div>
                )}
                {typeof event.aux_wait_ms === 'number' && event.aux_wait_ms >= 1 && (
                  <div className="text-muted-foreground">
                    {tf('detail.auxWait', { ms: String(Math.round(event.aux_wait_ms)) })}
                  </div>
                )}
                {typeof event.ner_sem_wait_ms === 'number' && event.ner_sem_wait_ms >= 1 && (
                  <div className="text-muted-foreground">
                    {tf('detail.nerSemWait', { ms: String(Math.round(event.ner_sem_wait_ms)) })}
                  </div>
                )}
              </div>
            )}

            {/* C-2：本该流式却整包——把"为什么"直接写出来。
                用户看到的只是"字一个个蹦 vs 一坨蹦"，没有这条就只能翻配置猜。
                三种原因的可操作性不同，所以文案分开：编码问题是上游行为（改不了），
                排除名单是自己加的（改得了）。 */}
            {event.stream_degraded_reason && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs leading-relaxed text-amber-700 dark:text-amber-400">
                <div className="font-semibold">{t('detail.streamDegraded')}</div>
                <div className="mt-1">
                  {event.stream_degraded_reason.startsWith('content_encoding:')
                    ? tf('detail.streamDegraded.encoding', {
                        enc: event.stream_degraded_reason.slice('content_encoding:'.length),
                      })
                    : event.stream_degraded_reason === 'excluded_host'
                      ? t('detail.streamDegraded.excluded')
                      : event.stream_degraded_reason === 'non_sse'
                        ? t('detail.streamDegraded.non_sse')
                        : tf('detail.streamDegraded.other', { reason: event.stream_degraded_reason })}
                </div>
              </div>
            )}

            {/* C-2 附带：本条的脱敏排队时长（只在真排过队时出现）。
                它是"我这台机器/这套并发到底吃不吃得消"的直接证据，比看 CPU 直观。 */}
            {typeof event.queue_wait_ms === 'number' && event.queue_wait_ms >= 1 && (
              <div className="text-xs text-muted-foreground">
                {tf('detail.queueWait', { ms: String(Math.round(event.queue_wait_ms)) })}
              </div>
            )}

            {/* msg / reason 提示（_reasoning_effort_hint 等排查信息） */}
            {(event.msg || event.reason) && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs leading-relaxed text-amber-700 dark:text-amber-400">
                {event.msg && <div className="whitespace-pre-wrap">{event.msg}</div>}
                {event.reason && <div className="mt-1 text-muted-foreground">{transportLabel('reason', event.reason)}</div>}
                {/* 连续静默秒数是上面那句结论的证据：没有它，用户无法核对
                    「600 秒看门狗到点」这条判据有没有被误触发。 */}
                {typeof event.upstream_idle_s === 'number' && (
                  <div className="mt-1 text-muted-foreground">
                    {tf('detail.upstreamIdle', { s: String(Math.round(event.upstream_idle_s)) })}
                  </div>
                )}
              </div>
            )}

            {/* 本次检测结论（批次 2 统一口径）：把「扫了没命中 / 已脱敏 / 主动阻断 / 明确直通」
                四种状态分开显示——它们此前在列表里都表现为「0 命中」。完整度只表示
                「所配置的检测执行到什么程度」，不保证现实中没有漏检；原因码如实列出。 */}
            {(event.decision || event.completeness) && (
              <div className="rounded-lg border bg-muted/30 p-3 text-xs leading-relaxed">
                <div className="flex flex-wrap items-center gap-2">
                  {event.decision && (
                    <Badge
                      variant={event.decision === 'blocked' ? 'destructive' : 'secondary'}
                      className="text-[11px]"
                    >
                      {t(DECISION_LABELS[event.decision] || event.decision)}
                    </Badge>
                  )}
                  {event.completeness && (
                    <Badge variant="outline" className="text-[11px] font-normal">
                      {t(COMPLETENESS_LABELS[event.completeness] || event.completeness)}
                    </Badge>
                  )}
                </div>
                {reasonCodes.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {reasonCodes.map(([k, n]) => (
                      <Badge key={k} variant="outline" className="text-[11px] font-normal">
                        {t(NER_SKIP_LABELS[k] || k)} × {n}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* 语义识别（NER）降级提示。
                「静默降级」＝用户以为开了、其实没脱：正则/词表照常，但只有 NER 能识别的
                人名/机构/地址会整段明文上行（实测长会话下漏过 101/200 个人名）。
                所以一旦命中就必须在这条事件的详情里说清「为什么漏、漏了几条」，
                让用户能自己决定是调大预算还是关掉语义识别。 */}
            {event.ner_truncated && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs leading-relaxed text-amber-700 dark:text-amber-400">
                <div className="font-semibold">{t('detail.nerDegraded')}</div>
                <div className="mt-1 text-muted-foreground">{t('detail.nerDegradedHint')}</div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {Object.entries(event.ner_skip_reasons ?? {}).map(([k, n]) => (
                    <Badge key={k} variant="outline" className="text-[11px] font-normal">
                      {t(NER_SKIP_LABELS[k] || k)} × {n}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* 顶栏链路全景图：直观告知用户本条请求是 脱敏请求(出站) 还是 还原回复(入站) 或 异常/直连 */}
            {stageInfo && (
              <div className="rounded-lg border bg-muted/20 p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-muted-foreground">{t('detail.pipelineStage')}</span>
                    <Badge
                      className={cn(
                        'text-xs font-mono',
                        stageInfo.className
                      )}
                    >
                      {stageInfo.label}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-3 text-xs">
                    {(event.count ?? 0) > 0 && (
                      <span className="text-blue-600 dark:text-blue-400">
                        {t('logs.colMasked')} <strong>{event.count}</strong>
                      </span>
                    )}
                    {(event.restored ?? 0) > 0 && (
                      <span className="text-emerald-600 dark:text-emerald-400">
                        {t('logs.colRestored')} <strong>{event.restored}</strong>
                      </span>
                    )}
                    {(event.unresolved ?? 0) > 0 && (
                      <span className="text-amber-600 dark:text-amber-400" title={t('logs.unresolvedHint')}>
                        {t('logs.colUnresolved')} <strong>{event.unresolved}</strong>
                      </span>
                    )}
                    {(event.degraded ?? 0) > 0 && (
                      <span className="text-muted-foreground">
                        {t('logs.colDegraded')} <strong>{event.degraded}</strong>
                      </span>
                    )}
                  </div>
                </div>
                <p className="mt-1.5 text-[11px] text-muted-foreground leading-relaxed">
                  {stageInfo.desc}
                </p>
                {/* 未还原占位符样本：让「模型把占位符写错/自造」与「映射过期」一眼可分。
                    旧事件没有这个字段时不渲染（不给正常请求加噪声）。 */}
                {Array.isArray(event.unresolved_samples) && event.unresolved_samples.length > 0 && (
                  <div className="mt-1.5 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[11px] leading-snug text-amber-700 dark:text-amber-300">
                    <span>{t('logs.unresolvedSamples')}</span>
                    <span className="ml-1 font-mono">{event.unresolved_samples.join(' / ')}</span>
                  </div>
                )}
              </div>
            )}

            {/* 脱敏/还原项目对照（明文 → 占位符 / 占位符 → 明文） */}
            {event.items && event.items.length > 0 ? (
              <div>
                <h3 className="mb-2 text-[13px] font-semibold">
                  {event.type === 'RESTORE' && (event.restored ?? 0) > 0
                    ? tf('detail.restoreItemsWithTotal', { n: event.items.length, total: event.restored })
                    : tf(event.type === 'RESTORE' ? 'detail.restoreItems' : 'detail.maskItems', { n: event.items.length })}
                </h3>
                <div className="space-y-2">
                  {(event.items as { label: string; original?: string; preview?: string; tok?: string; hash?: string; length?: number; restored?: boolean; from_history?: boolean }[]).map(
                    (item, idx) => {
                      const isRestored = (event.type === 'RESTORE' && item.restored !== false) || item.restored === true
                      const notRestored = event.type === 'RESTORE' && item.restored === false
                      return (
                        <div key={item.label + idx} className={cn("rounded-lg border bg-card p-3", isRestored && "border-emerald-500/30 bg-emerald-500/5")}>
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              {isRestored && (
                                <span className="flex items-center gap-1 rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-600 dark:text-emerald-400" title={t('detail.itemRestored')}>
                                  <CheckCircle2 className="h-3 w-3" />
                                  <span>{t('detail.itemRestored')}</span>
                                </span>
                              )}
                              {notRestored && (
                                <span className="flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground" title={t('detail.itemNotRestored')}>
                                  <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/50" />
                                  <span>{t('detail.itemNotRestored')}</span>
                                </span>
                              )}
                              <Badge variant="outline" className="font-mono text-[11px]">
                                {item.label}
                              </Badge>
                              {item.from_history && (
                                <Badge variant="secondary" className="text-[10px] font-normal text-muted-foreground">
                                  {t('detail.fromHistory')}
                                </Badge>
                              )}
                            </div>
                            {item.original != null && <CopyBtn text={item.original} />}
                          </div>
                          <div className="mt-2 space-y-1.5 font-mono text-xs leading-relaxed">
                            {item.original != null && (
                              <div className="flex items-start gap-2">
                                <span className="w-12 shrink-0 text-muted-foreground">{t('detail.original')}</span>
                                <span className="break-all font-semibold text-foreground">{item.original}</span>
                              </div>
                            )}
                            {item.preview != null && (
                              <div className="flex items-start gap-2">
                                <span className="w-12 shrink-0 text-muted-foreground">{t('detail.preview')}</span>
                                <span className="break-all text-muted-foreground">{item.preview}</span>
                              </div>
                            )}
                            {item.tok != null && (
                              <div className="flex items-start gap-2">
                                <span className="w-12 shrink-0 text-muted-foreground">{t('detail.placeholder')}</span>
                                <span className="break-all rounded bg-blue-500/10 px-1 text-blue-600 dark:text-blue-400">
                                  {item.tok}
                                </span>
                              </div>
                            )}
                            {item.hash != null && (
                              <div className="flex items-start gap-2 text-muted-foreground">
                                <span className="w-12 shrink-0">{t('detail.hash')}</span>
                                <span className="break-all">{item.hash}</span>
                                {item.length != null && (
                                  <span className="shrink-0">({tf('detail.length', { n: item.length })})</span>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      )
                    },
                  )}
                </div>
              </div>
            ) : event.type === 'RESTORE' && (event.restored ?? 0) > 0 ? (
              <div className="rounded-lg border bg-muted/20 p-3 text-xs text-muted-foreground leading-relaxed">
                <div className="font-medium text-foreground">{t('detail.noItemsTitle')}</div>
                <p className="mt-1">{tf('detail.noItemsDesc', { n: event.restored })}</p>
              </div>
            ) : null}

            {/* 用户请求原文（dialog_req） */}
            {event.dialog_req && (
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <h3 className="text-[13px] font-semibold">{t('detail.reqOriginal')}</h3>
                    <span className="text-[11px] text-muted-foreground">
                      {event.dialog_req.length.toLocaleString()} {t('detail.chars')} · {tf('detail.approxTokens', { n: Math.ceil(event.dialog_req.length / 3.5).toLocaleString() })}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    {originals.length > 0 && (
                      <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground" title={t('detail.highlightTitle')}>
                        <Switch
                          checked={hl}
                          onCheckedChange={setHl}
                          className="scale-75"
                        />
                        <span>{t('detail.highlight')}</span>
                      </label>
                    )}
                    <CopyBtn text={event.dialog_req} />
                  </div>
                </div>
                <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-all rounded-lg border bg-muted/40 p-3 font-mono text-xs leading-relaxed">
                  {hl ? highlightOriginals(event.dialog_req, originals) : event.dialog_req}
                </pre>
              </div>
            )}
            {/* 对话内容（明文） */}
            {event.dialog && (
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <h3 className="text-[13px] font-semibold">
                      {event.type === 'MASK' ? t('detail.userMsg') : event.type === 'RESTORE' ? t('detail.assistantMsg') : t('detail.bodyText')}
                    </h3>
                    <span className="text-[11px] text-muted-foreground">
                      {event.dialog.length.toLocaleString()} {t('detail.chars')} · {tf('detail.approxTokens', { n: Math.ceil(event.dialog.length / 3.5).toLocaleString() })}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    {originals.length > 0 && (
                      <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground" title={t('detail.highlightTitle')}>
                        <Switch
                          checked={hl}
                          onCheckedChange={setHl}
                          className="scale-75"
                        />
                        <span>{t('detail.highlight')}</span>
                      </label>
                    )}
                    <CopyBtn text={event.dialog} />
                  </div>
                </div>
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-lg border bg-muted/40 p-3 font-mono text-xs leading-relaxed">
                  {hl ? highlightOriginals(event.dialog, originals) : event.dialog}
                </pre>
              </div>
            )}

            {/* 正文预览兜底（当无全量 dialog 时展示截断预览） */}
            {!event.dialog_req && !event.dialog && Boolean(event.req_preview || (event as { resp_preview?: string }).resp_preview) && (
              <div className="space-y-3">
                {event.req_preview && (
                  <div>
                    <h3 className="mb-2 text-[13px] font-semibold">{t('detail.reqOriginal')}</h3>
                    <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-all rounded-lg border bg-muted/40 p-3 font-mono text-xs leading-relaxed">
                      {event.req_preview}
                    </pre>
                  </div>
                )}
                {(event as { resp_preview?: string }).resp_preview && (
                  <div>
                    <h3 className="mb-2 text-[13px] font-semibold">{t('detail.assistantMsg')}</h3>
                    <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-all rounded-lg border bg-muted/40 p-3 font-mono text-xs leading-relaxed">
                      {(event as { resp_preview?: string }).resp_preview}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {/* 最小记录模式下正文根本没落盘：必须**明确写「未记录」**，
                而不是留一片空白让用户猜是脱敏失败还是 UI 坏了（§D1/§E）。 */}
            {logMode === 'summary' && !event.dialog_req && !event.dialog && !event.req_preview &&
              !(event as { resp_preview?: string }).resp_preview && (
                <p className="rounded-lg border border-dashed bg-muted/30 p-3 text-xs text-muted-foreground">
                  {t('detail.notRecorded')}
                </p>
              )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
