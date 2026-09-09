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
import { EventTypeIcon } from '@/components/events/EventTypeIcon'
import { CheckCircle2 } from 'lucide-react'
import type { ShieldEvent } from '@/types/api'
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
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
  seq: number | null
}) {
  const { t, tf } = useI18n()
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

  // 可高亮的原文：凭据类只有 preview + sha256，没有明文可匹配
  const originals = useMemo(
    () => ((event?.items ?? []) as { original?: string }[])
      .map((i) => i.original)
      .filter((s): s is string => typeof s === 'string' && s.length > 0),
    [event],
  )

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

            {/* msg / reason 提示（_reasoning_effort_hint 等排查信息） */}
            {(event.msg || event.reason) && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs leading-relaxed text-amber-700 dark:text-amber-400">
                {event.msg && <div className="whitespace-pre-wrap">{event.msg}</div>}
                {event.reason && <div className="mt-1 text-muted-foreground">{event.reason}</div>}
              </div>
            )}

            {/* 脱敏/还原项目对照（明文 → 占位符 / 占位符 → 明文） */}
            {event.items && event.items.length > 0 && (
              <div>
                <h3 className="mb-2 text-[13px] font-semibold">
                  {tf(event.type === 'RESTORE' ? 'detail.restoreItems' : 'detail.maskItems', { n: event.items.length })}
                </h3>
                <div className="space-y-2">
                  {(event.items as { label: string; original?: string; preview?: string; tok?: string; hash?: string; length?: number; restored?: boolean }[]).map(
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
                            </div>
                            {item.original != null && <CopyBtn text={item.original} />}
                          </div>
                          <div className="mt-2 space-y-1.5 font-mono text-xs leading-relaxed">
                            {item.original != null && (
                              <div className="flex gap-2">
                                <span className="w-10 shrink-0 text-muted-foreground">{t('detail.original')}</span>
                                <span className="break-all">{item.original}</span>
                              </div>
                            )}
                            {item.preview != null && (
                              <div className="flex gap-2">
                                <span className="w-10 shrink-0 text-muted-foreground">{t('detail.preview')}</span>
                                <span className="break-all text-muted-foreground">{item.preview}</span>
                              </div>
                            )}
                            {item.tok != null && (
                              <div className="flex gap-2">
                                <span className="w-10 shrink-0 text-muted-foreground">{t('detail.placeholder')}</span>
                                <span className="break-all text-blue-600 dark:text-blue-400">
                                  {item.tok}
                                </span>
                              </div>
                            )}
                            {item.hash != null && (
                              <div className="flex gap-2">
                                <span className="w-10 shrink-0 text-muted-foreground">{t('detail.hash')}</span>
                                <span className="break-all text-muted-foreground">{item.hash}</span>
                                {item.length != null && (
                                  <span className="text-muted-foreground">（len={item.length}）</span>
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
            )}

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
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
