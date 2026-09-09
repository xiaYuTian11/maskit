/**
 * 审计事件详情弹窗（审计中心与拦截日志页共用）：
 * - 日志页审计行点击后原地打开（此前跳转审计中心，用户要求本页查看）
 * - 原因分析 + 危害说明 + 证据 + 请求 + 探针 ID
 */
import { useState } from 'react'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import type { AuditEvent, AuditSeverity } from '@/types/api'
import { cn, copyText } from '@/lib/utils'
import { useI18n } from '@/lib/i18n'
import dayjs from 'dayjs'

function CopyEvidenceBtn({ text }: { text: string }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  return (
    <Button
      size="sm"
      variant="ghost"
      className="h-5 px-1.5 text-[10px]"
      onClick={async () => {
        try {
          await copyText(text)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        } catch {}
      }}
    >
      {copied ? t('detail.copied') : t('detail.copy')}
    </Button>
  )
}

export const SEVERITY_META: Record<AuditSeverity, { labelKey: string; cls: string }> = {
  CRITICAL: {
    labelKey: 'audit.sevCritical',
    cls: 'border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400',
  },
  HIGH: {
    labelKey: 'audit.sevHigh',
    cls: 'border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400',
  },
  MEDIUM: {
    labelKey: 'audit.sevMedium',
    cls: 'border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  },
  LOW: {
    labelKey: 'audit.sevLow',
    cls: 'border-slate-400/40 bg-slate-400/10 text-slate-600 dark:text-slate-400',
  },
}

export function severityMeta(sev: string) {
  return (
    SEVERITY_META[sev as AuditSeverity] ?? {
      labelKey: sev,
      cls: 'border-border bg-muted text-muted-foreground',
    }
  )
}

/** 审计信号说明（弹窗详情引用）：信号 -> {中文名, 原因分析, 危害} */
export const SIGNAL_INFO: Record<string, { labelKey?: string; label?: string; reasonKey: string; impactKey: string }> = {
  error_leak: {
    labelKey: 'audit.s1', label: 'S1 错误泄漏',
    reasonKey: 'audit.s1Reason', impactKey: 'audit.s1Impact',
  },
  identity_swap: {
    labelKey: 'audit.s2', label: 'S2 身份换芯',
    reasonKey: 'audit.s2Reason', impactKey: 'audit.s2Impact',
  },
  tool_call_rewrite: {
    labelKey: 'audit.s3', label: 'S3 工具调用改写',
    reasonKey: 'audit.s3Reason', impactKey: 'audit.s3Impact',
  },
  sse_anomaly: {
    labelKey: 'audit.s4', label: 'S4 SSE 异常',
    reasonKey: 'audit.s4Reason', impactKey: 'audit.s4Impact',
  },
  response_poison: {
    labelKey: 'audit.s6', label: 'S6 响应投毒',
    reasonKey: 'audit.s6Reason', impactKey: 'audit.s6Impact',
  },
  cross_request_pollution: {
    labelKey: 'audit.s7', label: 'S7 跨请求污染',
    reasonKey: 'audit.s7Reason', impactKey: 'audit.s7Impact',
  },
  dangerous_action: {
    labelKey: 'audit.s9', label: 'S9 危险动作',
    reasonKey: 'audit.s9Reason', impactKey: 'audit.s9Impact',
  },
}

/** 未知信号的兜底（结构与已知信号一致，reason/impact 用通用文案） */
export function signalInfo(sig: string) {
  return (
    SIGNAL_INFO[sig] ?? {
      labelKey: sig,
      label: sig,
      reasonKey: 'audit.unknownReason',
      impactKey: 'audit.unknownImpact',
    }
  )
}

/** 当前安全信号顺序（S1-S4、S6-S7、S9）。S5 当前请求回显与 S8 提示词句式检测已移除，
 * 保留跨请求污染 S7 作为唯一高置信度 nonce 泄漏信号。 */
export const SIGNAL_ORDER = [
  'error_leak',
  'identity_swap',
  'tool_call_rewrite',
  'sse_anomaly',
  'response_poison',
  'cross_request_pollution',
  'dangerous_action',
] as const

export function AuditEventDetailDialog({
  event,
  onOpenChange,
}: {
  event: AuditEvent | null
  onOpenChange: (v: boolean) => void
}) {
  const { t } = useI18n()
  return (
    <Dialog open={event !== null} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        {event && (() => {
          const info = signalInfo(event.signal_type)
          const sev = severityMeta(event.severity)
          const isInfoMode = event.seq === -1
          return (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  {isInfoMode ? t('audit.signalInfo') : t('audit.detailTitle')}
                  <Badge variant="outline" className={cn('rounded-full text-[11px]', sev.cls)}>
                    {t(sev.labelKey)}
                  </Badge>
                </DialogTitle>
                <DialogDescription className="flex items-center gap-1.5">
                  <span className="font-mono text-xs">{t(info.labelKey ?? info.label ?? '')}</span>
                  {!isInfoMode && event.ts > 0 && (
                    <span className="text-xs text-muted-foreground">
                      · {dayjs(event.ts * 1000).format('YYYY-MM-DD HH:mm:ss')}
                    </span>
                  )}
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 text-sm">
                <div>
                  <div className="mb-1 text-xs font-semibold text-muted-foreground">{t('audit.dialogSignalType')}</div>
                  <code className="rounded bg-muted/60 px-1.5 py-0.5 font-mono text-xs">{event.signal_type}</code>
                </div>
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
                  <div className="mb-1 text-xs font-semibold text-amber-700 dark:text-amber-400">{t('audit.dialogReason')}</div>
                  <p className="text-xs leading-relaxed text-amber-800/90 dark:text-amber-200/90">{t(info.reasonKey)}</p>
                </div>
                <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3">
                  <div className="mb-1 text-xs font-semibold text-red-700 dark:text-red-400">{t('audit.dialogImpact')}</div>
                  <p className="text-xs leading-relaxed text-red-800/90 dark:text-red-200/90">{t(info.impactKey)}</p>
                </div>
                {event.evidence && !isInfoMode && (
                  <div>
                    <div className="mb-1 flex items-center justify-between">
                      <span className="text-xs font-semibold text-muted-foreground">{t('audit.evidence')}</span>
                      <CopyEvidenceBtn text={event.evidence} />
                    </div>
                    <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-muted/60 p-2.5 font-mono text-[11px] leading-relaxed text-foreground">
                      {event.evidence}
                    </pre>
                  </div>
                )}
                {!isInfoMode && (event.host || event.method || event.path) && (
                  <div>
                    <div className="mb-1 text-xs font-semibold text-muted-foreground">{t('audit.request')}</div>
                    <code className="rounded bg-muted/60 px-1.5 py-0.5 font-mono text-xs">
                      {[event.method, event.host, event.path].filter(Boolean).join(' ')}
                    </code>
                  </div>
                )}
                {!isInfoMode && event.probe_id && (
                  <div>
                    <div className="mb-1 text-xs font-semibold text-muted-foreground">{t('audit.probeId')}</div>
                    <code className="rounded bg-muted/60 px-1.5 py-0.5 font-mono text-xs">{event.probe_id}</code>
                  </div>
                )}
              </div>
              <DialogFooter>
                <Button size="sm" variant="outline" onClick={() => onOpenChange(false)}>
                  {t('audit.close')}
                </Button>
              </DialogFooter>
            </>
          )
        })()}
      </DialogContent>
    </Dialog>
  )
}
