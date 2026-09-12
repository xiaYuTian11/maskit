/**
 * 审计中心（日志审计，被动）——对标旧版「探针主动审计」重构：
 * - 主动探针（会发真实请求消耗 token）已移到「设置-高级选项」
 * - 本页专注：审计配置（开关/S1-S9 信号）+ 被动审计事件列表 + 详情弹窗
 */
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { useVisibility } from '@/lib/useVisibility'
import { Trash2, Radar, ShieldCheck, Info, Play } from 'lucide-react'
import {
  getAuditEvents,
  clearAudit,
} from '@/api/audit'
import { getConfig, patchConfig, type ConfigPatch } from '@/api/settings'
import type { AuditEvent, AuditSeverity } from '@/types/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { AuditEventDetailDialog, SIGNAL_INFO, SIGNAL_ORDER, severityMeta, signalInfo } from '@/components/audit/AuditEventDetailDialog'
import { cn } from '@/lib/utils'
import { toast } from '@/lib/toast'
import dayjs from 'dayjs'
import { useI18n } from '@/lib/i18n'

export default function AuditPage() {
  const { t, tf } = useI18n()
  const queryClient = useQueryClient()
  const { hidden } = useVisibility()

  // 配置（审计开关 / 信号）
  const { data: cfg } = useQuery({ queryKey: ['config'], queryFn: getConfig })
  const auditCfg = (cfg?.audit as Record<string, unknown>) ?? {}
  const auditSignals = (auditCfg.signals as Record<string, boolean>) ?? {}
  const [detailEvent, setDetailEvent] = useState<AuditEvent | null>(null)

  // 只下发被改动的那一个审计开关；提交整个 audit 对象会覆盖别处（如 Settings 页）
  // 并发的修改，也会把 audit.signals 整表用陈旧快照替换掉。
  const saveAudit = async (patch: Omit<ConfigPatch, 'key'>) => {
    if (!cfg) return
    try {
      const r = await patchConfig({ key: 'audit', ...patch })
      if (!r.ok) toast(r.error || t('common.saveFail'), 'error')
      queryClient.invalidateQueries({ queryKey: ['config'] })
    } catch (e) { toast(tf('common.saveFailWith', { e: String(e) }), 'error') }
  }

  // 审计事件列表
  const { data: eventsData, isLoading: eventsLoading } = useQuery({
    queryKey: ['auditEvents'],
    queryFn: () => getAuditEvents(0, 500),
    refetchInterval: hidden ? false : 3000,
  })

  const events = useMemo(() => eventsData?.events ?? [], [eventsData])

  // 筛选：严重度 + 信号类型（前端过滤，500 条足够实时）
  const [sevFilter, setSevFilter] = useState<string>('__ALL__')
  const [sigFilter, setSigFilter] = useState<string>('__ALL__')
  const filteredEvents = useMemo(() => {
    return events.filter((ev) => {
      if (sevFilter !== '__ALL__' && ev.severity !== sevFilter) return false
      if (sigFilter !== '__ALL__' && ev.signal_type !== sigFilter) return false
      return true
    })
  }, [events, sevFilter, sigFilter])
  const availableSignals = useMemo(() =>
    [...new Set(events.map((e) => e.signal_type))].sort(), [events])

  const navigate = useNavigate()

  const clearMutation = useMutation({
    mutationFn: clearAudit,
    onSuccess: () => {
      toast(t('audit.cleared'))
      queryClient.invalidateQueries({ queryKey: ['auditEvents'] })
    },
    onError: (e: Error) => toast(tf('audit.clearFail', { e: e.message }), 'error'),
  })

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t('nav.audit')}</h1>
          <p className="mt-1 text-sm font-medium text-muted-foreground">
            {t('audit.subtitle')}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="default"
            className="gap-1.5"
            onClick={() => navigate('/settings?tab=advanced')}
          >
            <Play className="h-4 w-4" /> {t('audit.runProbe')}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => clearMutation.mutate()}
            loading={clearMutation.isPending}
            className="gap-1.5 text-destructive hover:text-destructive"
          >
            {!clearMutation.isPending && <Trash2 className="h-4 w-4" />} {t('common.clear')}
          </Button>
        </div>
      </div>

      {/* ===== 审计配置（基础 + 高级） ===== */}
      <Card className="border bg-card shadow-[var(--shadow-card)]">
        <CardHeader className="flex-row items-center gap-2 space-y-0">
          <ShieldCheck className="h-5 w-5 text-primary" />
          <CardTitle className="text-sm">{t('audit.config')}</CardTitle>
          <span className={cn('ml-auto rounded-full px-2.5 py-0.5 text-xs font-medium', auditCfg.enabled ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-muted text-muted-foreground')}>
            {auditCfg.enabled ? t('audit.enabled') : t('audit.disabled')}
          </span>
        </CardHeader>
        <CardContent className="space-y-5">
          {/* 基础：一行三个开关卡 */}
          <div className="grid gap-3 sm:grid-cols-3">
            {([
              ['enabled', t('audit.enable'), t('audit.enableDesc')],
              ['passive', t('audit.passive'), t('audit.passiveDesc')],
              ['active_probes', t('audit.probes'), t('audit.probesDesc')],
            ] as [string, string, string][]).map(([k, title, desc]) => (
              <label key={k} className="flex cursor-pointer select-none flex-col justify-between rounded-lg border bg-muted/30 p-3 transition-colors hover:border-primary/40">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[13px] font-medium">{title}</span>
                  <Switch checked={!!(auditCfg[k] as boolean)} onCheckedChange={(v) => saveAudit({ op: 'set', path: [k], value: v })} className="scale-90" />
                </div>
                <p className="mt-1 text-[11px] text-muted-foreground">{desc}</p>
              </label>
            ))}
          </div>

          {/* 高级：自动报告 + 严重度门槛 */}
          <div className="grid gap-3 md:grid-cols-2">
            <label className="flex cursor-pointer select-none flex-col justify-between rounded-lg border bg-muted/30 p-3 transition-colors hover:border-primary/40">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-medium">{t('audit.autoReport')}</span>
                <Switch checked={!!(auditCfg.auto_report as boolean)} onCheckedChange={(v) => saveAudit({ op: 'set', path: ['auto_report'], value: v })} className="scale-90" />
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">{t('audit.reportHint')}</p>
            </label>
            <div className="rounded-lg border bg-muted/30 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-medium">{t('audit.severityFloor')}</span>
                <Select value={String(auditCfg.severity_floor ?? 'MEDIUM')} onValueChange={(v) => saveAudit({ op: 'set', path: ['severity_floor'], value: v })}>
                  <SelectTrigger className="h-8 w-44 text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="LOW">{t('audit.severityLow')}</SelectItem>
                    <SelectItem value="MEDIUM">{t('audit.severityMedium')}</SelectItem>
                    <SelectItem value="HIGH">{t('audit.severityHigh')}</SelectItem>
                    <SelectItem value="CRITICAL">{t('audit.severityCritical')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">{t('audit.floorHint')}</p>
            </div>
          </div>

          {/* 信号开关 S1-S9 */}
          <div>
            <div className="mb-2 flex items-center gap-1.5 text-sm font-medium">
              {t('audit.signalsTitle2')}
              <span className="inline-flex items-center gap-1 text-[11px] font-normal text-muted-foreground" title={t('audit.clickHint2')}>
                <Info className="h-3 w-3" /> {t('audit.clickHint')}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1 md:grid-cols-4">
              {SIGNAL_ORDER.map((sig) => {
                const info = SIGNAL_INFO[sig]
                return (
                  <label key={sig} className="flex items-center justify-between border-b py-2">
                    <button
                      type="button"
                      className="group flex min-w-0 items-center gap-1 text-[13px] text-muted-foreground hover:text-foreground"
                      onClick={() => setDetailEvent({
                        seq: -1,
                        ts: 0,
                        signal_type: sig,
                        severity: 'MEDIUM' as AuditSeverity,
                        evidence: t(info.reasonKey),
                      } as AuditEvent)}
                      title={t('audit.clickReason')}
                    >
                      <span className="truncate">{t(info.labelKey ?? info.label ?? '')}</span>
                      <Info className="h-3 w-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-60" />
                    </button>
                    <Switch checked={!!auditSignals[sig]} onCheckedChange={(v) => saveAudit({ op: 'set', path: ['signals', sig], value: v })} className="scale-75" />
                  </label>
                )
              })}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 信号识别轻量提示 */}
      <div className="flex items-center gap-2 rounded-xl border border-blue-500/20 bg-blue-500/5 px-4 py-2.5 text-xs text-muted-foreground">
        <Info className="h-4 w-4 shrink-0 text-blue-500" />
        <span>{t('audit.judgeCompact')}</span>
      </div>

      {/* 审计事件列表 */}
      <Card className="border bg-card shadow-[var(--shadow-card)]">
        <CardContent className="p-4">
          <div className="mb-3 flex items-center gap-2">
            <Radar className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-semibold">{t('audit.events')}</span>
            <Badge variant="outline" className="ml-auto text-xs">
              {eventsData?.count ?? 0} {t('audit.countSuffix')}
            </Badge>
          </div>

          {/* 筛选器：严重度 + 信号类型 */}
          {events.length > 0 && (
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <Select value={sevFilter} onValueChange={setSevFilter}>
                <SelectTrigger className="h-8 w-36 text-xs"><SelectValue placeholder={t('audit.filterSeverity')} /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="__ALL__">{t('audit.filterAllSeverity')}</SelectItem>
                  <SelectItem value="CRITICAL">{t('audit.sevCritical')}</SelectItem>
                  <SelectItem value="HIGH">{t('audit.sevHigh')}</SelectItem>
                  <SelectItem value="MEDIUM">{t('audit.sevMedium')}</SelectItem>
                  <SelectItem value="LOW">{t('audit.sevLow')}</SelectItem>
                </SelectContent>
              </Select>
              <Select value={sigFilter} onValueChange={setSigFilter}>
                <SelectTrigger className="h-8 w-44 text-xs"><SelectValue placeholder={t('audit.filterSignal')} /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="__ALL__">{t('audit.filterAllSignals')}</SelectItem>
                  {availableSignals.map((s) => (
                    <SelectItem key={s} value={s}>{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {(sevFilter !== '__ALL__' || sigFilter !== '__ALL__') && (
                <Button size="sm" variant="ghost" className="h-8 px-2 text-xs" onClick={() => { setSevFilter('__ALL__'); setSigFilter('__ALL__') }}>
                  {t('common.reset')}
                </Button>
              )}
            </div>
          )}

          {eventsLoading && events.length === 0 ? (
            <div className="space-y-2">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : events.length === 0 ? (
            <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-emerald-500/30 bg-emerald-500/5 py-12 text-center">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                <ShieldCheck className="h-6 w-6" />
              </div>
              <h4 className="mt-3 text-sm font-semibold text-foreground">{t('audit.emptySafeTitle')}</h4>
              <p className="mt-1 max-w-md text-xs text-muted-foreground">
                {t('audit.emptySafeDesc')}
              </p>
              <Button
                size="sm"
                variant="outline"
                className="mt-4 gap-1.5 border-emerald-500/30 text-emerald-600 hover:bg-emerald-500/10 hover:text-emerald-700 dark:text-emerald-400"
                onClick={() => navigate('/settings?tab=advanced')}
              >
                <Play className="h-3.5 w-3.5" />
                {t('audit.runProbe')}
              </Button>
            </div>
          ) : filteredEvents.length === 0 ? (
            <div className="py-10 text-center text-sm text-muted-foreground">
              <Radar className="mx-auto mb-3 h-8 w-8 text-muted-foreground/50" />
              {t('audit.noEventsAfterFilter')}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table className="w-full text-left text-[13px]">
                <TableHeader>
                  <TableRow className="border-b text-xs text-muted-foreground">
                    <TableHead className="pb-2 pr-3 font-medium">{t('audit.colSeverity')}</TableHead>
                    <TableHead className="pb-2 pr-3 font-medium">{t('audit.colSignal')}</TableHead>
                    <TableHead className="pb-2 pr-3 font-medium">{t('audit.colTime')}</TableHead>
                    <TableHead className="pb-2 pr-3 font-medium">{t('audit.colRequest')}</TableHead>
                    <TableHead className="pb-2 pr-3 font-medium">{t('audit.colProbe')}</TableHead>
                    <TableHead className="pb-2 font-medium">{t('audit.colEvidence')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody className="divide-y divide-border/60">
                  {filteredEvents.map((ev) => {
                    const sev = severityMeta(ev.severity)
                    const req = [ev.method, ev.path].filter(Boolean).join(' ')
                    const info = signalInfo(ev.signal_type)
                    return (
                      <TableRow
                        key={ev.seq}
                        className="cursor-pointer align-top transition-colors hover:bg-muted/30"
                        onClick={() => setDetailEvent(ev)}
                        title={`${t('common.viewDetail')}：${t(info.labelKey ?? info.label ?? '')}`}
                      >
                        <TableCell className="py-2 pr-3">
                          <Badge variant="outline" className={cn('shrink-0 rounded-full text-[11px]', sev.cls)}>
                            {t(sev.labelKey)}
                          </Badge>
                        </TableCell>
                        <TableCell className="py-2 pr-3">
                          <span className="font-mono text-xs font-medium">{t(info.labelKey ?? info.label ?? '')}</span>
                        </TableCell>
                        <TableCell className="whitespace-nowrap py-2 pr-3 text-xs text-muted-foreground">
                          {dayjs(ev.ts * 1000).format('MM-DD HH:mm:ss')}
                        </TableCell>
                        <TableCell className="max-w-[200px] truncate py-2 pr-3 font-mono text-xs text-muted-foreground">
                          {req || ev.host || '—'}
                        </TableCell>
                        <TableCell className="max-w-[120px] truncate py-2 pr-3 text-xs text-muted-foreground">
                          {ev.probe_id || '—'}
                        </TableCell>
                        <TableCell className="max-w-[240px] truncate py-2 text-xs text-muted-foreground">
                          {ev.evidence || '—'}
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 审计事件详情弹窗（共用组件：审计中心与日志页同款） */}
      <AuditEventDetailDialog event={detailEvent} onOpenChange={(v) => !v && setDetailEvent(null)} />
    </div>
  )
}
