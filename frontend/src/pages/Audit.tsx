/**
 * 审计中心（日志审计，被动）——对标旧版「探针主动审计」重构：
 * - 主动探针（会发真实请求消耗 token）已移到「设置-高级选项」
 * - 本页专注：审计配置（开关/S1-S9 信号）+ 被动审计事件列表 + 详情弹窗
 */
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVisibility } from '@/lib/useVisibility'

/**
 * 一次拉取的审计事件条数（服务端上限 1000，见 `fetch_audit_events`）。
 *
 * 筛选是纯客户端的，所以这个数字同时是**筛选的作用域**：窗口被填满时，
 * 「筛选后为空」可能只是命中的事件落在窗口之外。UI 必须把这个前提说出来
 * （见 `windowFull`），否则等于把「我没看到」当成「不存在」。
 */
const AUDIT_WINDOW = 500
import { Trash2, Radar, ShieldCheck, Info, Play, Loader2, X, FileText, HelpCircle, Activity, RefreshCw, Ban, Plus } from 'lucide-react'
import { Hint } from '@/components/common/Hint'
import {
  getAuditEvents,
  clearAudit,
  runAudit,
  getAuditJob,
  cancelAudit,
  getAuditReport,
} from '@/api/audit'
import { getConfig, patchConfig, type ConfigPatch } from '@/api/settings'
import type { AuditEvent, AuditSeverity } from '@/types/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { PageHeader } from '@/components/patterns/PageHeader'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { AuditEventDetailDialog, SIGNAL_INFO, SIGNAL_ORDER, severityMeta, signalInfo } from '@/components/audit/AuditEventDetailDialog'
import { cn } from '@/lib/utils'
import { toast } from '@/lib/toast'
import dayjs from 'dayjs'
import { useI18n } from '@/lib/i18n'

/** 命令拦截规则条目（与引擎 `config.command_block.patterns` 同形）。
 * `builtin` 只用于界面标注「内置」；**删除靠数组本身**（服务端只在 patterns 键缺失时
 * 灌种子，所以删掉的内置条目不会复活）。 */
type CmdPattern = {
  id?: string
  label: string
  regex: string
  enabled: boolean
  builtin?: boolean
}

export default function AuditPage() {
  const { t, tf } = useI18n()
  const queryClient = useQueryClient()
  const { hidden } = useVisibility()

  // 配置（审计开关 / 信号）
  const { data: cfg } = useQuery({ queryKey: ['config'], queryFn: getConfig })
  const auditCfg = (cfg?.audit as Record<string, unknown>) ?? {}
  const auditSignals = (auditCfg.signals as Record<string, boolean>) ?? {}
  const upstreams = useMemo(() => cfg?.upstreams ?? [], [cfg])
  const [detailEvent, setDetailEvent] = useState<AuditEvent | null>(null)
  const [auditSubTab, setAuditSubTab] = useState<'events' | 'timeline' | 'probe'>('events')

  // 主动探针任务状态与控制
  const [auditUpstream, setAuditUpstream] = useState('')
  const [auditModel, setAuditModel] = useState('')
  const [auditProfile, setAuditProfile] = useState('general')
  const [confirmAudit, setConfirmAudit] = useState(false)
  // 清空审计的二次确认（审计 L8）。与 confirmAudit 分开：探针确认与破坏性清空
  // 是两件事，共用一个状态会让「点清空却弹出探针确认」。
  const [confirmClearAudit, setConfirmClearAudit] = useState(false)
  const [auditReport, setAuditReport] = useState<string | null>(null)
  const [reportFetching, setReportFetching] = useState(false)

  const { data: auditJob } = useQuery({
    queryKey: ['auditJob'],
    queryFn: getAuditJob,
    refetchInterval: hidden ? false : 1500,
  })
  const auditRunning = auditJob?.running ?? false
  const auditDone = auditJob?.done ?? 0
  const auditTotal = auditJob?.total ?? 0
  const auditProgress = auditTotal > 0 ? Math.min(100, Math.round((auditDone / auditTotal) * 100)) : 0

  const runAuditMutation = useMutation({
    mutationFn: (opts: { upstream_name: string; model: string; profile: string }) =>
      // W1-4：允许后端临时启用探针并在结束后自动恢复原值。用户已在确认弹窗
      // （probesOn 为 false 时会多出一行明示）里看到并同意这一步。
      runAudit({ ...opts, allow_temp_probes: true }),
    onSuccess: (r) => {
      if (!r.ok) {
        toast(r.error || t('settings.toast.auditStartFail'), 'error')
        return
      }
      toast(t('settings.toast.auditStarted'))
      queryClient.invalidateQueries({ queryKey: ['auditJob'] })
    },
    onError: (e: Error) => toast(`${t('settings.toast.auditStartFail')}：${e.message}`, 'error'),
  })

  const cancelAuditMutation = useMutation({
    mutationFn: cancelAudit,
    onSuccess: () => {
      toast(t('settings.toast.cancelRequested'))
      queryClient.invalidateQueries({ queryKey: ['auditJob'] })
    },
    onError: (e: Error) => toast(`${t('settings.toast.cancelFail')}：${e.message}`, 'error'),
  })

  const showAuditReport = async () => {
    if (reportFetching) return
    setReportFetching(true)
    try {
      const r = await getAuditReport()
      if (r.ok && r.report) setAuditReport(r.report)
      else toast(r.error || t('settings.toast.noReport'), 'error')
    } catch (e) {
      toast(`${t('settings.toast.reportFail')}：${String(e)}`, 'error')
    } finally {
      setReportFetching(false)
    }
  }

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

  // ===== 命令拦截（W2-3）=====
  // 列表类字段（patterns / allow_patterns）走 `set` 整数组写入：服务端
  // `_normalize_command_block` 会逐条校验（非法正则丢弃 + warnings 回传），
  // 前端只负责组装数组。单个字段的开关走同一套 patch，避免整对象覆盖。
  const cmdBlock = (cfg?.command_block as Record<string, unknown>) ?? {}
  const cmdMode = String(cmdBlock.mode ?? 'observe')
  const cmdPatterns = (cmdBlock.patterns as CmdPattern[] | undefined) ?? []
  const cmdChannels = (cmdBlock.channels as string[] | undefined) ?? ['tool']
  const cmdAllow = (cmdBlock.allow_patterns as string[] | undefined) ?? []
  const [cmdDraft, setCmdDraft] = useState<{ id: string; label: string; regex: string; builtin: boolean } | null>(null)
  const [cmdError, setCmdError] = useState('')
  const [cmdAllowDraft, setCmdAllowDraft] = useState('')

  const saveCmdBlock = async (patch: Omit<ConfigPatch, 'key'>) => {
    if (!cfg) return
    try {
      const r = await patchConfig({ key: 'command_block', ...patch })
      if (!r.ok) toast(r.error || t('common.saveFail'), 'error')
      // 被丢弃的条目（非法/超长/嵌套量词）在后端以 warnings 回传，不静默
      for (const w of r.warnings ?? []) toast(w, 'error')
      queryClient.invalidateQueries({ queryKey: ['config'] })
    } catch (e) { toast(tf('common.saveFailWith', { e: String(e) }), 'error') }
  }
  const saveCmdPatterns = (next: CmdPattern[]) =>
    saveCmdBlock({ op: 'set', path: ['patterns'], value: next })
  const toggleCmdChannel = (ch: string, on: boolean) => {
    const next = on ? [...new Set([...cmdChannels, ch])] : cmdChannels.filter((c) => c !== ch)
    // 至少留一个通道，否则功能静默失效（用户会以为「开了却没用」）
    if (!next.length) return
    saveCmdBlock({ op: 'set', path: ['channels'], value: next })
  }
  const submitCmdDraft = () => {
    if (!cmdDraft) return
    const regex = cmdDraft.regex.trim()
    if (!regex) return
    try {
      // eslint-disable-next-line no-new
      new RegExp(regex)
    } catch {
      setCmdError(t('audit.cmd.regexInvalid'))
      return
    }
    setCmdError('')
    const id = cmdDraft.id || `user-${Math.random().toString(36).slice(2, 12)}`
    const entry: CmdPattern = { id, label: cmdDraft.label.trim(), regex, enabled: true, builtin: cmdDraft.builtin }
    const idx = cmdPatterns.findIndex((p) => p.id === id)
    const next = idx >= 0 ? cmdPatterns.map((p, i) => (i === idx ? { ...p, ...entry } : p)) : [...cmdPatterns, entry]
    setCmdDraft(null)
    void saveCmdPatterns(next)
  }

  // 审计档位预设（W1-5）：三档**只写既有字段**（fail_closed + severity_floor），
  // 不新增 audit.mode——那会与这两个字段形成第二套真值来源（设计 C3）。
  // 档位是“当前字段组合的读法”，而不是独立存储的状态；所以预设值由字段反推，
  // 不另存一份（否则 UI 与引擎会各自说一套话）。
  const auditFloor = String(auditCfg.severity_floor ?? 'MEDIUM')
  const auditBlockOn = !!auditCfg.fail_closed
  const auditPreset = auditBlockOn ? 'strict' : (auditFloor === 'LOW' ? 'verbose' : 'pure')
  const PRESETS: Record<string, { fail_closed: boolean; severity_floor: string }> = {
    pure: { fail_closed: false, severity_floor: 'MEDIUM' },
    verbose: { fail_closed: false, severity_floor: 'LOW' },
    strict: { fail_closed: true, severity_floor: 'MEDIUM' },
  }
  const applyPreset = async (p: string) => {
    const v = PRESETS[p]
    if (!cfg || !v) return
    try {
      // merge 一次只写两个字段：分两次 set 会出现“中途失败 → 档位卡在中间态”
      const r = await patchConfig({ key: 'audit', op: 'merge', path: [], value: v })
      if (!r.ok) toast(r.error || t('common.saveFail'), 'error')
      queryClient.invalidateQueries({ queryKey: ['config'] })
    } catch (e) { toast(tf('common.saveFailWith', { e: String(e) }), 'error') }
  }

  // 审计事件列表
  //
  // `isError` 必须显式取出来用：后端 5xx / 引擎没起来时 `data` 是 undefined，
  // `events` 随之变成 `[]`，而空数组此前**和「审计通过、零发现」渲染成同一个绿色空态**
  // （审计 L6）—— 把「我没读到」显示成「没问题」，是安全审计页最不能犯的一类错：
  // 用户看到绿盾就放心了，实际上后端整条链路是断的。
  const {
    data: eventsData,
    isLoading: eventsLoading,
    isError: eventsError,
    error: eventsErrorObj,
    refetch: refetchEvents,
  } = useQuery({
    queryKey: ['auditEvents', auditFloor],
    // 服务端按**用户档位**过滤（W2-5）：S9 危险动作是「恒落库」的（见引擎
    // AUDIT_ALWAYS_RECORD），它不带这个 floor 就会在默认视图里冒出来。
    // 时间线视图自己传 floor=LOW，两者互不影响。
    queryFn: () => getAuditEvents(0, AUDIT_WINDOW, { floor: auditFloor }),
    refetchInterval: hidden ? false : 3000,
  })

  // 高风险操作时间线（W2-5）：**视图级**放宽到 LOW，且只看 S9 危险动作。
  // 不新建页面/表，也不改默认视图的查询——切回默认视图事件数不增加。
  const {
    data: timelineData,
    isLoading: timelineLoading,
    isError: timelineError,
  } = useQuery({
    queryKey: ['auditTimeline'],
    queryFn: () => getAuditEvents(0, AUDIT_WINDOW, { floor: 'LOW', signal: 'dangerous_action' }),
    refetchInterval: hidden ? false : 5000,
    enabled: auditSubTab === 'timeline',
  })
  const timelineEvents = useMemo(() => timelineData?.events ?? [], [timelineData])

  const events = useMemo(() => eventsData?.events ?? [], [eventsData])

  // 服务端一次最多回 1000 条（`event_store.fetch_audit_events` 里 `min(limit, 1000)`），
  // 而筛选是**纯客户端**的（审计 L8）。窗口被填满时，「筛选后为空」有两种完全不同的
  // 含义：真的没有，还是命中的那条在 500 条之外？不说明就会把后者显示成前者。
  // 窗口填满时额外提示（见下面 noEventsAfterFilter 分支）。
  const windowFull = events.length >= AUDIT_WINDOW

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
      <PageHeader
        title={t('nav.audit')}
        subtitle={t('audit.subtitle')}
        actions={<>
          <Button
            size="sm"
            variant="default"
            className="gap-1.5"
            onClick={() => {
              setAuditSubTab('probe')
              setConfirmAudit(true)
            }}
          >
            <Play className="h-4 w-4" /> {t('audit.runProbe')}
          </Button>
          {/* 清空审计**必须二次确认**（审计 L8）：审计留痕是这个产品的证据链本身，
              误点一次就没了，且没有任何撤销途径（后端是 DELETE 语义）。
              同页的「发起探针」都有确认弹窗，破坏性更强的清空却没有，不成比例。 */}
          <Button
            size="sm"
            variant="outline"
            onClick={() => setConfirmClearAudit(true)}
            loading={clearMutation.isPending}
            className="gap-1.5 text-destructive-ink hover:text-destructive-ink"
          >
            {!clearMutation.isPending && <Trash2 className="h-4 w-4" />} {t('common.clear')}
          </Button>
        </>
      } />

      {/* 二级选项卡切换：事件日志 vs 审计探针与规则 */}
      <Tabs value={auditSubTab} onValueChange={(v) => setAuditSubTab(v as 'events' | 'timeline' | 'probe')} className="w-full">
        <TabsList>
          <TabsTrigger value="events">{t('audit.tab.events')}</TabsTrigger>
          <TabsTrigger value="timeline">{t('audit.tab.timeline')}</TabsTrigger>
          <TabsTrigger value="probe">{t('audit.tab.probe')}</TabsTrigger>
        </TabsList>

        <TabsContent value="probe" className="space-y-4 pt-2">
          {/* 主动安全探针扫描执行卡片 */}
          <Card className="border bg-card shadow-card">
            <CardHeader className="flex-row items-center gap-2 space-y-0">
              <Activity className="h-5 w-5 text-primary-ink" />
              <CardTitle className="flex items-center gap-1.5 text-sm font-semibold">
                {t('settings.security.auditProbe')}
                <Hint text={t('settings.advanced.auditProbeDesc')} />
              </CardTitle>
              <Badge variant="outline" className="ml-auto text-xs">
                {auditRunning ? t('settings.advanced.auditRunning') : (auditJob?.phase || t('common.idle'))}
              </Badge>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap items-end gap-3">
                <div className="min-w-[170px]">
                  <Label className="text-xs">{t('settings.advanced.upstream')}</Label>
                  <Select value={auditUpstream} onValueChange={setAuditUpstream}>
                    <SelectTrigger className="mt-1 h-8 text-xs"><SelectValue placeholder={t('settings.advanced.chooseUpstream')} /></SelectTrigger>
                    <SelectContent>
                      {upstreams.map((u) => (
                        <SelectItem key={u.name} value={u.name}>{u.name} :{u.port}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-xs">{t('logs.colModel')}</Label>
                  <Input className="mt-1 h-8 w-44 text-xs" value={auditModel} onChange={(e) => setAuditModel(e.target.value)} placeholder={t('settings.advanced.modelPh')} />
                </div>
                <div>
                  <Label className="flex items-center gap-1 text-xs">{t('settings.advanced.profile')}
                    <Hint text={t('settings.advanced.profileTooltip')} />
                  </Label>
                  <Select value={auditProfile} onValueChange={setAuditProfile}>
                    <SelectTrigger className="mt-1 h-8 w-28 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="general">{t('settings.advanced.profile.general')}</SelectItem>
                      <SelectItem value="web3">{t('settings.advanced.profile.web3')}</SelectItem>
                      <SelectItem value="full">{t('settings.advanced.profile.full')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" onClick={() => setConfirmAudit(true)} disabled={auditRunning} className="gap-1.5">
                    <Play className="h-4 w-4" />{t('settings.advanced.runAudit')}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => cancelAuditMutation.mutate()} disabled={!auditRunning} className="gap-1.5">
                    <X className="h-4 w-4" />{t('common.cancel')}
                  </Button>
                  <Button size="sm" variant="outline" onClick={showAuditReport} loading={reportFetching} className="gap-1.5">
                    {!reportFetching && <FileText className="h-4 w-4" />}{t('settings.advanced.viewReport')}
                  </Button>
                </div>
              </div>

              {auditRunning && (
                <div className="rounded-lg border border-primary/30 bg-primary/5 p-3">
                  <div className="flex items-center gap-2">
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-primary-ink" />
                    <span className="text-xs font-medium">{auditJob?.phase || t('settings.advanced.auditRunning')}</span>
                    <Badge variant="outline" className="ml-auto shrink-0 font-mono text-2xs">{auditDone}/{auditTotal}</Badge>
                  </div>
                  <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                    <div className="h-full rounded-full bg-primary transition-[width] duration-500" style={{ width: `${auditProgress}%` }} />
                  </div>
                </div>
              )}

              {!auditRunning && auditJob?.phase && (
                <p className="text-2xs text-muted-foreground">
                  {t('settings.advanced.lastTask')}{auditJob.phase}
                  {auditJob.error ? tf('settings.advanced.failed', { e: auditJob.error.slice(0, 120) }) : ''}
                </p>
              )}
            </CardContent>
          </Card>

      {/* ===== 审计配置（基础 + 高级） ===== */}
      <Card className="border bg-card shadow-card">
        <CardHeader className="flex-row items-center gap-2 space-y-0">
          <ShieldCheck className="h-5 w-5 text-primary-ink" />
          <CardTitle className="text-sm font-semibold">{t('audit.config')}</CardTitle>
          <span className={cn('ml-auto rounded-full px-2.5 py-0.5 text-xs font-medium', auditCfg.enabled ? 'bg-success/10 text-success-ink' : 'bg-muted text-muted-foreground')}>
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
                <p className="mt-1 text-2xs text-muted-foreground">{desc}</p>
              </label>
            ))}
          </div>

          {/* 高级：档位预设 + 自动报告 + 严重度门槛 + 审计阻断开关 */}
          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-lg border bg-muted/30 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-medium">{t('audit.preset')}</span>
                <Select value={auditPreset} onValueChange={applyPreset}>
                  <SelectTrigger className="h-8 w-44 text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pure">{t('audit.presetPure')}</SelectItem>
                    <SelectItem value="verbose">{t('audit.presetVerbose')}</SelectItem>
                    <SelectItem value="strict">{t('audit.presetStrict')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <p className="mt-1 text-2xs text-muted-foreground">
                {auditPreset === 'pure' ? t('audit.presetPureDesc')
                  : auditPreset === 'verbose' ? t('audit.presetVerboseDesc')
                  : t('audit.presetStrictDesc')}
              </p>
              {/* 承诺文案由 fail_closed **实时推导**，不硬编码（否则会与行为脱节） */}
              <p className={cn('mt-1.5 text-2xs font-medium', auditBlockOn ? 'text-warning-ink' : 'text-success-ink')}>
                {auditBlockOn ? t('audit.promiseBlockCritical') : t('audit.promiseNoBlock')}
              </p>
            </div>
            <div className="rounded-lg border bg-muted/30 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-medium">{t('audit.blockSwitch')}</span>
                <Switch checked={auditBlockOn} onCheckedChange={(v) => saveAudit({ op: 'set', path: ['fail_closed'], value: v })} className="scale-90" />
              </div>
              <p className="mt-1 text-2xs text-muted-foreground">{t('audit.blockSwitchDesc')}</p>
            </div>
            <label className="flex cursor-pointer select-none flex-col justify-between rounded-lg border bg-muted/30 p-3 transition-colors hover:border-primary/40">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-medium">{t('audit.autoReport')}</span>
                <Switch checked={!!(auditCfg.auto_report as boolean)} onCheckedChange={(v) => saveAudit({ op: 'set', path: ['auto_report'], value: v })} className="scale-90" />
              </div>
              <p className="mt-1 text-2xs text-muted-foreground">{t('audit.reportHint')}</p>
            </label>
            <div className="rounded-lg border bg-muted/30 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-medium">{t('audit.severityFloor')}</span>
                <Select value={auditFloor} onValueChange={(v) => saveAudit({ op: 'set', path: ['severity_floor'], value: v })}>
                  <SelectTrigger className="h-8 w-44 text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="LOW">{t('audit.severityLow')}</SelectItem>
                    <SelectItem value="MEDIUM">{t('audit.severityMedium')}</SelectItem>
                    <SelectItem value="HIGH">{t('audit.severityHigh')}</SelectItem>
                    <SelectItem value="CRITICAL">{t('audit.severityCritical')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <p className="mt-1 text-2xs text-muted-foreground">{t('audit.floorHint')}</p>
            </div>
          </div>

          {/* 信号开关 S1-S9 */}
          <div>
            <div className="mb-2 flex items-center gap-1.5 text-sm font-medium">
              {t('audit.signalsTitle2')}
              <span className="inline-flex items-center gap-1 text-2xs font-normal text-muted-foreground" title={t('audit.clickHint2')}>
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
          {/* ===== 命令拦截（W2-3）：模式 / 通道 / 规则 / 白名单 + 残留风险 ===== */}
          <Card className="border bg-card shadow-card">
            <CardHeader className="flex-row items-center gap-2 space-y-0">
              <Ban className="h-5 w-5 text-primary-ink" />
              <div>
                <CardTitle className="text-sm font-semibold">{t('audit.cmd.title')}</CardTitle>
                <p className="mt-0.5 text-xs text-muted-foreground">{t('audit.cmd.desc')}</p>
              </div>
              <Badge variant="outline" className="ml-auto shrink-0 text-xs">
                {cmdMode === 'observe' ? t('audit.cmd.modeObserve')
                  : cmdMode === 'rewrite' ? t('audit.cmd.modeRewrite') : t('audit.cmd.modeBlock')}
              </Badge>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-lg border bg-muted/30 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[13px] font-medium">{t('audit.cmd.mode')}</span>
                    <Select value={cmdMode} onValueChange={(v) => saveCmdBlock({ op: 'set', path: ['mode'], value: v })}>
                      <SelectTrigger className="h-8 w-40 text-xs"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="observe">{t('audit.cmd.modeObserve')}</SelectItem>
                        <SelectItem value="rewrite">{t('audit.cmd.modeRewrite')}</SelectItem>
                        <SelectItem value="block">{t('audit.cmd.modeBlock')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  {/* 模式后果写清楚（含 block 在流式/非流式下的差异）——UI 承诺必须等于行为 */}
                  <p className="mt-1 text-2xs text-muted-foreground">
                    {cmdMode === 'observe' ? t('audit.cmd.modeObserveDesc')
                      : cmdMode === 'rewrite' ? t('audit.cmd.modeRewriteDesc') : t('audit.cmd.modeBlockDesc')}
                  </p>
                </div>
                <div className="rounded-lg border bg-muted/30 p-3">
                  <div className="text-[13px] font-medium">{t('audit.cmd.channels')}</div>
                  <div className="mt-1.5 flex flex-wrap items-center gap-4">
                    {([['tool', t('audit.cmd.channelTool')], ['text', t('audit.cmd.channelText')]] as [string, string][]).map(([ch, label]) => (
                      <label key={ch} className="flex cursor-pointer items-center gap-2 text-xs">
                        <Switch checked={cmdChannels.includes(ch)} onCheckedChange={(v) => toggleCmdChannel(ch, v)} className="scale-90" />
                        {label}
                      </label>
                    ))}
                  </div>
                  {cmdChannels.includes('text') && (
                    <p className="mt-1.5 text-2xs text-warning-ink">{t('audit.cmd.channelTextWarn')}</p>
                  )}
                </div>
              </div>

              <div>
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{t('audit.cmd.patterns')}</span>
                  <span className="text-2xs text-muted-foreground">{t('audit.cmd.ruleHint')}</span>
                  <Button
                    size="sm" variant="outline" className="ml-auto h-7 gap-1"
                    onClick={() => { setCmdError(''); setCmdDraft({ id: '', label: '', regex: '', builtin: false }) }}
                  >
                    <Plus className="h-3.5 w-3.5" />{t('audit.cmd.addRule')}
                  </Button>
                </div>
                <div className="space-y-1.5">
                  {cmdPatterns.length === 0 && (
                    <p className="rounded-lg border border-dashed py-4 text-center text-xs text-muted-foreground">
                      {t('audit.cmd.deletedHint')}
                    </p>
                  )}
                  {cmdPatterns.map((p) => (
                    <div key={p.id ?? p.regex} className="flex items-start gap-2 rounded-lg border bg-muted/20 p-2">
                      <Switch
                        checked={!!p.enabled} className="mt-0.5 scale-75"
                        onCheckedChange={(v) => saveCmdPatterns(cmdPatterns.map((x) => (x.id === p.id ? { ...x, enabled: v } : x)))}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          <span className="text-xs font-medium">{p.label || p.id}</span>
                          {p.builtin && <Badge variant="outline" className="text-2xs">{t('audit.cmd.builtin')}</Badge>}
                        </div>
                        <code className="mt-0.5 block truncate font-mono text-2xs text-muted-foreground" title={p.regex}>{p.regex}</code>
                      </div>
                      <Button
                        size="2xs" variant="ghost" className="shrink-0 px-1.5"
                        onClick={() => { setCmdError(''); setCmdDraft({ id: p.id ?? '', label: p.label, regex: p.regex, builtin: !!p.builtin }) }}
                      >{t('audit.cmd.edit')}</Button>
                      <Button
                        size="2xs" variant="ghost" className="shrink-0 px-1.5 text-destructive-ink hover:text-destructive-ink"
                        onClick={() => saveCmdPatterns(cmdPatterns.filter((x) => x.id !== p.id))}
                      >{t('audit.cmd.delete')}</Button>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{t('audit.cmd.allow')}</span>
                  <span className="text-2xs text-muted-foreground">{t('audit.cmd.allowHint')}</span>
                </div>
                <div className="space-y-1.5">
                  {cmdAllow.map((rx, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <Input
                        className="h-8 font-mono text-xs" defaultValue={rx}
                        onBlur={(e) => {
                          const v = e.target.value.trim()
                          if (v === rx) return
                          const next = cmdAllow.map((x, j) => (j === i ? v : x)).filter(Boolean)
                          void saveCmdBlock({ op: 'set', path: ['allow_patterns'], value: next })
                        }}
                      />
                      <Button
                        size="xs" variant="ghost" className="shrink-0 px-2 text-destructive-ink hover:text-destructive-ink"
                        onClick={() => saveCmdBlock({ op: 'set', path: ['allow_patterns'], value: cmdAllow.filter((_, j) => j !== i) })}
                      >{t('audit.cmd.delete')}</Button>
                    </div>
                  ))}
                  <div className="flex items-center gap-2">
                    <Input
                      className="h-8 font-mono text-xs" value={cmdAllowDraft}
                      placeholder={t('audit.cmd.allowPh')}
                      onChange={(e) => setCmdAllowDraft(e.target.value)}
                    />
                    <Button
                      size="sm" variant="outline" className="h-7 shrink-0 gap-1"
                      disabled={!cmdAllowDraft.trim()}
                      onClick={() => {
                        void saveCmdBlock({ op: 'list_add', path: ['allow_patterns'], value: [cmdAllowDraft.trim()] })
                        setCmdAllowDraft('')
                      }}
                    ><Plus className="h-3.5 w-3.5" />{t('audit.cmd.addAllow')}</Button>
                  </div>
                </div>
              </div>

              <p className="text-2xs text-muted-foreground">{t('audit.cmd.risk')}</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="events" className="space-y-4 pt-2">
      {/* 信号识别轻量提示 */}
      <div className="flex items-center gap-2 rounded-xl border bg-muted/40 px-4 py-2.5 text-xs text-muted-foreground">
        <Info className="h-4 w-4 shrink-0" />
        <span>{t('audit.judgeCompact')}</span>
      </div>

      {/* 审计事件列表 */}
      <Card className="border bg-card shadow-card">
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
                <Button size="sm" variant="ghost" className="px-2" onClick={() => { setSevFilter('__ALL__'); setSigFilter('__ALL__') }}>
                  {t('common.reset')}
                </Button>
              )}
              {/* 窗口填满时把「筛选作用域」说出来（审计 L8）：筛选在前端做，
                  命中项若在窗口之外就看不到，此时「无匹配」不能读作「不存在」。 */}
              {windowFull && (sevFilter !== '__ALL__' || sigFilter !== '__ALL__') && (
                <span className="text-2xs text-warning-ink">
                  {tf('audit.filterWindowHint', { n: AUDIT_WINDOW })}
                </span>
              )}
            </div>
          )}

          {eventsLoading && events.length === 0 ? (
            <div className="space-y-2">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : eventsError ? (
            /* 读失败与「零发现」必须视觉可分（审计 L6）。这里刻意用红色警示而不是绿色：
               引擎没起来 / 请求被拒 / 后端 5xx 时，「什么都没读到」的正确解读是
               「审计这一层现在是瞎的」，而不是「一切正常」。 */
            <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-destructive/40 bg-destructive/5 py-12 text-center">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10 text-destructive-ink">
                <HelpCircle className="h-6 w-6" />
              </div>
              <h4 className="mt-3 text-sm font-semibold text-foreground">{t('audit.loadFailTitle')}</h4>
              <p className="mt-1 max-w-md text-xs text-muted-foreground">
                {t('audit.loadFailDesc')}
              </p>
              {eventsErrorObj ? (
                <p className="mt-1 max-w-md break-all font-mono text-2xs text-destructive-ink">
                  {String((eventsErrorObj as Error)?.message || eventsErrorObj)}
                </p>
              ) : null}
              <Button
                size="sm"
                variant="outline"
                className="mt-4 gap-1.5 border-destructive/40 text-destructive-ink hover:bg-destructive/10"
                onClick={() => { void refetchEvents() }}
              >
                <RefreshCw className="h-3.5 w-3.5" />
                {t('common.reload')}
              </Button>
            </div>
          ) : events.length === 0 ? (
            <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-success/30 bg-success/5 py-12 text-center">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-success/10 text-success-ink">
                <ShieldCheck className="h-6 w-6" />
              </div>
              <h4 className="mt-3 text-sm font-semibold text-foreground">{t('audit.emptySafeTitle')}</h4>
              <p className="mt-1 max-w-md text-xs text-muted-foreground">
                {t('audit.emptySafeDesc')}
              </p>
              <Button
                size="sm"
                variant="outline"
                className="mt-4 gap-1.5 border-success/30 text-success-ink hover:bg-success/10 hover:text-success-ink"
                onClick={() => {
                  setAuditSubTab('probe')
                  setConfirmAudit(true)
                }}
              >
                <Play className="h-3.5 w-3.5" />
                {t('audit.runProbe')}
              </Button>
            </div>
          ) : filteredEvents.length === 0 ? (
            <div className="py-10 text-center text-sm text-muted-foreground">
              <Radar className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
              {t('audit.noEventsAfterFilter')}
              {/* 窗口满时补一句限定语：筛选只作用于已加载的 N 条（审计 L8）。 */}
              {windowFull && (
                <p className="mt-1.5 text-xs text-warning-ink">
                  {tf('audit.noEventsWindowNote', { n: AUDIT_WINDOW })}
                </p>
              )}
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
                          <Badge variant="outline" className={cn('shrink-0 rounded-full text-2xs', sev.cls)}>
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
        </TabsContent>

        <TabsContent value="timeline" className="space-y-4 pt-2">
          {/* 高风险操作时间线（W2-5）：**视图级**放宽 to floor=LOW，且只看 S9 危险动作。
              不新建页面/表；默认事件视图仍按用户档位过滤，切回来事件数不增加。 */}
          <div className="flex items-center gap-2 rounded-xl border border-warning/20 bg-warning/5 px-4 py-2.5 text-xs text-muted-foreground">
            <Info className="h-4 w-4 shrink-0 text-warning-ink" />
            <span>{t('audit.timelineHint')}</span>
          </div>
          <Card className="border bg-card shadow-card">
            <CardContent className="p-4">
              <div className="mb-3 flex items-center gap-2">
                <Radar className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm font-semibold">{t('audit.timelineTitle')}</span>
                <Badge variant="outline" className="ml-auto text-xs">
                  {timelineData?.count ?? 0} {t('audit.countSuffix')}
                </Badge>
              </div>
              {timelineLoading && timelineEvents.length === 0 ? (
                <div className="space-y-2">
                  {[0, 1, 2].map((i) => <Skeleton key={i} className="h-12 w-full" />)}
                </div>
              ) : timelineError ? (
                /* 读失败与「零发现」必须视觉可分（同审计 L6 的口径） */
                <div className="py-10 text-center text-xs text-muted-foreground">
                  <HelpCircle className="mx-auto mb-2 h-6 w-6 text-destructive-ink" />
                  {t('audit.loadFailTitle')}
                </div>
              ) : timelineEvents.length === 0 ? (
                <div className="py-10 text-center text-xs text-muted-foreground">
                  <Radar className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
                  {t('audit.timelineEmpty')}
                </div>
              ) : (
                <ol className="relative space-y-3 border-l border-border pl-4">
                  {timelineEvents.map((ev) => {
                    const sev = severityMeta(ev.severity)
                    return (
                      <li
                        key={ev.seq}
                        className="relative cursor-pointer"
                        onClick={() => setDetailEvent(ev)}
                        title={t('common.viewDetail')}
                      >
                        <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full bg-warning" />
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant="outline" className={cn('rounded-full text-2xs', sev.cls)}>{t(sev.labelKey)}</Badge>
                          <span className="text-xs text-muted-foreground">{dayjs(ev.ts * 1000).format('MM-DD HH:mm:ss')}</span>
                          {ev.host ? <span className="text-xs text-muted-foreground">{ev.host}</span> : null}
                        </div>
                        <pre className="mt-1 whitespace-pre-wrap break-all rounded-lg bg-muted/60 p-2 font-mono text-2xs leading-relaxed text-foreground">
                          {ev.evidence || '—'}
                        </pre>
                      </li>
                    )
                  })}
                </ol>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* 审计事件详情弹窗（共用组件：审计中心与日志页同款） */}
      <AuditEventDetailDialog event={detailEvent} onOpenChange={(v) => !v && setDetailEvent(null)} />

      {/* 清空审计确认弹窗（审计 L8） */}
      <Dialog open={confirmClearAudit} onOpenChange={setConfirmClearAudit}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t('audit.clearTitle')}</DialogTitle>
            <DialogDescription>
              {t('audit.clearDesc')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button size="sm" variant="outline" onClick={() => setConfirmClearAudit(false)} disabled={clearMutation.isPending}>
              {t('common.cancel')}
            </Button>
            <Button size="sm" variant="destructive" onClick={() => {
              setConfirmClearAudit(false)
              clearMutation.mutate()
            }} loading={clearMutation.isPending}>
              {t('common.clear')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 命令拦截规则新增/修改弹窗（W2-3） */}
      <Dialog open={cmdDraft !== null} onOpenChange={(v) => { if (!v) { setCmdDraft(null); setCmdError('') } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{cmdDraft?.id ? t('audit.cmd.editRule') : t('audit.cmd.addRule')}</DialogTitle>
            <DialogDescription>{t('audit.cmd.ruleHint')}</DialogDescription>
          </DialogHeader>
          {cmdDraft && (
            <div className="space-y-3">
              <div>
                <Label className="text-xs">{t('audit.cmd.label')}</Label>
                <Input
                  className="mt-1 h-8 text-xs" value={cmdDraft.label}
                  placeholder={t('audit.cmd.labelPh')}
                  onChange={(e) => setCmdDraft({ ...cmdDraft, label: e.target.value })}
                />
              </div>
              <div>
                <Label className="text-xs">{t('audit.cmd.regex')}</Label>
                <Input
                  className="mt-1 h-8 font-mono text-xs" value={cmdDraft.regex}
                  placeholder={"rm\\s+-rf\\s+/"}
                  onChange={(e) => { setCmdError(''); setCmdDraft({ ...cmdDraft, regex: e.target.value }) }}
                />
              </div>
              {cmdError && <p className="text-2xs text-destructive-ink">{cmdError}</p>}
            </div>
          )}
          <DialogFooter>
            <Button size="sm" variant="outline" onClick={() => { setCmdDraft(null); setCmdError('') }}>{t('common.cancel')}</Button>
            <Button size="sm" onClick={submitCmdDraft} disabled={!cmdDraft?.regex.trim()}>{t('common.save')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 主动审计确认弹窗 */}
      <Dialog open={confirmAudit} onOpenChange={setConfirmAudit}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t('settings.confirm.auditTitle')}</DialogTitle>
            <DialogDescription>
              {tf('settings.confirm.auditDesc', { name: auditUpstream || t('settings.advanced.selectedUpstream') })}
            </DialogDescription>
          </DialogHeader>
          {/* 主动探针关闭时要说清后果（W1-4）：否则用户只会在跑完才发现
              「我的安全设置被改了」——临时改也必须是明示的。 */}
          {!auditCfg.active_probes && (
            <p className="text-xs leading-relaxed text-warning-ink">
              {t('settings.confirm.auditTempProbes')}
            </p>
          )}
          <DialogFooter>
            <Button size="sm" variant="outline" onClick={() => setConfirmAudit(false)}>{t('common.cancel')}</Button>
            <Button size="sm" variant="destructive" onClick={() => {
              setConfirmAudit(false)
              runAuditMutation.mutate({
                upstream_name: auditUpstream,
                model: auditModel,
                profile: auditProfile,
              })
            }}>{t('settings.confirm.auditStart')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 查看审计报告弹窗 */}
      <Dialog open={auditReport !== null} onOpenChange={(v) => !v && setAuditReport(null)}>
        <DialogContent className="flex max-h-[80vh] max-w-2xl flex-col">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5 text-primary-ink" />
              {t('settings.advanced.viewReport')}
            </DialogTitle>
          </DialogHeader>
          <div className="max-h-[60vh] flex-1 overflow-auto whitespace-pre-wrap rounded-lg border bg-muted/40 p-4 font-mono text-xs leading-relaxed">
            {auditReport}
          </div>
          <DialogFooter>
            <Button size="sm" variant="outline" onClick={() => setAuditReport(null)}>{t('common.close')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
