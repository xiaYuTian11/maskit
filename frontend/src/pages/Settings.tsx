/**
 * 高级设置页（对标旧版：客户端管理 / 敏感词库 / 高级设置 / 系统安全）
 * - 客户端：upstreams CRUD + 连通性测试
 * - 敏感词库：分类词表 + 内置规则开关 + secret 前缀
 * - 高级：捕获模式/stop_mode/流式/出口代理/自启/保留天数等
 * - 系统安全：证书安装 / 数据目录 / 审计配置
 * 保存走 POST /api/config 全量提交，warnings 必须展示（端口变化自动重启提示）
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useVisibility } from '@/lib/useVisibility'
import {
  Plus,
  Pencil,
  Trash2,
  AlertTriangle,
  Plug,
  FolderOpen,
  Loader2,
  Copy,
  Play,
  X,
  FileText,
  Radar,
  Coins,
  RefreshCw,
  List,
  Send,
  HelpCircle,
  ExternalLink,
  Check,
  Search,
  ChevronRight,
} from 'lucide-react'
import { getConfig, saveConfig, saveBuiltinRules, testUpstream, openDataDir, restoreNetwork, getHealth, getConfigBackups, restoreConfigBackup, getPriceSyncStatus, syncPricesNow, getPriceList, type ConfigBackup, type SaveConfigResponse } from '@/api/settings'
import { runAudit, cancelAudit, getAuditJob, getAuditReport } from '@/api/audit'
import { getStatus } from '@/api/proxy'
import { useMutation } from '@tanstack/react-query'
import type { ShieldConfig, UpstreamConfig } from '@/types/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogDescription,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Textarea } from '@/components/ui/textarea'
import { toast } from '@/lib/toast'
import { isTauri, shieldFetch } from '@/lib/shield-fetch'
import { setAutostartTauri } from '@/lib/tauri'
import { cn, copyText } from '@/lib/utils'
import dayjs from 'dayjs'
import { useI18n } from '@/lib/i18n'
import { AboutUpdateCard } from '@/components/settings/AboutUpdateCard'
import { EnvImportDialog } from '@/components/settings/EnvImportDialog'

import { BackgroundCard } from '@/components/settings/BackgroundCard'

// 内置规则分组（将 19 项规则按场景归类，降低视觉负荷与误伤风险）
const BUILTIN_RULE_GROUPS: { key: string; labelKey: string; rules: string[] }[] = [
  {
    key: 'core',
    labelKey: 'settings.words.groupCore',
    rules: ['PHONE', 'EMAIL', 'IDCARD', 'LANDLINE', 'CARD', 'API_KEY', 'CONNSTR'],
  },
  {
    key: 'credentials',
    labelKey: 'settings.words.groupCredentials',
    rules: ['ACCESS_KEY', 'PRIVATE_KEY', 'SECRET', 'TOKEN', 'JWT'],
  },
  {
    key: 'network',
    labelKey: 'settings.words.groupNetwork',
    rules: ['IP_PRIVATE', 'IP_INTERNAL', 'MAC'],
  },
  {
    key: 'entities',
    labelKey: 'settings.words.groupEntities',
    rules: ['PLATE', 'USCC', 'HKID', 'IBAN'],
  },
]

// ========== 上游表单 ==========
// 客户端类型 → 路径预设（多选 chip 展示，用户可增删；自定义类型全部手输）
// headers 只放「与凭据无关」的协议头。凭据头（Authorization / x-api-key）**绝不预填**：
// 预设一旦填上 <YOUR_API_KEY> 这类占位符，用户不替换就保存，转发时会无条件覆盖客户端
// 自带的真 key，上游只回 401「无效的令牌」，用户完全看不出是自己的配置把 key 顶掉了
// （实测 anyrouter 中转站必现）。客户端本来就带凭据，真需要注入的场景手填真实值即可。
const CLIENT_TYPE_PRESETS: Record<string, { labelKey: string; paths: string[]; headers: [string, string][] }> = {
  openai: {
    labelKey: 'settings.clientType.openai',
    paths: ['/v1/chat/completions', '/v1/completions', '/v1/responses', '/v1/embeddings', '/v1/rerank', '/rerank', '/v1/models'],
    headers: [],
  },
  anthropic: {
    labelKey: 'settings.clientType.anthropic',
    paths: ['/v1/messages', '/v1/complete'],
    headers: [['anthropic-version', '2023-06-01']],
  },
  gemini: {
    labelKey: 'settings.clientType.gemini',
    paths: ['/v1/models', '/v1beta/models'],
    headers: [],
  },
  custom: { labelKey: 'settings.clientType.custom', paths: [], headers: [] },
}

// 凭据类请求头：语义就是「承载身份凭据」，禁止通过「注入请求头」配置。
// Maskit 只配 URL、只做透明转发，凭据归客户端（Claude Code / Cursor 等自带）。
// 在这里填凭据只会覆盖客户端自带的真 key，换回一个必然 401，而上游只报「无效的令牌」，
// 用户完全看不出是自己配置造成的（实测 anyrouter 中转站报障即此因）。
// 必须与引擎侧 engine/transparent.py 的 _CREDENTIAL_HEADER_NAMES 保持一致。
const CREDENTIAL_HEADER_NAMES = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'x-api-key',
  'api-key',
  'apikey',
  'x-goog-api-key',
  'x-auth-token',
  'x-access-token',
  'x-token',
  'x-session-token',
  'private-token',
  'x-gitlab-token',
  'x-github-token',
  'x-amz-security-token',
  'x-amz-credential',
  'x-client-secret',
  'client-secret',
])

const isCredentialHeader = (k: string) => CREDENTIAL_HEADER_NAMES.has(k.trim().toLowerCase())

function detectClientType(u: UpstreamConfig): string {
  // 按现有 paths 猜测类型（编辑已有客户端时回显）
  const paths = (u.paths ?? []).map((p) => p.toLowerCase())
  if (paths.some((p) => p.includes('/v1/messages')) && !paths.some((p) => p.includes('/v1/chat/completions'))) return 'anthropic'
  if (paths.some((p) => p.includes('/v1beta'))) return 'gemini'
  return 'openai'
}

function UpstreamForm({
  initial,
  onSave,
  onClose,
  captureMode,
}: {
  initial: UpstreamConfig
  onSave: (u: UpstreamConfig) => void
  onClose: () => void
  captureMode: string
}) {
  const [form, setForm] = useState<UpstreamConfig>({ ...initial })
  const set = (k: keyof UpstreamConfig, v: unknown) => setForm((f) => ({ ...f, [k]: v }))
  const [clientType, setClientType] = useState<string>(detectClientType(initial))
  const [newPath, setNewPath] = useState('')
  const [newHeaderKey, setNewHeaderKey] = useState('')
  const [newHeaderVal, setNewHeaderVal] = useState('')
  const { t, tf } = useI18n()
  const extraHeaders = form.extra_headers ?? {}
  // 「注入请求头」是可选的高级覆盖入口，默认收起——请求头本来就原样透传，不需要用户做任何事。
  // 但已有配置（含历史遗留的占位符行）必须默认展开，否则用户看不到问题行、也删不掉。
  // 受控 + onToggle 回写：初始值由 lazy initializer 一次性算出（不依赖 effect 时机，弹窗在
  // Radix portal 里挂载时 effect 里改 DOM 不生效），用户手动开合时把 DOM 真实状态同步回 state，
  // 于是重渲染永远写回正确值，不会把用户展开的状态弹回去。
  const [advOpen, setAdvOpen] = useState(() => Object.keys(initial.extra_headers ?? {}).length > 0)

  const presets = CLIENT_TYPE_PRESETS[clientType] ?? CLIENT_TYPE_PRESETS.openai
  const presetPaths = presets.paths.filter((p) => !(form.paths ?? []).includes(p))
  const presetHeaders = presets.headers.filter(([k]) => !(k in extraHeaders))

  const applyType = (t: string) => {
    setClientType(t)
    if (t === 'custom') return
    // 选类型 → 切换为该类型的预设路径 + 预设 header（不保留其他协议的旧路径）
    const p = CLIENT_TYPE_PRESETS[t]
    set('paths', [...p.paths])
    const h = { ...extraHeaders }
    for (const [k, v] of p.headers) {
      if (!(k in h)) h[k] = v
    }
    set('extra_headers', h)
  }

  const togglePath = (p: string) => {
    const cur = form.paths ?? []
    set('paths', cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p])
  }

  const setHeader = (k: string, v: string) => {
    const h = { ...extraHeaders }
    if (!k.trim()) return
    h[k.trim()] = v
    set('extra_headers', h)
  }
  const removeHeader = (k: string) => {
    const h = { ...extraHeaders }
    delete h[k]
    set('extra_headers', h)
  }

  // 保存前双重拦截「会覆盖客户端凭据」的配置：
  //   1) 凭据类头名（Authorization / x-api-key / cookie …）——凭据归客户端，不该配在这里；
  //   2) 占位符值（<YOUR_API_KEY>，可带 Bearer 前缀）——假 key 顶掉真 key，必然 401。
  // 两者都会让上游只回「无效的令牌」，用户完全看不出是自己的配置造成的。
  // 预设已不再预填凭据头，这里兜住手输与历史配置。
  const PLACEHOLDER_HEADER_VAL = /^\s*(?:Bearer\s+)?<[^<>]{1,64}>\s*$/i
  const saveChecked = () => {
    // 空值的行不算违规：onSaveUpstream 会把它整行丢掉，效果等同「删行」，
    // 否则用户清空值（而不是点删除）时会被永久卡在弹窗里，改不动也退不出。
    const cred = Object.keys(extraHeaders).find(
      (k) => isCredentialHeader(k) && String(extraHeaders[k] ?? '').trim() !== '',
    )
    if (cred) {
      toast(tf('settings.upstream.headerCredential', { k: cred }), 'error')
      return
    }
    const bad = Object.entries(extraHeaders).find(([, v]) => PLACEHOLDER_HEADER_VAL.test(String(v ?? '')))
    if (bad) {
      toast(tf('settings.upstream.headerPlaceholder', { k: bad[0], v: bad[1] }), 'error')
      return
    }
    onSave(form)
  }

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{initial.name ? t('settings.upstream.titleEdit') : t('settings.upstream.titleAdd')}</DialogTitle>
        </DialogHeader>
        <div className="grid gap-3">
          {/* 基础信息 */}
          <div className="grid grid-cols-3 gap-3">
            <div>
              <Label className="text-xs">{t('settings.upstream.name')}</Label>
              <Input className="mt-1 h-8 text-xs" value={form.name} onChange={(e) => set('name', e.target.value)} placeholder={t('settings.upstream.namePh')} />
            </div>
            <div>
              <Label className="text-xs">{t('settings.upstream.port')}</Label>
              <Input className="mt-1 h-8 text-xs" type="number" value={form.port || ''} onChange={(e) => set('port', Number(e.target.value))} placeholder={t('settings.upstream.portAuto')} />
            </div>
            <div>
              <Label className="text-xs">{t('settings.upstream.clientType')}</Label>
              <Select value={clientType} onValueChange={applyType}>
                <SelectTrigger className="mt-1 h-8 text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {Object.entries(CLIENT_TYPE_PRESETS).map(([k, v]) => (
                    <SelectItem key={k} value={k}>{t(v.labelKey)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <Label className="text-xs">{t('settings.upstream.targetBaseUrl')}</Label>
            <Input className="mt-1 h-8 font-mono text-xs" value={form.target} onChange={(e) => set('target', e.target.value)} placeholder={t('settings.upstream.targetPh')} />
            <p className="mt-1 text-[11px] text-muted-foreground">{t('settings.upstream.targetHint')}</p>
          </div>

          {/* 路径白名单：多选 chip */}
          <div>
            <Label className="text-xs">{t('settings.upstream.paths')}</Label>
            <p className="mt-1 text-[11px] text-muted-foreground">{t('settings.upstream.pathsHint')}</p>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {(form.paths ?? []).map((p) => (
                <span key={p} className="group flex items-center gap-1 rounded-full border border-primary/40 bg-primary/10 px-2 py-0.5 font-mono text-[11px]">
                  {p}
                  <button type="button" className="text-muted-foreground opacity-60 hover:text-red-500 group-hover:opacity-100" onClick={() => togglePath(p)} title={t('settings.words.delTitle')} aria-label={t('settings.words.delTitle')}><X className="h-3 w-3" /></button>
                </span>
              ))}
              {presetPaths.map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => togglePath(p)}
                  className="rounded-full border border-dashed border-border bg-muted/40 px-2 py-0.5 font-mono text-[11px] text-muted-foreground hover:border-primary/50 hover:text-foreground"
                >
                  + {p}
                </button>
              ))}
            </div>
            <div className="mt-1.5 flex items-center gap-1.5">
              <Input className="h-7 w-52 font-mono text-xs" value={newPath} onChange={(e) => setNewPath(e.target.value)} placeholder={t('settings.upstream.pathPh')} onKeyDown={(e) => {
                if (e.key === 'Enter' && newPath.trim().startsWith('/')) {
                  togglePath(newPath.trim()); setNewPath('')
                }
              }} />
              <Button size="sm" variant="ghost" className="h-7 text-[11px]" onClick={() => { if (newPath.trim().startsWith('/')) { togglePath(newPath.trim()); setNewPath('') } }}>{t('settings.upstream.pathAdd')}</Button>
            </div>
          </div>

          {/* 注入请求头：可选的高级覆盖入口，默认收起。
              请求头本来就原样透传（引擎只改写 Host，流式请求额外把 accept-encoding 置为
              identity），不碰这里就绝不会注入任何头。仅在「客户端根本不发某个头、上游又要求」
              时才需要展开填写，例如 anthropic-beta: context-1m-2025-08-07。 */}
          <details
            className="group rounded-lg border border-border/60 bg-muted/20"
            open={advOpen}
            onToggle={(e) => setAdvOpen(e.currentTarget.open)}
          >
            <summary className="flex cursor-pointer list-none items-center gap-1.5 px-2.5 py-2 text-xs text-muted-foreground hover:text-foreground">
              <ChevronRight className="h-3 w-3 transition-transform group-open:rotate-90" />
              {t('settings.upstream.headersAdvanced')}
              {Object.keys(extraHeaders).length > 0 && (
                <span className="rounded-full bg-muted px-1.5 py-0.5 font-mono text-[10px]">{Object.keys(extraHeaders).length}</span>
              )}
            </summary>
            <div className="px-2.5 pb-2.5">
              <div className="space-y-1.5">
                {Object.entries(extraHeaders).map(([k, v]) => {
                  // 凭据头标红：这类头不该配在这里，非空值时保存会被拦下（见 saveChecked）。
                  // 历史配置里若残留，用户一眼就能看到该删哪行；值已清空的行等同于删行，不标红。
                  const cred = isCredentialHeader(k) && String(v ?? '').trim() !== ''
                  const base = 'h-7 font-mono text-[11px]'
                  return (
                    <div key={k} className="flex items-center gap-1.5">
                      <Input
                        className={`${base} w-36 ${cred ? 'border-destructive/60 text-destructive' : ''}`}
                        value={k}
                        readOnly
                        title={cred ? t('settings.upstream.headerCredentialRow') : undefined}
                      />
                      <Input className={`${base} flex-1`} value={v} onChange={(e) => setHeader(k, e.target.value)} />
                      <button type="button" className="shrink-0 text-muted-foreground opacity-60 hover:text-red-500" onClick={() => removeHeader(k)} title={t('settings.words.delTitle')} aria-label={t('settings.words.delTitle')}><X className="h-3 w-3" /></button>
                    </div>
                  )
                })}
                {presetHeaders.map(([k, v]) => (
                  <button
                    key={k}
                    type="button"
                    onClick={() => setHeader(k, v)}
                    className="flex items-center gap-1.5 rounded-lg border border-dashed border-border bg-muted/40 px-2 py-1 text-[11px] text-muted-foreground hover:border-primary/50 hover:text-foreground"
                  >
                    <Plus className="h-3 w-3" /> {k}：{v}
                  </button>
                ))}
                <div className="flex items-center gap-1.5">
                  <Input className="h-7 w-36 font-mono text-[11px]" value={newHeaderKey} onChange={(e) => setNewHeaderKey(e.target.value)} placeholder={t('settings.upstream.headerNamePh')} />
                  <Input className="h-7 flex-1 font-mono text-[11px]" value={newHeaderVal} onChange={(e) => setNewHeaderVal(e.target.value)} placeholder={t('settings.upstream.headerValPh')} />
                  <Button size="sm" variant="ghost" className="h-7 shrink-0 text-[11px]" onClick={() => { if (newHeaderKey.trim()) { setHeader(newHeaderKey, newHeaderVal); setNewHeaderKey(''); setNewHeaderVal('') } }}>{t('settings.upstream.headerAdd')}</Button>
                </div>
              </div>
              <p className="mt-1.5 text-[11px] text-muted-foreground">{t('settings.upstream.headerHint')}</p>
            </div>
          </details>

          {/* 单端口前缀模式才需要 base_path；反向代理模式无需 */}
          {captureMode !== 'reverse' && (
            <div>
              <Label className="text-xs">{t('settings.upstream.basePath')}</Label>
              <Input className="mt-1 h-8 font-mono text-xs" value={form.base_path ?? ''} onChange={(e) => set('base_path', e.target.value)} placeholder={t('settings.upstream.basePathPh')} />
            </div>
          )}

          <label className="flex cursor-pointer select-none items-center gap-2 text-xs text-muted-foreground transition-colors hover:text-foreground">
            <Switch checked={!!form.use_proxy} onCheckedChange={(v) => set('use_proxy', v)} />
            {t('settings.upstream.useEgress')}
          </label>
        </div>
        <DialogFooter>
          <Button size="sm" variant="outline" onClick={onClose}>{t('settings.upstream.cancel')}</Button>
          <Button size="sm" onClick={saveChecked}>{t('settings.upstream.save')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ========== 配置备份与回滚 ==========
/**
 * 配置备份在数据目录中自动生成；此卡展示时间、结构摘要并提供一键回滚。
 */
/** 开关行：label + ? 问号 Tooltip 说明 + Switch（全局统一样式） */
function SettingToggle({ label, desc, checked, onChange }: { label: string; desc: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-2 rounded-lg border bg-card/60 px-3 py-2.5">
      <span className="flex min-w-0 items-center gap-1.5 text-[13px]">
        <span className="truncate">{label}</span>
        <TooltipProvider delayDuration={200}>
          <Tooltip>
            <TooltipTrigger asChild>
              <HelpCircle className="h-3.5 w-3.5 shrink-0 cursor-help text-muted-foreground/60" />
            </TooltipTrigger>
            <TooltipContent className="max-w-[280px] text-xs">{desc}</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </span>
      <Switch checked={checked} onCheckedChange={onChange} className="scale-75" />
    </label>
  )
}

function ConfigBackupCard() {
  const { t, tf } = useI18n()
  const queryClient = useQueryClient()
  const { hidden } = useVisibility()
  const [pending, setPending] = useState<ConfigBackup | null>(null)
  const [restoring, setRestoring] = useState(false)
  const { data, isLoading } = useQuery({
    queryKey: ['configBackups'],
    queryFn: getConfigBackups,
    refetchOnMount: 'always',
    refetchInterval: hidden ? false : 120000,
  })
  const backups = data?.backups ?? []
  const cur = data?.current ?? {}

  const doRestore = async () => {
    if (!pending) return
    setRestoring(true)
    try {
      const r = await restoreConfigBackup(pending.file)
      if (!r.ok) {
        toast(r.error || t('settings.backup.restoreFail2'), 'error')
        return
      }
      r.warnings?.forEach((w) => toast(w, 'error'))
      toast(r.proxy_restarted ? t('settings.toast.restarted') : t('settings.backup.restored'))
      setPending(null)
      queryClient.invalidateQueries({ queryKey: ['config'] })
      queryClient.invalidateQueries({ queryKey: ['configBackups'] })
      queryClient.invalidateQueries({ queryKey: ['proxyStatus'] })
    } catch (e) {
      toast(`${t('settings.backup.restoreFail2')}：${String(e)}`, 'error')
    } finally {
      setRestoring(false)
    }
  }

  return (
    <Card className="border bg-card">
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="text-sm font-semibold">{t('settings.backup.title')}</CardTitle>
          <p className="text-[11px] text-muted-foreground">{t('settings.backup.desc')}</p>
          <p className="mt-1 text-xs text-muted-foreground">{t('settings.backup.desc2')}</p>
        </div>
        <span className="shrink-0 rounded-lg border bg-muted/40 px-2.5 py-1 text-[11px] text-muted-foreground">
          {t('settings.backup.currentLabel')} <b className="font-mono text-foreground">{cur.upstreams ?? '—'}</b>
          {' · '}{t('settings.backup.wordLabel')} <b className="font-mono text-foreground">{cur.words ?? '—'}</b>
        </span>
      </CardHeader>
      <CardContent>
        {isLoading && <p className="py-6 text-center text-xs text-muted-foreground">{t('settings.backup.loading')}</p>}
        {!isLoading && backups.length === 0 && (
          <p className="py-6 text-center text-xs text-muted-foreground">{t('settings.backup.empty')}</p>
        )}
        <div className="space-y-1.5">
          {backups.map((b) => {
            // 结构比当前「多」的备份高亮，方便识别可能包含更多配置的版本。
            const richer = (b.upstreams ?? 0) > (cur.upstreams ?? 0) || (b.words ?? 0) > (cur.words ?? 0)
            return (
              <div
                key={b.file}
                className={cn(
                  'flex flex-wrap items-center gap-2 rounded-lg border px-3 py-2 text-xs',
                  richer ? 'border-amber-500/40 bg-amber-500/5' : 'bg-muted/20',
                )}
              >
                <span className="font-mono text-[11px] text-muted-foreground">
                  {b.mtime ? dayjs(b.mtime * 1000).format('YYYY-MM-DD HH:mm:ss') : '—'}
                </span>
                <span className="text-muted-foreground">
                  {t('settings.backup.summaryClients')} <b className="font-mono text-foreground">{b.upstreams}</b>
                  {' · '}{t('settings.backup.summaryCats')} <b className="font-mono text-foreground">{b.cats}</b>
                  {' · '}{t('settings.backup.summaryWords')} <b className="font-mono text-foreground">{b.words}</b>
                  {' · '}{t('settings.backup.summaryDomains')} <b className="font-mono text-foreground">{b.domains}</b>
                </span>
                {richer && (
                  <Badge className="bg-amber-500/15 text-[10px] text-amber-600 hover:bg-amber-500/15 dark:text-amber-400">
                    {t('settings.backup.richer')}
                  </Badge>
                )}
                <Button size="sm" variant="outline" className="ml-auto h-7 px-2.5 text-[11px]" onClick={() => setPending(b)}>
                  {t('settings.backup.restore')}
                </Button>
              </div>
            )
          })}
        </div>
      </CardContent>

      <Dialog open={pending != null} onOpenChange={(v) => !v && setPending(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t('settings.backup.confirmTitle')}</DialogTitle>
            <DialogDescription>
              {tf('settings.backup.confirmDesc', {
                time: pending?.mtime ? dayjs(pending.mtime * 1000).format('YYYY-MM-DD HH:mm:ss') : '—',
                a: cur.upstreams ?? 0, b: pending?.upstreams ?? 0,
                c: cur.words ?? 0, d: pending?.words ?? 0,
              })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button size="sm" variant="outline" onClick={() => setPending(null)} disabled={restoring}>{t('settings.confirm.cancel')}</Button>
            <Button size="sm" onClick={doRestore} disabled={restoring}>
              {restoring && <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />}
              {t('settings.backup.confirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}

// ========== 主页面 ==========
export default function SettingsPage({ embeddedTab }: { embeddedTab?: string } = {}) {
  const { lang, setLang, t, tf } = useI18n()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  // 页面隐藏时停止轮询；可见时自动刷新
  const { hidden } = useVisibility()
  // embeddedTab（独立页模式）：敏感词库/客户端管理直接渲染单个 tab，无 tab 栏）
  const defaultTab = embeddedTab ?? searchParams.get('tab') ?? 'advanced'
  const [activeTab, setActiveTab] = useState(defaultTab)
  // 侧边栏跳 /settings?tab=xxx 时同步 tab（defaultValue 只首次生效，已挂载后要受控切换）
  // 独立页模式不监听 searchParams（URL 保持 #/words / #/clients）
  // 注意：依赖必须是字符串值 searchParams.get('tab')，不能是 searchParams 对象——
  // HashRouter 下 useSearchParams 每次渲染可能返回新引用；依赖对象会让 effect 每次
  // 执行，因此只依赖字符串参数，避免覆盖用户当前选择。
  const tabParam = searchParams.get('tab')
  // 顶栏「更新到 vX」跳转时带 install=1，关于页自动开始下载
  const autoInstallUpdate = searchParams.get('install') === '1'
  useEffect(() => {
    if (!embeddedTab && tabParam) setActiveTab(tabParam)
  }, [tabParam, embeddedTab])
  const { data: cfg } = useQuery({ queryKey: ['config'], queryFn: getConfig, refetchInterval: hidden ? false : 120000 })
  const [editing, setEditing] = useState<UpstreamConfig | null>(null)
  const [adding, setAdding] = useState(false)
  const [testing, setTesting] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  // 查看审计报告 / 健康检查是网络请求，需局部 pending 反馈
  const [reportFetching, setReportFetching] = useState(false)
  const [healthChecking, setHealthChecking] = useState(false)
  const [netRestoring, setNetRestoring] = useState(false)
  const [clientSearch, setClientSearch] = useState('')
  const [testModel, setTestModel] = useState('')
  const [testApiKey, setTestApiKey] = useState('')
  const [testPathPrefix, setTestPathPrefix] = useState('/v1')
  const [testMode, setTestMode] = useState<'port' | 'models' | 'chat'>('port')
  // 内联添加输入（替代 window.prompt，WebView2 下不可靠）
  const [addWordCat, setAddWordCat] = useState<string | null>(null)
  const [addWordVal, setAddWordVal] = useState('')
  // 词条搜索：跨分类过滤，词库多时快速定位
  const [wordSearch, setWordSearch] = useState('')
  const [newCatName, setNewCatName] = useState('')
  // 从 .env 导入对话框
  const [envImportOpen, setEnvImportOpen] = useState(false)
  const [newPrefix, setNewPrefix] = useState('')
  const [newDomain, setNewDomain] = useState('')
  const [newPath, setNewPath] = useState('')
  const [newExcludeHost, setNewExcludeHost] = useState('')
  const [demoText, setDemoText] = useState('')
  const [demoResult, setDemoResult] = useState<{ ok: boolean; masked?: string; count?: number; items?: { label: string; original_len: number; token: string }[]; error?: string } | null>(null)
  // 真实脱敏测试（走代理）：客户端 / key / 模型 / 文本
  const [demoUpstream, setDemoUpstream] = useState('')
  const [demoApiKey, setDemoApiKey] = useState('')
  const [demoModel, setDemoModel] = useState('')
  const [realTesting, setRealTesting] = useState(false)
  const [healthInfo, setHealthInfo] = useState<Record<string, unknown> | null>(null)
  const [copiedMap, setCopiedMap] = useState<Record<string, boolean>>({})
  const [confirmDeleteCat, setConfirmDeleteCat] = useState<{ name: string; count: number } | null>(null)

  const triggerCopy = async (key: string, text: string) => {
    try {
      await copyText(text)
      setCopiedMap((m) => ({ ...m, [key]: true }))
      setTimeout(() => setCopiedMap((m) => ({ ...m, [key]: false })), 1500)
      toast(t('settings.toast.copied'))
    } catch {
      toast(t('settings.toast.copyFailed'), 'error')
    }
  }

  // 关于页：官网更新日志一键跳转（panel os.startfile 打开系统默认浏览器）
  const openSiteChangelog = async () => {
    try {
      const r = await shieldFetch('/api/open-url', {
        method: 'POST',
        body: JSON.stringify({ url: 'https://github.com/xiaYuTian11/maskit/releases' }),
      })
      if (!(r as { ok?: boolean }).ok) toast(t('settings.toast.openFail'), 'error')
    } catch (e) { toast(`${t('settings.toast.openFail')}：${String(e)}`, 'error') }
  }

  // 关于页：GitHub Releases 最新版本（更新日志）
  const [siteRelease, setSiteRelease] = useState<{ version: string; notes?: string; pub_date?: string } | null>(null)
  const [siteReleaseErr, setSiteReleaseErr] = useState('')
  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const r = await (isTauri()
          ? (await import('@tauri-apps/plugin-http')).fetch('https://api.github.com/repos/xiaYuTian11/maskit/releases/latest')
          : window.fetch('https://api.github.com/repos/xiaYuTian11/maskit/releases/latest'))
        const d = await r.json()
        if (alive && d?.tag_name) {
          setSiteRelease({
            version: String(d.tag_name).replace(/^v/, ''),
            notes: d.body,
            pub_date: d.published_at,
          })
        }
      } catch (e) {
        if (alive) setSiteReleaseErr(String(e).slice(0, 80))
      }
    }
    load()
    return () => { alive = false }
  }, [])

  // 主动审计（探针）：参数 + 进度
  const [auditUpstream, setAuditUpstream] = useState('')
  const [auditModel, setAuditModel] = useState('')
  const [auditProfile, setAuditProfile] = useState('general')
  const [confirmAudit, setConfirmAudit] = useState(false)
  const { data: auditJob } = useQuery({
    queryKey: ['auditJob'],
    queryFn: getAuditJob,
    refetchInterval: hidden ? false : 1200,
  })
  // 版本号取引擎运行时值，不写死在前端，避免与实际产物脱节。
  const { data: status } = useQuery({ queryKey: ['proxyStatus'], queryFn: getStatus, refetchInterval: hidden ? false : 10000 })
  const [auditReport, setAuditReport] = useState<string | null>(null)
  const auditRunning = auditJob?.running ?? false
  const auditDone = auditJob?.done ?? 0
  const auditTotal = auditJob?.total ?? 0
  const auditProgress = auditTotal > 0 ? Math.min(100, Math.round((auditDone / auditTotal) * 100)) : 0

  const runAuditMutation = useMutation({
    mutationFn: (opts: { upstream_name: string; model: string; profile: string }) => runAudit(opts),
    onSuccess: (r) => {
      if (!r.ok) {
        toast(r.error || t('settings.toast.auditStartFail'), 'error')
        return
      }
      toast(t('settings.toast.auditStarted'))
    },
    onError: (e: Error) => toast(`${t('settings.toast.auditStartFail')}：${e.message}`, 'error'),
  })

  const cancelAuditMutation = useMutation({
    mutationFn: cancelAudit,
    onSuccess: () => toast(t('settings.toast.cancelRequested')),
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

  // 价格同步状态 + 手动触发
  const { data: priceSyncState, refetch: refetchPriceSync } = useQuery({
    queryKey: ['priceSync'],
    queryFn: getPriceSyncStatus,
    refetchInterval: hidden ? false : 30000,
  })
  const priceSyncing = priceSyncState?.syncing ?? false
  // 价格明细弹窗：搜索 + 列表
  const [priceListOpen, setPriceListOpen] = useState(false)
  const [priceSearch, setPriceSearch] = useState('')
  const { data: priceList } = useQuery({
    queryKey: ['priceList'],
    queryFn: getPriceList,
    enabled: priceListOpen,
  })
  const openPriceList = () => { setPriceSearch(''); setPriceListOpen(true) }
  const syncPricesMutation = useMutation({
    mutationFn: syncPricesNow,
    onSuccess: (r) => {
      if (!r.ok) {
        toast(r.error || t('settings.toast.syncFail'), 'error')
      } else {
        toast(tf('settings.toast.syncDone', { n: r.state?.model_count ?? 0 }))
      }
      refetchPriceSync()
    },
    onError: (e: Error) => toast(`${t('settings.toast.syncErr')}：${e.message}`, 'error'),
  })

  const upstreams = useMemo(() => cfg?.upstreams ?? [], [cfg?.upstreams])
  const nextPort = useMemo(() => {
    const used = new Set(upstreams.map((u) => u.port))
    for (let p = 18704; p <= 18799; p++) {
      if (!used.has(p)) return p
    }
    return 18711
  }, [upstreams])

  const words = useMemo(() => {
    const raw = cfg?.sensitive as Record<string, string[]> | undefined
    return raw ?? {}
  }, [cfg])

  const saveQueueRef = useRef<Promise<void>>(Promise.resolve())

  const save = async (next: Partial<ShieldConfig> | (() => Promise<SaveConfigResponse>), msg?: string) => {
    setSaving(true)
    // 串行执行保存请求；规则开关只提交变化的条目，不携带旧的整表快照。
    const task = saveQueueRef.current.then(async () => {
      try {
        const r = await (typeof next === 'function' ? next() : saveConfig(next))
        if (!r.ok) {
          toast(r.error || t('settings.toast.saveFailed'), 'error')
          return
        }
        if (r.warnings?.length) {
          r.warnings.forEach((w) => toast(w, 'error'))
        }
        if (r.proxy_restarted) toast(t('settings.toast.restarted'))
        else toast(msg || t('settings.toast.saved'))
        if (r.config) {
          queryClient.setQueryData(['config'], r.config)
        }
        queryClient.invalidateQueries({ queryKey: ['config'] })
        queryClient.invalidateQueries({ queryKey: ['proxyStatus'] })
      } catch (e) {
        toast(`${t('settings.toast.saveFailed')}：${String(e)}`, 'error')
      }
    })
    saveQueueRef.current = task.catch(() => {})
    try {
      await task
    } finally {
      setSaving(false)
    }
  }

  const onSaveUpstream = (u: UpstreamConfig) => {
    // 清理空 header（Key 为空或 Value 为空的条目不发后端）
    const extra = u.extra_headers ?? {}
    const cleanExtra = Object.fromEntries(Object.entries(extra).filter(([, v]) => v.trim() !== ''))
    const clean: UpstreamConfig = { ...u, extra_headers: Object.keys(cleanExtra).length ? cleanExtra : undefined }
    // 编辑：按原 name 匹配（改名/改端口都更新而非新增）；新增：无匹配则添加
    const isEdit = editing != null
    const currentUps = queryClient.getQueryData<ShieldConfig>(['config'])?.upstreams ?? upstreams
    const next = isEdit
      ? currentUps.map((x) => (x.name === editing!.name ? clean : x))
      : [...currentUps, clean]
    save({ upstreams: next }, isEdit ? t('settings.toast.clientUpdated') : t('settings.toast.clientAdded'))
    setEditing(null)
    setAdding(false)
  }

  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const removeUpstream = (name: string) => {
    const currentUps = queryClient.getQueryData<ShieldConfig>(['config'])?.upstreams ?? upstreams
    save({ upstreams: currentUps.filter((u) => u.name !== name) }, tf('settings.toast.deleted', { name }))
    setConfirmDelete(null)
  }

  const doTest = async (u: UpstreamConfig) => {
    setTesting(u.name)
    setTestResult((r) => ({ ...r, [u.name]: '' }))
    try {
      const r = await testUpstream({
        name: u.name, port: u.port, mode: testMode,
        api_key: testApiKey || undefined,
        model: testModel || undefined,
        path_prefix: testPathPrefix || undefined,
      })
      setTestResult((m) => ({
        ...m,
        [u.name]: r.ok ? `✓ ${r.message ?? t('settings.toast.testOk')}` : `✗ ${r.error ?? t('settings.toast.testFailed')}`,
      }))
      if (!r.ok) toast(`${t('settings.toast.testFailed')}：${r.error}`, 'error')
      else toast(t('settings.toast.testPassed'))
    } catch (e) {
      setTestResult((m) => ({ ...m, [u.name]: `✗ ${String(e)}` }))
    } finally {
      setTesting(null)
    }
  }

  const addWord = (cat: string, val: string) => {
    const v = val.trim()
    if (!v) return
    const existing = (words[cat] ?? [])
    // 去重：已存在则提示，不重复添加
    if (existing.some((x) => x === v)) {
      toast(tf('settings.toast.wordExists', { word: v }), 'error')
      setAddWordVal('')
      return
    }
    // 短词告警（不阻断）：自定义词是无边界的字面子串匹配，1-2 字符会连带打码 data1 这类
    // 标识符（实测加 "a1" 会把 "data1" 变成 "dat{{TERM_x}}"），把上游 prompt 改坏且极难排查。
    // re: 正则词走用户自己的模式，不套用这个长度门槛。
    if (v.length < 3 && !v.startsWith('re:')) {
      toast(tf('settings.toast.wordTooShort', { word: v, n: v.length }), 'error')
    }
    const next = { ...words, [cat]: [...existing, v] }
    save({ sensitive: next }, t('settings.toast.added'))
    setAddWordVal('')
    setAddWordCat(null)
  }

  const removeWord = (cat: string, word: string) => {
    const next = { ...words, [cat]: (words[cat] ?? []).filter((x) => x !== word) }
    save({ sensitive: next }, t('settings.toast.removed'))
  }

  const addCategory = (name: string) => {
    if (!name.trim()) return
    save({ sensitive: { ...words, [name.trim()]: [] } }, t('settings.toast.catAdded'))
    setNewCatName('')
  }

  const removeCategory = (cat: string) => {
    const next = { ...words }
    delete next[cat]
    const curDisabled = { ...(cfg?.sensitive_word_disabled as Record<string, string[]> | undefined) ?? {} }
    const nextDisabled = { ...curDisabled }
    delete nextDisabled[cat]
    const curCatDisabled = new Set((cfg?.sensitive_disabled as string[]) ?? [])
    curCatDisabled.delete(cat)
    save({ sensitive: next, sensitive_word_disabled: nextDisabled, sensitive_disabled: [...curCatDisabled] }, tf('settings.toast.catDeleted', { cat }))
  }

  const setRule = (rule: string, on: boolean) => {
    save(() => saveBuiltinRules({ [rule]: on }), tf(on ? 'settings.toast.ruleOn' : 'settings.toast.ruleOff', { rule }))
  }

  const setSecret = (v: string[], msg?: string) => save({ secret_prefixes: v }, msg || t('settings.toast.prefixUpdated'))

  const handleAddPrefix = () => {
    const p = newPrefix.trim()
    if (!p) return
    if (secretPrefixes.includes(p)) {
      toast(t('settings.words.prefixExists'), 'error')
      return
    }
    if (!/^[@A-Za-z0-9][@A-Za-z0-9_.-]*$/.test(p) || p.length > 32) {
      toast(t('settings.words.prefixInvalid'), 'error')
      return
    }
    setSecret([...secretPrefixes, p], `${t('settings.toast.prefixUpdated')} (+${p})`)
    setNewPrefix('')
  }

  const toggleAuditSignal = (sig: string, on: boolean) => {
    const audit = (cfg?.audit as Record<string, unknown>) ?? {}
    const signals = (audit.signals as Record<string, boolean>) ?? {}
    save({ audit: { ...audit, signals: { ...signals, [sig]: on } } }, t('settings.toast.signalUpdated'))
  }

  const doOpenDataDir = async () => {
    try {
      await openDataDir()
    } catch {
      // 忽略
    }
  }

  const toggle = (key: keyof ShieldConfig, v: boolean) => save({ [key]: v } as Partial<ShieldConfig>)

  const auditCfg = (cfg?.audit as Record<string, unknown>) ?? {}
  const auditSignals = (auditCfg.signals as Record<string, boolean>) ?? {}
  const builtinRules = (cfg?.builtin_rules as Record<string, boolean>) ?? {}
  const ruleMeta = (cfg?._meta?.builtin_rule_meta as Record<string, string>) ?? {}
  const secretPrefixes = (cfg?.secret_prefixes as string[]) ?? []
  const streamExclude = (cfg?.stream_exclude_hosts as string[]) ?? []
  // 分类级禁用（sensitive_disabled: string[]）
  const catDisabledList = (cfg?.sensitive_disabled as string[]) ?? []
  const toggleCatDisabled = (cat: string) => {
    if (!cfg) return
    const cur = new Set((cfg.sensitive_disabled as string[]) ?? [])
    const wasDisabled = cur.has(cat)
    if (wasDisabled) cur.delete(cat)
    else cur.add(cat)
    save({ sensitive_disabled: [...cur] } as Partial<ShieldConfig>, tf(wasDisabled ? 'settings.toast.catEnabled' : 'settings.toast.catDisabled', { cat }))
  }

  // 词级禁用（sensitive_word_disabled: {label: [words]}）
  const wordDisabled = (cfg?.sensitive_word_disabled as Record<string, string[]>) ?? {}

  const toggleWordDisabled = (cat: string, word: string) => {
    if (!cfg) return
    const cur = { ...(cfg.sensitive_word_disabled as Record<string, string[]> | undefined) ?? {} }
    const arr = new Set(cur[cat] ?? [])
    if (arr.has(word)) arr.delete(word)
    else arr.add(word)
    const next = { ...cur }
    if (arr.size > 0) next[cat] = [...arr]
    else delete next[cat]
    save({ sensitive_word_disabled: next } as Partial<ShieldConfig>, arr.has(word) ? t('settings.toast.wordDisabled') : t('settings.toast.wordEnabled'))
  }

  // 整词匹配开关（sensitive_word_whole: [words]）：开启后该词两侧加边界，
  // 避免短词子串误命中更长的词。
  const wordWhole = (cfg?.sensitive_word_whole as string[]) ?? []
  const toggleWordWhole = (word: string) => {
    if (!cfg) return
    const cur = new Set(wordWhole)
    if (cur.has(word)) cur.delete(word)
    else cur.add(word)
    save({ sensitive_word_whole: [...cur] } as Partial<ShieldConfig>, cur.has(word) ? t('settings.toast.wholeOn') : t('settings.toast.wholeOff'))
  }

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            {embeddedTab === 'words' ? t('settings.pageTitle.words') : embeddedTab === 'clients' ? t('settings.pageTitle.clients') : t('settings.pageTitle.advanced')}
          </h1>
          <p className="mt-1 text-sm font-medium text-muted-foreground">
            {embeddedTab === 'words'
              ? t('settings.pageSubtitle.words')
              : embeddedTab === 'clients'
                ? t('settings.pageSubtitle.clients')
                : t('settings.pageSubtitle.advanced')}
          </p>
        </div>
        {/* 原来这里是一个「保存全部」按钮，onClick 是 save({})——提交一个空补丁。
            它不只是坏，而是多余：本页每个开关都在 onChange 里即时保存，
            文本框按 Enter 提交，压根没有「待保存」的本地状态。
            留着它反而制造「我的改动还没存」的错觉，点一下又什么都没发生。
            改为如实说明当前行为，避免让用户误以为存在待提交状态。 */}
        <span className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
          {saving
            ? <><Loader2 className="h-3.5 w-3.5 animate-spin" />{t('settings.saving')}</>
            : <><Check className="h-3.5 w-3.5 text-emerald-500" />{t('settings.autoSaved')}</>}
        </span>
      </div>

      {/* embeddedTab（独立页模式）：隐藏 tab 栏，只渲染对应内容；URL 保持 /words /clients */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        {!embeddedTab && (
          <TabsList>
            <TabsTrigger value="advanced">{t('settings.tab.advanced')}</TabsTrigger>
            <TabsTrigger value="security">{t('settings.tab.security')}</TabsTrigger>
            <TabsTrigger value="tools">{t('settings.tab.tools')}</TabsTrigger>
            {/* 「关于」此前只有 TabsContent 没有 TabsTrigger：内容存在但点不进去，
                只能靠 ?tab=about 这个没人知道的 URL 参数进入，等于授权激活、
                版本与更新日志必须有明确的「关于」入口，避免内容渲染后却没有可达标签。 */}
            <TabsTrigger value="about">{t('settings.tab.about')}</TabsTrigger>
          </TabsList>
        )}

        {/* ===== 客户端管理（仅 embedded 独立页渲染；#/settings 不含此项） ===== */}
        {embeddedTab === 'clients' && (
        <TabsContent value="clients" className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-[13px] text-muted-foreground">
              {tf('settings.clients.count', { n: upstreams.length })}
            </p>
            <Input
              className="h-8 w-48 text-xs"
              placeholder={t('settings.clients.searchPh')}
              value={clientSearch}
              onChange={(e) => setClientSearch(e.target.value)}
            />
            <Button size="sm" variant="outline" className="h-8" onClick={() => setAdding(true)}>
              <Plus className="mr-1 h-3.5 w-3.5" /> {t('settings.clients.add')}
            </Button>
          </div>

          {/* 测试参数 */}
          <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/30 px-3 py-2">
            <span className="text-xs text-muted-foreground">{t('settings.clients.testParams')}</span>
            <Select value={testMode} onValueChange={(v) => setTestMode(v as typeof testMode)}>
              <SelectTrigger className="h-7 w-24 text-xs"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="port">{t('settings.clients.mode.port')}</SelectItem>
                <SelectItem value="models">{t('settings.clients.mode.models')}</SelectItem>
                <SelectItem value="chat">{t('settings.clients.mode.chat')}</SelectItem>
              </SelectContent>
            </Select>
            <Input className="h-7 w-32 font-mono text-xs" placeholder={t('settings.clients.modelPh')} value={testModel} onChange={(e) => setTestModel(e.target.value)} />
            <Input className="h-7 w-40 font-mono text-xs" placeholder={t('settings.clients.apiKeyPh')} value={testApiKey} onChange={(e) => setTestApiKey(e.target.value)} />
                  <Input className="h-7 w-24 font-mono text-xs" placeholder={t('settings.clients.pathPrefixPh')} value={testPathPrefix} onChange={(e) => setTestPathPrefix(e.target.value)} />
          </div>

          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3" style={{ alignItems: 'stretch' }}>
            {upstreams.filter((u) => !clientSearch || u.name.includes(clientSearch) || String(u.port).includes(clientSearch) || (u.target ?? '').includes(clientSearch)).map((u) => {
              const baseUrl = `http://127.0.0.1:${u.port}`
              // SDK Base URL 规范化：
              // 1. OpenAI 兼容体系：官方 SDK 要求带 /v1（例如 http://127.0.0.1:18701/v1）
              // 2. Anthropic、Gemini 体系：官方 SDK 明确要求根地址（例如 http://127.0.0.1:18703），SDK 内部会自动请求 /v1/messages 等，追加 /v1 会导致 /v1/v1/messages 404
              const cType = detectClientType(u)
              const isStandardOpenAI = cType === 'openai' && (u.paths ?? []).some((p) => p.startsWith('/v1'))
              const standardBaseUrl = isStandardOpenAI ? `${baseUrl}/v1` : baseUrl
              const paths: string[] = (u.paths ?? []).length > 0 ? (u.paths as string[]) : ['/v1/chat/completions', '/v1/completions', '/v1/messages', '/v1/responses']
              return (
              <Card key={u.port} className="flex h-full flex-col border bg-card shadow-[var(--shadow-card)] transition-[transform,box-shadow] duration-200 hover:-translate-y-0.5 hover:shadow-[var(--shadow-card-hover)]">
                <CardContent className="flex flex-1 flex-col gap-2.5 p-3.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold">{u.name}</span>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      :{u.port}
                    </Badge>
                    {u.use_proxy && (
                      <Badge className="bg-amber-500/10 px-1.5 text-[10px] font-medium text-amber-600 hover:bg-amber-500/10 dark:text-amber-400">
                        {t('settings.clients.egress')}
                      </Badge>
                    )}
                    <code className="ml-auto truncate font-mono text-[11px] text-muted-foreground" title={u.target}>
                      {u.target}
                    </code>
                    <div className="flex items-center gap-1">
                      <Button size="sm" variant="ghost" className="h-8 px-2 text-xs" onClick={() => doTest(u)} disabled={testing === u.name}>
                        {testing === u.name ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plug className="h-3 w-3" />}
                        {t('settings.clients.test')}
                      </Button>
                      <Button size="sm" variant="ghost" className="h-8 px-2 text-xs" onClick={() => setEditing(u)}>
                        <Pencil className="h-3 w-3" /> {t('settings.clients.edit')}
                      </Button>
                      <Button size="sm" variant="ghost" className="h-8 px-2 text-xs text-red-600 hover:text-red-600 dark:text-red-400" onClick={() => setConfirmDelete(u.name)}>
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                  {/* Base URL 行：一键复制符合 SDK 规范的 Base URL（OpenAI 规范带 /v1） */}
                  <div className="flex items-center gap-2 rounded-lg border bg-muted/30 px-2.5 py-1.5">
                    <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{t('settings.clients.baseUrl')}</span>
                    <code className="min-w-0 flex-1 truncate font-mono text-[12px] font-medium text-foreground">{standardBaseUrl}</code>
                    <Button
                      size="sm" variant="ghost" className="h-6 shrink-0 gap-1 px-2 text-[11px]"
                      onClick={() => triggerCopy(`url:${u.name}`, standardBaseUrl)}
                    >
                      {copiedMap[`url:${u.name}`] ? (
                        <>
                          <Check className="h-3 w-3 text-emerald-500" />
                          <span className="font-medium text-emerald-600 dark:text-emerald-400">{t('detail.copied')}</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          <span>{t('settings.clients.copy')}</span>
                        </>
                      )}
                    </Button>
                  </div>
                  {/* 支持路径：点击复制带路径的完整地址 */}
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="shrink-0 text-[10px] font-medium text-muted-foreground">{t('settings.clients.supportPaths')}</span>
                    {paths.map((p) => {
                      const isCopied = !!copiedMap[`path:${u.name}:${p}`]
                      return (
                        <button
                          key={p}
                          type="button"
                          title={tf('settings.clients.copyUrl', { url: `${baseUrl}${p}` })}
                          onClick={() => triggerCopy(`path:${u.name}:${p}`, `${baseUrl}${p}`)}
                          className={cn(
                            'rounded-full border px-2 py-0.5 font-mono text-[10px] transition-all',
                            isCopied
                              ? 'border-emerald-500 bg-emerald-500/10 font-semibold text-emerald-600 dark:text-emerald-400'
                              : 'border-border bg-card text-muted-foreground hover:border-primary/40 hover:text-foreground',
                          )}
                        >
                          {isCopied ? `✓ ${p}` : p}
                        </button>
                      )
                    })}
                    {(cfg?.capture_mode ?? 'reverse') !== 'reverse' && u.base_path && (
                      <Badge variant="outline" className="font-mono text-[10px]" title={t('settings.clients.routePrefix')}>{tf('settings.clients.routePrefixVal', { p: u.base_path })}</Badge>
                    )}
                    {Object.keys(u.extra_headers ?? {}).length > 0 && (
                      <Badge variant="outline" className="font-mono text-[10px]" title={tf('settings.clients.injectedHeaders', { list: Object.keys(u.extra_headers ?? {}).join(', ') })}>
                        {tf('settings.clients.headerCount', { n: Object.keys(u.extra_headers ?? {}).length })}
                      </Badge>
                    )}
                  </div>
                  {testResult[u.name] && (
                    <div className={cn('truncate text-[11px]', testResult[u.name].startsWith('✓') ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400')}>
                      {testResult[u.name]}
                    </div>
                  )}
                </CardContent>
              </Card>
              )
            })}
            {upstreams.length === 0 && (
              <Card className="border bg-card">
                <CardContent className="py-10 text-center text-sm text-muted-foreground">
                  {t('settings.clients.noClients')}
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>
        )}

        {/* ===== 敏感词库（仅 embedded 独立页渲染） ===== */}
        {embeddedTab === 'words' && (
        <TabsContent value="words" className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-[13px] text-muted-foreground">
              {tf('settings.words.count', { a: Object.keys(words).length, b: Object.values(words).reduce((a, b) => a + b.length, 0) })}
            </p>
            <div className="flex gap-1.5">
              <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => {
                // 并集：保留已有禁用 + 新增 ≤2 字短词，不覆盖用户手动禁用的长词
                const cur = { ...(cfg?.sensitive_word_disabled as Record<string, string[]> | undefined) ?? {} }
                Object.entries(words).forEach(([cat, list]) => {
                  const shorts = list.filter((w) => w.length <= 2)
                  const existing = new Set(cur[cat] ?? [])
                  shorts.forEach((w) => existing.add(w))
                  if (existing.size > 0) cur[cat] = [...existing]
                  else delete cur[cat]
                })
                save({ sensitive_word_disabled: cur } as Partial<ShieldConfig>, tf('settings.toast.disableShorts', { n: Object.values(cur).flat().length }))
              }} title={t('settings.words.disableShortsTitle')}>
                {t('settings.words.disableShorts')}
              </Button>
              <div className="flex items-center gap-1.5">
                {newCatName !== '' && (
                  <Input
                    className="h-7 w-32 text-xs"
                    placeholder={t('settings.words.catNamePh')}
                    value={newCatName}
                    onChange={(e) => setNewCatName(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && addCategory(newCatName)}
                    autoFocus
                  />
                )}
                <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => newCatName === '' ? setNewCatName(' ') : addCategory(newCatName)}>
                  <Plus className="mr-1 h-3 w-3" /> {t('settings.words.newCat')}
                </Button>
              </div>
              <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setEnvImportOpen(true)}>
                <FileText className="mr-1 h-3 w-3" /> {t('settings.words.envImport')}
              </Button>
            </div>
          </div>

          {/* 分类词表：卡片式（每分类一张卡，网格布局） */}
          <div className="rounded-lg border bg-muted/30 px-3 py-2 text-[11px] text-muted-foreground">
            {t('settings.words.regexHint').split('{n}')[0]}<code className="font-mono">re:</code>{t('settings.words.regexHint').split('{n}').slice(1).join('{n}')}
          </div>
          {/* 词条搜索：词库多时快速定位 */}
          {Object.values(words).reduce((n, l) => n + l.length, 0) > 15 && (
            <div className="relative max-w-xs">
              <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={wordSearch}
                onChange={(e) => setWordSearch(e.target.value)}
                placeholder={t('settings.words.searchPh')}
                className="h-8 pl-8 pr-7 text-xs"
              />
              {wordSearch && (
                <button
                  type="button"
                  onClick={() => setWordSearch('')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground/60 hover:text-foreground"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          )}
          <div className="grid items-stretch gap-3 md:grid-cols-2">
            {Object.entries(words).map(([cat, list]) => {
              const isCatDisabled = catDisabledList.includes(cat)
              const filtered = wordSearch.trim()
                ? list.filter((w) => w.toLowerCase().includes(wordSearch.trim().toLowerCase()))
                : list
              return (
              <Card
                key={cat}
                className={cn(
                  'flex h-full flex-col border bg-card shadow-[var(--shadow-card)] transition-all hover:shadow-[var(--shadow-card-hover)]',
                  isCatDisabled && 'border-dashed border-border/80 bg-muted/15 opacity-65 hover:opacity-100',
                )}
              >
                <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
                  <div className="flex items-center gap-2">
                    <Switch
                      checked={!isCatDisabled}
                      onCheckedChange={() => toggleCatDisabled(cat)}
                      className="scale-75 shrink-0"
                      title={isCatDisabled ? t('settings.words.catEnableHint') : t('settings.words.catDisableHint')}
                    />
                    <span className={cn('text-[13px] font-semibold', isCatDisabled && 'text-muted-foreground line-through')}>{cat}</span>
                    <span className={cn('flex h-5 min-w-5 items-center justify-center rounded-full px-1.5 text-[10px] font-semibold', isCatDisabled ? 'bg-muted text-muted-foreground' : 'bg-primary/10 text-primary')}>
                      {list.length}
                    </span>
                    {isCatDisabled && (
                      <span className="rounded bg-muted/80 px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                        {t('settings.words.catDisabledBadge')}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5">
                    {addWordCat === cat ? (
                      <Input
                        className="h-6 w-28 text-xs"
                        placeholder={t('settings.words.inputWordPh')}
                        title={t('settings.words.regexTitle')}
                        value={cat === addWordCat ? addWordVal : ''}
                        onChange={(e) => setAddWordVal(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault()
                            if (addWordVal.trim()) addWord(cat, addWordVal)
                          }
                        }}
                        onBlur={() => { if (!addWordVal.trim()) setAddWordCat(null) }}
                        autoFocus
                      />
                    ) : null}
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 px-2 text-[11px]"
                      title={t('settings.words.regexTitle')}
                      onMouseDown={(e) => e.preventDefault()}
                      onClick={() => {
                        if (addWordCat === cat) {
                          if (addWordVal.trim()) {
                            addWord(cat, addWordVal)
                          } else {
                            setAddWordCat(null)
                          }
                        } else {
                          setAddWordCat(cat)
                          setAddWordVal('')
                        }
                      }}
                    >
                      {addWordCat === cat && addWordVal.trim() ? t('common.save') : t('settings.words.addWord')}
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-6 w-6 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                      title={t('settings.words.deleteCat')}
                      onClick={() => {
                        if (list.length > 0) {
                          setConfirmDeleteCat({ name: cat, count: list.length })
                        } else {
                          removeCategory(cat)
                        }
                      }}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="flex min-h-8 flex-wrap gap-1.5">
                    {filtered.map((w) => {
                      const disabled = (wordDisabled[cat] ?? []).includes(w)
                      const whole = wordWhole.includes(w)
                      // 三态：正常 → 整词匹配 → 禁用（循环）
                      const nextAction = () => {
                        if (disabled) {
                          // 禁用 → 正常
                          toggleWordDisabled(cat, w)
                        } else if (whole) {
                          // 整词 → 禁用
                          toggleWordWhole(w)
                          toggleWordDisabled(cat, w)
                        } else {
                          // 正常 → 整词
                          toggleWordWhole(w)
                        }
                      }
                      return (
                        <span
                          key={w}
                          className={cn(
                            'group inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs transition-colors',
                            disabled
                              ? 'border-border bg-muted/30 text-muted-foreground line-through opacity-60'
                              : whole
                                ? 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400'
                                : 'border-primary/15 bg-primary/5 text-foreground hover:border-primary/40',
                          )}
                        >
                          <button
                            title={disabled ? t('settings.words.wordTitle') : whole ? t('settings.words.wholeTitle') : t('settings.words.substrTitle')}
                            onClick={nextAction}
                          >
                            {w}
                            {whole && !disabled && <span className="ml-0.5 text-[9px] font-bold">{t('settings.words.wholeBadge')}</span>}
                          </button>
                          <button
                            type="button"
                            className="text-muted-foreground opacity-50 transition-opacity hover:text-red-500 group-hover:opacity-100"
                            onClick={() => removeWord(cat, w)}
                            title={t('settings.words.delTitle')}
                            aria-label={t('settings.words.delTitle')}
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </span>
                      )
                    })}
                    {filtered.length === 0 && (
                      <span className="text-xs text-muted-foreground">{wordSearch ? t('settings.words.noMatch') : t('settings.words.emptyCat')}</span>
                    )}
                  </div>
                </CardContent>
              </Card>
              )
            })}
            {Object.keys(words).length === 0 && (
              <Card className="col-span-full border bg-card">
                <CardContent className="py-10 text-center text-sm text-muted-foreground">
                  {t('settings.words.noCats')}
                </CardContent>
              </Card>
            )}
          </div>

          {/* 分类删除确认弹窗 */}
          <Dialog open={!!confirmDeleteCat} onOpenChange={(open) => !open && setConfirmDeleteCat(null)}>
            <DialogContent className="max-w-md">
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2 text-destructive">
                  <AlertTriangle className="h-5 w-5" />
                  {t('settings.words.confirmDeleteCatTitle')}
                </DialogTitle>
                <DialogDescription className="pt-2 text-sm leading-relaxed text-foreground">
                  {tf('settings.words.confirmDeleteCatDesc', {
                    name: confirmDeleteCat?.name ?? '',
                    count: confirmDeleteCat?.count ?? 0,
                  })}
                </DialogDescription>
              </DialogHeader>
              <DialogFooter className="gap-2 sm:gap-0">
                <Button variant="outline" size="sm" onClick={() => setConfirmDeleteCat(null)}>
                  {t('common.cancel')}
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => {
                    if (confirmDeleteCat) {
                      removeCategory(confirmDeleteCat.name)
                      setConfirmDeleteCat(null)
                    }
                  }}
                >
                  {t('common.confirmDelete')}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* 从 .env 导入：目标分类候选取引擎内置标签（cfg.builtin_rules 的键），
              这样用户不必先手工建分类；凭据行的可选范围由对话框内部收窄到凭据标签。 */}
          <EnvImportDialog
            open={envImportOpen}
            onOpenChange={setEnvImportOpen}
            words={words}
            builtinLabels={Object.keys(builtinRules)}
            onImport={(next, msg) => save({ sensitive: next }, msg)}
          />

          <Card className="border bg-card">
            <CardHeader className="flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle className="text-sm font-semibold">{t('settings.words.builtinRules')}</CardTitle>
                <p className="mt-0.5 text-[11px] text-muted-foreground">{t('settings.words.builtinRulesHint')}</p>
              </div>
              <div className="flex gap-1.5">
                <Button size="sm" variant="outline" className="h-6 text-[11px]" disabled={Object.keys(builtinRules).length === 0} onClick={() => {
                  const next = Object.fromEntries(Object.keys(builtinRules).map((r) => [r, true]))
                  save(() => saveBuiltinRules(next), t('settings.toast.allOn'))
                }}>{t('settings.words.allOn')}</Button>
                <Button size="sm" variant="outline" className="h-6 text-[11px]" disabled={Object.keys(builtinRules).length === 0} onClick={() => {
                  const next = Object.fromEntries(Object.keys(builtinRules).map((r) => [r, false]))
                  save(() => saveBuiltinRules(next), t('settings.toast.allOff'))
                }}>{t('settings.words.allOff')}</Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {BUILTIN_RULE_GROUPS.map((group) => {
                const groupRules = group.rules.filter((r) => r in builtinRules)
                if (groupRules.length === 0) return null
                const onCount = groupRules.filter((r) => builtinRules[r]).length
                return (
                  <div key={group.key} className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-foreground/80">{t(group.labelKey)}</span>
                      <span className="rounded-full bg-muted px-1.5 py-0.2 font-mono text-[10px] text-muted-foreground">
                        {onCount}/{groupRules.length}
                      </span>
                    </div>
                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 md:grid-cols-3">
                      {groupRules.map((rule) => {
                        const on = Boolean(builtinRules[rule])
                        return (
                          <label
                            key={rule}
                            title={ruleMeta[rule] || rule}
                            className={cn(
                              'flex cursor-pointer items-center justify-between rounded-lg border px-3 py-2 transition-colors',
                              on
                                ? 'border-primary/25 bg-primary/5 hover:border-primary/40'
                                : 'border-border bg-muted/30 opacity-70 hover:opacity-100',
                            )}
                          >
                            <div className="min-w-0 pr-2">
                              <span className={cn('font-mono text-xs', on && 'font-medium text-primary')}>{rule}</span>
                              {ruleMeta[rule] && (
                                <div className="truncate text-[10px] text-muted-foreground" title={ruleMeta[rule]}>{ruleMeta[rule]}</div>
                              )}
                            </div>
                            <Switch checked={on} onCheckedChange={(v) => setRule(rule, v)} className="scale-75 shrink-0" />
                          </label>
                        )
                      })}
                    </div>
                  </div>
                )
              })}
            </CardContent>
          </Card>

          <Card className="border bg-card">
            <CardHeader className="space-y-1">
              <CardTitle className="text-sm font-semibold">{t('settings.words.secretPrefix')}</CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                {t('settings.words.secretPrefixDesc')}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap items-center gap-2">
                {secretPrefixes.map((p) => (
                  <span key={p} className="group inline-flex items-center gap-1 rounded-full border bg-muted/30 px-2.5 py-0.5 font-mono text-xs">
                    {p}
                    <button type="button" className="text-muted-foreground opacity-60 hover:text-red-500 group-hover:opacity-100" onClick={() => setSecret(secretPrefixes.filter((x) => x !== p), `${t('settings.toast.removed')} ${p}`)} title={t('settings.words.delTitle')} aria-label={t('settings.words.delTitle')}><X className="h-3 w-3" /></button>
                  </span>
                ))}
                <div className="flex items-center gap-1.5">
                  <Input
                    className="h-7 w-36 text-xs font-mono"
                    placeholder={t('settings.words.prefixPh')}
                    value={newPrefix}
                    onChange={(e) => setNewPrefix(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault()
                        handleAddPrefix()
                      }
                    }}
                  />
                  <Button
                    size="sm" variant="ghost" className="h-6 text-[11px]"
                    onClick={handleAddPrefix}
                  >
                    {t('settings.words.prefixAdd')}
                  </Button>
                </div>
                {secretPrefixes.length > 0 && (
                  <Button size="sm" variant="ghost" className="h-6 text-[11px] text-muted-foreground" onClick={() => setSecret([])}>
                    {t('settings.words.clear')}
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        )}

        {/* ===== 高级选项 ===== */}
        {!embeddedTab && (
        <TabsContent value="advanced" className="space-y-4">
          {/*
                  目标域名 / 拦截路径只在「透传模式」下生效，反向代理模式（默认）走的是
            另一条路：apply_reverse_routing 按入站端口匹配到客户端，再用该客户端自己的
            paths 白名单判断是否脱敏（transparent.py 反代分支根本不读 TARGET_DOMAINS）。
              反代模式下把它们摆在设置里会造成「配了不生效」的假开关——用户在客户端配一遍、
            这里再配一遍，还互相矛盾。所以按模式条件显示，而不是删（透传模式仍需要）。
          */}
          {(cfg?.capture_mode ?? 'reverse') === 'reverse' ? (
            <Card className="border bg-card">
              <CardHeader>
                <CardTitle className="text-sm font-semibold">{t('settings.advanced.trafficScope')}</CardTitle>
                <p className="mt-1 text-xs text-muted-foreground">
                  {t('settings.advanced.currentModeIs')}<b className="text-foreground">{t('dash.captureMode.reverse')}</b>{t('settings.advanced.reverseScopeHint')}
                </p>
              </CardHeader>
              <CardContent>
                <Button size="sm" variant="outline" className="h-8 text-xs" onClick={() => navigate('/clients')}>
                  {t('settings.advanced.goClients')}
                </Button>
              </CardContent>
            </Card>
          ) : (
          <>
          {/* 目标域名（仅透传模式生效） */}
          <Card className="border bg-card">
            <CardHeader className="flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle className="text-sm font-semibold">{t('settings.advanced.targetDomains')}</CardTitle>
                <p className="mt-1 text-xs text-muted-foreground">{t('settings.advanced.targetDomainsHint')}</p>
              </div>
              <div className="flex items-end gap-2">
                <Input
                  className="h-8 w-56 text-xs"
                  placeholder={t('settings.advanced.domainPh')}
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && newDomain.trim()) {
                      const domains = (cfg?.target_domains as string[] | undefined) ?? []
                      if (!domains.includes(newDomain.trim())) save({ target_domains: [...domains, newDomain.trim()] }, t('settings.toast.domainAdded'))
                      setNewDomain('')
                    }
                  }}
                />
                <Button size="sm" variant="ghost" className="h-8 text-[11px]" onClick={() => {
                  if (newDomain.trim()) {
                    const domains = (cfg?.target_domains as string[] | undefined) ?? []
                    if (!domains.includes(newDomain.trim())) save({ target_domains: [...domains, newDomain.trim()] }, t('settings.toast.domainAdded'))
                    setNewDomain('')
                  }
                }}>{t('settings.advanced.domainAdd')}</Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {((cfg?.target_domains as string[] | undefined) ?? []).map((d) => (
                  <span key={d} className="group flex items-center gap-1 rounded-full border bg-muted/30 px-2.5 py-0.5 font-mono text-xs">
                    {d}
                    <button type="button" className="text-muted-foreground opacity-60 hover:text-red-500 group-hover:opacity-100" onClick={() => {
                      const domains = (cfg?.target_domains as string[] | undefined) ?? []
                      save({ target_domains: domains.filter((x) => x !== d) }, tf('settings.toast.deleted', { name: d }))
                    }} title={t('settings.words.delTitle')} aria-label={t('settings.words.delTitle')}><X className="h-3 w-3" /></button>
                  </span>
                ))}
                {((cfg?.target_domains as string[] | undefined) ?? []).length === 0 && (
                  <span className="text-xs text-muted-foreground">{t('settings.advanced.noDomains')}</span>
                )}
              </div>
            </CardContent>
          </Card>

          {/* 拦截路径 */}
          <Card className="border bg-card">
            <CardHeader className="flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle className="text-sm font-semibold">{t('settings.advanced.interceptPaths')}</CardTitle>
                <p className="mt-1 text-xs text-muted-foreground">{t('settings.advanced.interceptPathsHint')}</p>
              </div>
              <div className="flex items-end gap-2">
                <Input
                  className="h-8 w-56 text-xs"
                  placeholder={t('settings.advanced.pathPh')}
                  value={newPath}
                  onChange={(e) => setNewPath(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && newPath.trim()) {
                      const paths = (cfg?.api_paths as string[] | undefined) ?? []
                      if (!paths.includes(newPath.trim())) save({ api_paths: [...paths, newPath.trim()] }, t('settings.toast.pathAdded'))
                      setNewPath('')
                    }
                  }}
                />
                <Button size="sm" variant="ghost" className="h-8 text-[11px]" onClick={() => {
                  if (newPath.trim()) {
                    const paths = (cfg?.api_paths as string[] | undefined) ?? []
                    if (!paths.includes(newPath.trim())) save({ api_paths: [...paths, newPath.trim()] }, t('settings.toast.pathAdded'))
                    setNewPath('')
                  }
                }}>{t('settings.advanced.pathAdd')}</Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {((cfg?.api_paths as string[] | undefined) ?? []).map((p) => (
                  <span key={p} className="group flex items-center gap-1 rounded-full border bg-muted/30 px-2.5 py-0.5 font-mono text-xs">
                    {p}
                    <button type="button" className="text-muted-foreground opacity-60 hover:text-red-500 group-hover:opacity-100" onClick={() => {
                      const paths = (cfg?.api_paths as string[] | undefined) ?? []
                      save({ api_paths: paths.filter((x) => x !== p) }, tf('settings.toast.deleted', { name: p }))
                    }} title={t('settings.words.delTitle')} aria-label={t('settings.words.delTitle')}><X className="h-3 w-3" /></button>
                  </span>
                ))}
              </div>
            </CardContent>
          </Card>
          </>
          )}

          <Card className="border bg-card">
            <CardHeader>
              <CardTitle className="text-sm font-semibold">{t('settings.advanced.engineBehavior')}</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 md:grid-cols-2">
              <div>
                <Label className="text-xs">{t('settings.advanced.captureMode')}</Label>
                {/* reverse 模式是核心场景（客户端 base_url 指向本机端口），
                    锁定 reverse 隐藏选择器，避免误切到 explicit/local（需证书+管理员）
                    若未来启用这些模式，再恢复选择器 */}
                <div className="mt-1 flex h-8 items-center rounded-md border bg-muted/30 px-3 text-xs text-muted-foreground">
                  {t('settings.advanced.captureModeHint')}
                </div>
              </div>
              <div>
                <Label className="text-xs">{t('settings.advanced.stopMode')}</Label>
                <Select value={cfg?.stop_mode ?? 'error'} onValueChange={(v) => save({ stop_mode: v as ShieldConfig['stop_mode'] }, t('settings.toast.stopModeUpdated'))}>
                  <SelectTrigger className="mt-1 h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="error">{t('settings.advanced.stopMode.error')}</SelectItem>
                    <SelectItem value="passthrough">{t('settings.advanced.stopMode.passthrough')}</SelectItem>
                    <SelectItem value="block">{t('settings.advanced.stopMode.block')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          {/* 开关按功能分类：代理行为 / 日志与隐私 / 系统 */}
          <div className="grid gap-3 lg:grid-cols-3">
            {/* 代理行为 */}
            <div className="rounded-lg border bg-muted/20 p-3">
              <div className="mb-2 text-xs font-semibold text-muted-foreground">{t('settings.advanced.proxyBehavior')}</div>
              <div className="space-y-2">
                {([
                  ['filter_enabled', t('settings.sw.filterEnabled'), t('settings.sw.filterEnabledDesc')],
                  ['fail_closed', t('settings.sw.failClosed'), t('settings.sw.failClosedDesc')],
                  ['response_scan', t('settings.sw.responseScan'), t('settings.sw.responseScanDesc')],
                  ['auto_start_proxy', t('settings.sw.autoStart'), t('settings.sw.autoStartDesc')],
                ] as [string, string, string][]).map(([k, label, desc]) => (
                  <SettingToggle key={k} label={label} desc={desc} checked={!!(cfg as Record<string, unknown> | undefined)?.[k]} onChange={(v) => toggle(k, v)} />
                ))}
              </div>
            </div>
            {/* 日志与隐私 */}
            <div className="rounded-lg border bg-muted/20 p-3">
              <div className="mb-2 text-xs font-semibold text-muted-foreground">{t('settings.advanced.logPrivacy')}</div>
              <div className="space-y-2">
                {([
                  ['record_plaintext_words', t('settings.sw.recordPlaintext'), t('settings.sw.recordPlaintextDesc')],
                  ['debug', t('settings.sw.debug'), t('settings.sw.debugDesc')],
                  ['start_minimized', t('settings.sw.startMinimized'), t('settings.sw.startMinimizedDesc')],
                ] as [string, string, string][]).map(([k, label, desc]) => (
                  <SettingToggle key={k} label={label} desc={desc} checked={!!(cfg as Record<string, unknown> | undefined)?.[k]} onChange={(v) => toggle(k, v)} />
                ))}
              </div>
            </div>
            {/* 系统 */}
            <div className="rounded-lg border bg-muted/20 p-3">
              <div className="mb-2 text-xs font-semibold text-muted-foreground">{t('settings.advanced.system')}</div>
              <div className="space-y-2">
                {/* 界面语言切换（i18n） */}
                <div className="flex items-center justify-between gap-2 rounded-lg border bg-card/60 px-3 py-2.5">
                  <span className="text-[13px]">{t('settings.language')}</span>
                  <Select value={lang} onValueChange={(v) => setLang(v as 'zh' | 'en')}>
                    <SelectTrigger className="h-7 w-28 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="zh">{t('settings.language.zh')}</SelectItem>
                      <SelectItem value="en">{t('settings.language.en')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <SettingToggle label={t('settings.advanced.autostart')} desc={t('settings.advanced.autostartDesc')} checked={!!cfg?.autostart} onChange={async (v) => {
                  if (isTauri()) {
                    try {
                      await setAutostartTauri(v)
                      toast(v ? t('settings.toast.autostartOn') : t('settings.toast.autostartOff'))
                      queryClient.invalidateQueries({ queryKey: ['proxyStatus'] })
                    } catch (e) {
                      toast(tf('settings.toast.autostartFail', { e: String(e) }), 'error')
                    }
                  } else {
                    toggle('autostart', v)
                  }
                }} />
                <p className="text-[11px] text-muted-foreground/80">
                  {t('settings.advanced.moreSwitchesHint')}
                </p>
              </div>
            </div>
          </div>

          <Card className="border bg-card">
            <CardHeader>
              <CardTitle className="text-sm font-semibold">{t('settings.advanced.streamExclude')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap items-center gap-2">
                {streamExclude.map((h) => (
                  <Badge key={h} variant="outline" className="font-mono">{h}</Badge>
                ))}
                <div className="flex items-center gap-1.5">
                  <Input
                    className="h-7 w-40 text-xs"
                    placeholder={t('settings.advanced.domainPh')}
                    value={newExcludeHost}
                    onChange={(e) => setNewExcludeHost(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && newExcludeHost.trim() && !streamExclude.includes(newExcludeHost.trim())) {
                        save({ stream_exclude_hosts: [...streamExclude, newExcludeHost.trim()] }, t('settings.toast.added'))
                        setNewExcludeHost('')
                      }
                    }}
                  />
                  <Button size="sm" variant="ghost" className="h-6 text-[11px]" onClick={() => {
                    if (newExcludeHost.trim() && !streamExclude.includes(newExcludeHost.trim())) {
                      save({ stream_exclude_hosts: [...streamExclude, newExcludeHost.trim()] }, t('settings.toast.added'))
                      setNewExcludeHost('')
                    }
                  }}>{t('settings.advanced.hostAdd')}</Button>
                </div>
              </div>
              <p className="mt-2 text-[11px] text-muted-foreground">{t('settings.advanced.streamExcludeHint')}</p>
            </CardContent>
          </Card>

          <Card className="border bg-card">
            <CardHeader className="flex-row items-center gap-2 space-y-0">
              <Radar className="h-4 w-4 text-primary" />
              <CardTitle className="text-sm font-semibold">{t('settings.advanced.auditProbe')}</CardTitle>
              <Badge variant="outline" className="ml-auto text-[11px]">{t('settings.advanced.auditTokenBadge')}</Badge>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">
                {t('settings.advanced.auditProbeDesc')}
              </p>
              <div className="flex flex-wrap items-end gap-3">
                <div className="min-w-[160px]">
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
                    <TooltipProvider delayDuration={200}>
                      <Tooltip>
                        <TooltipTrigger asChild><HelpCircle className="h-3.5 w-3.5 cursor-help text-muted-foreground/60" /></TooltipTrigger>
                        <TooltipContent className="max-w-[280px] text-xs">{t('settings.advanced.profileTooltip')}</TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
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
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
                    <span className="text-xs font-medium">{auditJob?.phase || t('settings.advanced.auditRunning')}</span>
                    <Badge variant="outline" className="ml-auto shrink-0 font-mono text-[11px]">{auditDone}/{auditTotal}</Badge>
                  </div>
                  <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                    <div className="h-full rounded-full bg-gradient-to-r from-primary to-cyan-500 transition-[width] duration-500" style={{ width: `${auditProgress}%` }} />
                  </div>
                </div>
              )}
              {!auditRunning && auditJob?.phase && (
                <p className="text-[11px] text-muted-foreground">
                  {t('settings.advanced.lastTask')}{auditJob.phase}
                  {auditJob.error ? tf('settings.advanced.failed', { e: auditJob.error.slice(0, 120) }) : ''}
                </p>
              )}
              {auditReport && (
                <pre className="max-h-[300px] overflow-auto whitespace-pre-wrap rounded-lg bg-muted/60 p-3 font-mono text-[11px] leading-relaxed">{auditReport}</pre>
              )}
            </CardContent>
          </Card>

          <Card className="border bg-card">
            <CardHeader className="flex-row items-center gap-2 space-y-0">
              <Coins className="h-4 w-4 text-primary" />
              <CardTitle className="text-sm font-semibold">{t('settings.advanced.priceSync')}</CardTitle>
              <Badge variant="outline" className="ml-auto text-[11px]">{t('settings.advanced.priceSyncAuto')}</Badge>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">
                {t('settings.advanced.priceSyncHint')}
              </p>
              <div className="flex flex-wrap items-center gap-3">
                <label className="flex cursor-pointer select-none items-center gap-2 text-xs text-muted-foreground transition-colors hover:text-foreground">
                  <Switch
                    checked={!!cfg?.price_sync_enabled}
                    onCheckedChange={(v) => save({ price_sync_enabled: v }, v ? t('settings.toast.priceSyncOn') : t('settings.toast.priceSyncOff'))}
                  />
                  {t('settings.advanced.enableSync')}
                </label>
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  {t('settings.advanced.syncInterval')}
                  <Select value={String(cfg?.price_sync_interval_days ?? 7)} onValueChange={(v) => save({ price_sync_interval_days: Number(v) }, t('settings.toast.priceIntervalUpdated'))}>
                    <SelectTrigger className="h-7 w-28 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">{t('settings.advanced.syncInterval.1')}</SelectItem>
                      <SelectItem value="3">{t('settings.advanced.syncInterval.3')}</SelectItem>
                      <SelectItem value="7">{t('settings.advanced.syncInterval.7')}</SelectItem>
                      <SelectItem value="30">{t('settings.advanced.syncInterval.30')}</SelectItem>
                    </SelectContent>
                  </Select>
                </label>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" onClick={() => syncPricesMutation.mutate()} disabled={syncPricesMutation.isPending || priceSyncing} className="gap-1.5">
                  <RefreshCw className={cn('h-3.5 w-3.5', (syncPricesMutation.isPending || priceSyncing) && 'animate-spin')} />
                  {t('settings.advanced.syncNow')}
                </Button>
                <Button size="sm" variant="outline" className="gap-1.5" onClick={openPriceList}>
                  <List className="h-3.5 w-3.5" />{t('settings.advanced.viewPrices')}
                </Button>
                {priceSyncState && (
                  <span className="text-[11px] text-muted-foreground">
                    {priceSyncState.syncing
                      ? t('settings.advanced.syncing')
                      : priceSyncState.synced_at > 0
                        ? tf('settings.advanced.syncedAt', { time: dayjs(priceSyncState.synced_at * 1000).format('MM-DD HH:mm') })
                        : t('settings.advanced.notSynced')}
                    {priceSyncState.last_error && (
                      <span className="ml-1 text-red-500">{tf('settings.advanced.syncFailed', { e: priceSyncState.last_error.slice(0, 60) })}</span>
                    )}
                  </span>
                )}
              </div>
            </CardContent>
          </Card>

      {/* 模型价格明细弹窗：搜索 + 厂商快速筛选 + 输入/输出/缓存输入/缓存写入价 */}
      <Dialog open={priceListOpen} onOpenChange={setPriceListOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {t('settings.priceList.title')}
              <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-normal text-muted-foreground">{tf('settings.priceList.countUnit', { n: priceList?.count ?? 0 })}</span>
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-2">
            <Input
              className="h-8 text-xs"
              placeholder={t('settings.priceList.searchPh')}
              value={priceSearch}
              onChange={(e) => setPriceSearch(e.target.value)}
            />
            {/* 常用厂商快速过滤标签 */}
            <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
              {[
                { label: t('common.all'), value: '' },
                { label: 'OpenAI', value: 'openai/' },
                { label: 'Anthropic', value: 'anthropic/' },
                { label: 'Qwen', value: 'qwen/' },
                { label: 'DeepSeek', value: 'deepseek/' },
                { label: 'Google', value: 'google/' },
                { label: 'Meta', value: 'meta-llama/' },
                { label: 'Mistral', value: 'mistralai/' },
              ].map((v) => {
                const active = v.value === '' ? priceSearch === '' : priceSearch.toLowerCase() === v.value.toLowerCase()
                return (
                  <button
                    key={v.label}
                    type="button"
                    onClick={() => setPriceSearch(v.value)}
                    className={cn(
                      'rounded-full px-2.5 py-0.5 text-[11px] font-medium transition-colors',
                      active
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted/70 text-muted-foreground hover:bg-muted hover:text-foreground',
                    )}
                  >
                    {v.label}
                  </button>
                )
              })}
            </div>
          </div>
          <div className="max-h-[380px] overflow-auto rounded-lg border">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-muted/80 backdrop-blur">
                <tr className="text-muted-foreground">
                  <th className="px-3 py-2 font-medium">{t('logs.colModel')}</th>
                  <th className="px-3 py-2 text-right font-medium">{t('settings.priceList.input')}</th>
                  <th className="px-3 py-2 text-right font-medium">{t('settings.priceList.output')}</th>
                  <th className="px-3 py-2 text-right font-medium">{t('settings.priceList.cacheInput')}</th>
                  <th className="px-3 py-2 text-right font-medium">{t('settings.priceList.cacheWrite')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {(priceList?.models ?? [])
                  .filter((m) => !priceSearch || m.model.toLowerCase().includes(priceSearch.toLowerCase()))
                  .slice(0, 300)
                  .map((m) => (
                    <tr key={m.model} className="hover:bg-muted/30">
                      <td className="px-3 py-1.5 font-mono">{m.model}</td>
                      <td className="px-3 py-1.5 text-right tabular-nums">${Number(m.input ?? 0).toFixed(2)}</td>
                      <td className="px-3 py-1.5 text-right tabular-nums">${Number(m.output ?? 0).toFixed(2)}</td>
                      <td className="px-3 py-1.5 text-right tabular-nums text-muted-foreground">
                        {m.cache_read != null ? `$${Number(m.cache_read).toFixed(2)}` : '—'}
                      </td>
                      <td className="px-3 py-1.5 text-right tabular-nums text-muted-foreground">
                        {m.cache_write != null ? `$${Number(m.cache_write).toFixed(2)}` : '—'}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
            {(priceList?.models ?? []).length === 0 && (
              <div className="py-8 text-center text-sm text-muted-foreground">{t('settings.priceList.empty')}</div>
            )}
          </div>
          <DialogFooter>
            <Button size="sm" variant="outline" onClick={() => setPriceListOpen(false)}>{t('common.close')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

          <Card className="border bg-card">
            <CardHeader>
              <CardTitle className="text-sm font-semibold">{t('settings.advanced.egress')}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <label className="flex cursor-pointer select-none items-center gap-2 text-xs text-muted-foreground transition-colors hover:text-foreground">
                <Switch checked={!!cfg?.egress_proxy?.enabled} onCheckedChange={(v) => save({ egress_proxy: { ...(cfg?.egress_proxy ?? { enabled: false, url: '' }), enabled: v } })} />
                {t('settings.advanced.egressHint')}
              </label>
              {/* 非受控 + key：避免每次击键触发保存，且在外部配置刷新后同步初值。
                  key 绑定已保存值 → 保存成功/外部刷新后重新挂载同步，中途击键不打断输入也不触发存盘。 */}
              <Input
                key={cfg?.egress_proxy?.url ?? ''}
                className="h-8 max-w-md font-mono text-xs"
                defaultValue={cfg?.egress_proxy?.url ?? ''}
                placeholder={t('settings.advanced.egressPh')}
                onBlur={(e) => {
                  const v = e.target.value
                  const cur = cfg?.egress_proxy ?? { enabled: false, url: '' }
                  if (v !== cur.url) save({ egress_proxy: { ...cur, url: v } }, t('settings.toast.egressUpdated'))
                }}
              />
              <p className="text-[11px] text-muted-foreground">
                {t('settings.advanced.egressTip')}
              </p>
            </CardContent>
          </Card>

          <Card className="border bg-card">
            <CardHeader>
              <CardTitle className="text-sm font-semibold">{t('settings.advanced.sessionDiag')}</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 md:grid-cols-3">
              <div>
                <Label className="flex items-center gap-1 text-xs">{t('settings.advanced.sessionTtl')}
                  <TooltipProvider delayDuration={200}>
                    <Tooltip>
                      <TooltipTrigger asChild><HelpCircle className="h-3.5 w-3.5 cursor-help text-muted-foreground/60" /></TooltipTrigger>
                      <TooltipContent className="max-w-[280px] text-xs">{t('settings.advanced.sessionTtlTooltip')}</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </Label>
                {/* onBlur 存盘：避免把输入过程中的中间值写进配置。 */}
                <Input type="number" className="mt-1 h-8 text-xs"
                  key={cfg?.session_ttl ?? 600}
                  defaultValue={cfg?.session_ttl ?? 600}
                  onBlur={(e) => {
                    const v = Number(e.target.value) || 600
                    if (v !== (cfg?.session_ttl ?? 600)) save({ session_ttl: v }, t('settings.toast.ttlUpdated'))
                  }} />
              </div>
              <div className="[&>label]:min-h-[52px]">
                <SettingToggle label={t('settings.advanced.unmatched')} desc={t('settings.advanced.unmatchedDesc')} checked={!!cfg?.diagnostic_unmatched} onChange={(v) => save({ diagnostic_unmatched: v })} />
              </div>
              <div className="[&>label]:min-h-[52px]">
                <SettingToggle label="HTTP/2" desc={t('settings.advanced.http2Desc')} checked={cfg?.http2 !== false} onChange={(v) => save({ http2: v }, t('settings.toast.http2Saved'))} />
              </div>
            </CardContent>
          </Card>

          <Card className="border bg-card">
            <CardHeader>
              <CardTitle className="text-sm font-semibold">{t('settings.advanced.dataRetention')}</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap items-center gap-3">
              <Label className="flex items-center gap-1 text-xs">{t('settings.advanced.retentionDays')}
                <TooltipProvider delayDuration={200}>
                  <Tooltip>
                    <TooltipTrigger asChild><HelpCircle className="h-3.5 w-3.5 cursor-help text-muted-foreground/60" /></TooltipTrigger>
                    <TooltipContent className="max-w-[300px] text-xs">{t('settings.advanced.retentionTooltip')}</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </Label>
              <Input
                type="number"
                className="h-8 w-24 text-xs"
                defaultValue={cfg?.log_retention_days ?? 7}
                onBlur={(e) => {
                  const parsed = Number(e.target.value)
                  // Zero means unlimited retention; only empty/invalid input uses the default.
                  const v = e.target.value.trim() === '' || !Number.isFinite(parsed) ? 7 : parsed
                  if (v !== (cfg?.log_retention_days ?? 7)) save({ log_retention_days: v }, t('settings.toast.retentionUpdated'))
                }}
              />
              <span className="text-[11px] text-muted-foreground">{t('settings.advanced.retentionHint')}</span>
            </CardContent>
          </Card>
        </TabsContent>
        )}

        {/* ===== 工具 ===== */}
        {!embeddedTab && (
        <TabsContent value="tools" className="space-y-4">
          {/* 更新卡只放「关于」页一处：这里原本也渲染了一份，同一张卡出现在两个 tab，
              用户在哪点都行反而不知道该信哪个，版本/更新日志也会各查一次接口。 */}

          <Card className="border bg-card">
            <CardHeader>
              <CardTitle className="text-sm font-semibold">{t('settings.tools.realTest')}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-wrap items-end gap-2">
                <div className="min-w-[140px]">
                  <Label className="text-xs">{t('dash.colClient')}</Label>
                  <Select value={demoUpstream} onValueChange={setDemoUpstream}>
                    <SelectTrigger className="mt-1 h-8 text-xs"><SelectValue placeholder={t('settings.tools.chooseClient')} /></SelectTrigger>
                    <SelectContent>
                      {upstreams.map((u) => (
                        <SelectItem key={u.name} value={u.name}>{u.name} :{u.port}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="min-w-[160px] flex-1">
                  <Label className="text-xs">{t('settings.tools.apiKey')}</Label>
                  <Input className="mt-1 h-8 font-mono text-xs" type="password" value={demoApiKey} onChange={(e) => setDemoApiKey(e.target.value)} placeholder={t('settings.tools.apiKeyPh')} />
                </div>
                <div className="min-w-[150px]">
                  <Label className="text-xs">{t('logs.colModel')}</Label>
                  <Input className="mt-1 h-8 font-mono text-xs" value={demoModel} onChange={(e) => setDemoModel(e.target.value)} placeholder={t('settings.tools.modelPh')} />
                </div>
              </div>
              <Textarea
                className="min-h-20 font-mono text-xs"
                placeholder={t('settings.tools.textPh')}
                value={demoText}
                onChange={(e) => setDemoText(e.target.value)}
              />
              <div className="flex gap-2">
                <Button size="sm" className="h-8" disabled={realTesting} onClick={async () => {
                  if (!demoUpstream) { toast(t('settings.toast.chooseClient'), 'error'); return }
                  if (!demoApiKey) { toast(t('settings.toast.needApiKey'), 'error'); return }
                  const u = upstreams.find((x) => x.name === demoUpstream)
                  if (!u) return
                  setRealTesting(true)
                  try {
                    const r = await testUpstream({
                      name: u.name, port: u.port, mode: 'chat',
                      api_key: demoApiKey, model: demoModel || undefined,
                      content: demoText || undefined,
                    })
                    setDemoResult({ ok: r.ok, masked: String(r.raw_preview ?? r.message ?? r.error ?? ''), error: r.error, items: [] })
                    if (!r.ok) toast(r.error || t('settings.toast.testFailed'), 'error')
                  } catch (e) { toast(tf('settings.toast.testFail', { e: String(e) }), 'error') }
                  finally { setRealTesting(false) }
                }}>
                  {realTesting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                  {t('settings.tools.sendTest')}
                </Button>
                <Button size="sm" variant="outline" className="h-8" onClick={() => setDemoText(t('settings.tools.sampleText'))}>
                  {t('settings.tools.fillSample')}
                </Button>
              </div>
              <p className="text-[11px] text-muted-foreground">
                {t('settings.tools.hint')}
              </p>
              {demoResult && (
                <div className="space-y-2 rounded-lg border bg-muted/30 p-3 text-xs">
                  {demoResult.ok ? (
                    <>
                      <div className="font-mono text-emerald-600 dark:text-emerald-400">
                        <span className="text-muted-foreground">{t('settings.tools.upstreamResp')}</span>{demoResult.masked}
                      </div>
                    </>
                  ) : (
                    <div className="text-red-600 dark:text-red-400">{demoResult.error || demoResult.masked}</div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        )}

        {/* ===== 关于 ===== */}
        {!embeddedTab && (
        <TabsContent value="about" className="space-y-4">
          {/* 产品信息 + 在线更新（合并为一个卡片） */}
          <AboutUpdateCard version={status?.version} dataRoot={cfg?.data_root} running={status?.proxy_running} autoInstall={autoInstallUpdate} />

          {/* 更新日志 */}
          <Card className="border bg-card">
            <CardHeader>
              <CardTitle className="text-sm font-semibold">{t('about.changelog')}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {siteRelease ? (
                <>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className="bg-primary/15 text-[11px] text-primary">{tf('settings.about.latestBadge', { v: siteRelease.version })}</Badge>
                    <span className="text-[11px] text-muted-foreground">{tf('settings.about.publishedAt', { d: siteRelease.pub_date && dayjs(siteRelease.pub_date).isValid() ? dayjs(siteRelease.pub_date).format('YYYY-MM-DD') : '—' })}</span>
                    {siteRelease.version === status?.version && (
                      <span className="text-[11px] text-emerald-600 dark:text-emerald-400">{t('about.currentLatest')}</span>
                    )}
                  </div>
                  {siteRelease.notes && (
                    <p className="whitespace-pre-wrap rounded-lg bg-muted/40 p-3 text-xs leading-relaxed">{siteRelease.notes}</p>
                  )}
                  <div className="flex items-center gap-3 pt-1">
                    <p className="text-[11px] text-muted-foreground">{t('settings.about.changelogLinkHint')}</p>
                    <Button size="sm" variant="outline" className="h-7 gap-1 text-[11px]" onClick={openSiteChangelog}>
                      <ExternalLink className="h-3 w-3" />{t('settings.about.viewSiteChangelog')}
                    </Button>
                  </div>
                </>
              ) : siteReleaseErr ? (
                /* 不把原始 JS 异常（TypeError: Failed to fetch 之类）甩给用户：
                   那串文字对使用者没有任何信息量，只会显得程序坏了。断网/服务器
                   抽风是常态，说清「不影响使用」即可。 */
                <p className="text-xs text-muted-foreground">
                  {t('settings.about.changelogUnavailable')}
                </p>
              ) : (
                <p className="text-xs text-muted-foreground">{t('common.loading')}</p>
              )}
            </CardContent>
          </Card>

          {/* 个性化背景 */}
          <BackgroundCard />
        </TabsContent>
        )}

        {!embeddedTab && (
        <TabsContent value="security" className="space-y-4">
          {/* 配置备份与回滚 */}
          <ConfigBackupCard />
          {/* 控制面访问安全：Origin 校验开关（反代/CDN 回源 403 逃生舱） */}
          <Card className="border bg-card">
            <CardHeader>
              <CardTitle className="text-sm font-semibold">{t('settings.security.access')}</CardTitle>
            </CardHeader>
            <CardContent>
              <SettingToggle
                label={t('settings.security.originCheck')}
                desc={t('settings.security.originCheckDesc')}
                checked={cfg?.origin_check ?? true}
                onChange={(v) => save({ origin_check: v }, v ? t('settings.toast.originCheckOn') : t('settings.toast.originCheckOff'))}
              />
            </CardContent>
          </Card>
          {/* 证书安装：reverse 模式不需要证书，隐藏避免误操作。
              explicit/local 模式需要证书，未来如果启用这些模式再恢复此卡片 */}
          <Card className="border bg-card">
            <CardHeader>
              <CardTitle className="text-sm font-semibold">{t('settings.security.auditProbe')}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid gap-2.5 md:grid-cols-2">
                {(
                  [
                    ['enabled', t('audit.enable')],
                    ['passive', t('settings.security.audit.passive')],
                    ['active_probes', t('audit.probes')],
                    ['auto_report', t('audit.autoReport')],
                  ] as [string, string][]
                ).map(([k, label]) => (
                  <label key={k} className="flex cursor-pointer items-center justify-between rounded-lg border bg-muted/30 px-3 py-2.5">
                    <span className="text-[13px]">{label}</span>
                    <Switch checked={!!(auditCfg[k] as boolean)} onCheckedChange={(v) => save({ audit: { ...auditCfg, [k]: v } })} className="scale-75" />
                  </label>
                ))}
              </div>
              <div>
                <Label className="text-xs">{t('settings.security.signals')}</Label>
                <div className="mt-2 grid grid-cols-2 gap-2 md:grid-cols-3">
                  {Object.entries(auditSignals).map(([sig, on]) => (
                    <label key={sig} className="flex cursor-pointer items-center justify-between rounded-lg border bg-muted/30 px-3 py-2">
                      <span className="font-mono text-[11px]">{sig}</span>
                      <Switch checked={on} onCheckedChange={(v) => toggleAuditSignal(sig, v)} className="scale-75" />
                    </label>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border bg-card">
            <CardHeader>
              <CardTitle className="text-sm font-semibold">{t('settings.security.health')}</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap items-center gap-3">
              <Button size="sm" variant="outline" className="h-8" onClick={async () => {
                if (healthChecking) return
                setHealthChecking(true)
                try {
                  const h = await getHealth()
                  setHealthInfo(h)
                } catch (e) { toast(tf('settings.toast.healthFail', { e: String(e) }), 'error') } finally { setHealthChecking(false) }
              }} loading={healthChecking}>
                {t('settings.tools.healthCheck')}
              </Button>
              <Button size="sm" variant="outline" className="h-8" onClick={async () => {
                if (netRestoring) return
                setNetRestoring(true)
                try {
                  const r = await restoreNetwork()
                  toast(r.ok ? t('settings.toast.restoreDone') : tf('settings.toast.restoreManual', { d: JSON.stringify(r).slice(0, 120) }), r.ok ? 'success' : 'error')
                } catch (e) { toast(tf('settings.toast.recoverFail', { e: String(e) }), 'error') } finally { setNetRestoring(false) }
              }} loading={netRestoring}>
                {t('settings.tools.recover')}
              </Button>
              {healthInfo && (
                <pre className="w-full overflow-auto rounded-lg border bg-muted/30 p-3 font-mono text-[11px]">
                  {JSON.stringify(healthInfo, null, 2).slice(0, 1500)}
                </pre>
              )}
            </CardContent>
          </Card>

          <Card className="border bg-card">
            <CardHeader>
              <CardTitle className="text-sm font-semibold">{t('about.dataDir')}</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap items-center gap-3">
              <Button size="sm" variant="outline" className="h-8" onClick={doOpenDataDir}>
                <FolderOpen className="mr-1.5 h-3.5 w-3.5" />{t('settings.security.openDataDir')}
              </Button>
              <code className="text-[11px] text-muted-foreground">{cfg?.data_root ?? '%APPDATA%\\Maskit'}</code>
            </CardContent>
          </Card>

        </TabsContent>
        )}
      </Tabs>

      {/* 编辑弹窗 */}
      {/* 主动审计确认弹窗：消耗真实 token，需二次确认 */}
      <Dialog open={confirmAudit} onOpenChange={setConfirmAudit}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t('settings.confirm.auditTitle')}</DialogTitle>
            <DialogDescription>
              {tf('settings.confirm.auditDesc', { name: auditUpstream || t('settings.advanced.selectedUpstream') })}
            </DialogDescription>
          </DialogHeader>
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

      {/* 删除客户端确认 */}
      <Dialog open={confirmDelete !== null} onOpenChange={(v) => !v && setConfirmDelete(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t('settings.confirm.deleteTitle')}</DialogTitle>
            <DialogDescription>{tf('settings.clients.deleteConfirm', { name: String(confirmDelete ?? '') })}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button size="sm" variant="outline" onClick={() => setConfirmDelete(null)}>{t('common.cancel')}</Button>
            <Button size="sm" variant="destructive" onClick={() => confirmDelete && removeUpstream(confirmDelete)}>{t('settings.confirm.delete')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {(editing || adding) && (
        <UpstreamForm
          initial={editing ?? { name: '', port: nextPort, target: '', use_proxy: false, paths: ['/v1/chat/completions', '/v1/completions'], base_path: '' }}
          onSave={onSaveUpstream}
          onClose={() => { setEditing(null); setAdding(false) }}
          captureMode={cfg?.capture_mode ?? 'reverse'}
        />
      )}
    </div>
  )
}
