/**
 * 关于 / 在线更新卡片。
 *
 * 交互原则：
 * - 检查失败（断网、服务器挂）不弹错误框打断人，只在卡片内显示一行灰字。
 *   更新是锦上添花，不该让它变成打扰。
 * - 下载期间必须有进度：45MB 的包在慢网上要几分钟，没反馈用户会以为卡死然后强杀，
 *   而强杀正好发生在 NSIS 替换文件的窗口期就会把安装装坏。
 * - 版本号从引擎 /api/status 取真实值，不写死在前端（写死必然和实际产物脱节）。
 */
import { useEffect, useRef, useState } from 'react'
import { Download, RefreshCw, CheckCircle2, Loader2, Shield, Terminal, ExternalLink, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { toast } from '@/lib/toast'
import { useI18n } from '@/lib/i18n'
import { isTauri } from '@/lib/shield-fetch'
import { cn } from '@/lib/utils'
import { checkUpdate, installUpdate, onUpdateProgress, type UpdateCheck } from '@/lib/tauri'
import { Logo } from '@/components/brand/Logo'
import dayjs from 'dayjs'

function fmtMB(n: number): string {
  return (n / 1024 / 1024).toFixed(1) + ' MB'
}

export function AboutUpdateCard({ version, dataRoot, running, autoInstall }: { version?: string; dataRoot?: string; running?: boolean; autoInstall?: boolean }) {
  const { t, tf } = useI18n()
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState<UpdateCheck | null>(null)
  const [installing, setInstalling] = useState(false)
  const [progress, setProgress] = useState<{ got: number; total: number | null } | null>(null)
  const unlistenRef = useRef<(() => void) | null>(null)
  const autoInstallStarted = useRef(false)

  useEffect(() => {
    return () => {
      unlistenRef.current?.()
    }
  }, [])

  // 顶栏点「更新到 vX」时带 autoInstall=true 跳进来：自动检查 + 发现有新版即开始下载
  useEffect(() => {
    if (!autoInstall || autoInstallStarted.current) return
    autoInstallStarted.current = true
    ;(async () => { await doCheck(); })()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoInstall])

  const doCheck = async () => {
    setChecking(true)
    setResult(null)
    try {
      const r = await checkUpdate(version)
      setResult(r)
      if (r.ok && !r.has_update) toast(t('about.upToDate'))
      // 顶栏「更新到 vX」跳进来时，桌面端检查到有新版就自动开始下载安装
      if (r.ok && r.has_update && autoInstall && isTauri()) {
        setTimeout(() => doInstall(), 300)
      }
      // r.ok === false 只在卡片里显示，不弹 toast：网络不好不是用户的错
    } catch (e) {
      setResult({ ok: false, has_update: false, error: String(e) })
    } finally {
      setChecking(false)
    }
  }

  const doInstall = async () => {
    setInstalling(true)
    setProgress({ got: 0, total: null })
    try {
      unlistenRef.current = await onUpdateProgress((p) => {
        if (p.event === 'started') setProgress({ got: 0, total: null })
        if (p.event === 'progress') setProgress((s) => ({
          // downloaded 累计值单调递增，取 max 防止事件乱序导致进度回退
          got: Math.max(s?.got ?? 0, p.downloaded ?? 0),
          total: p.total ?? s?.total ?? null,
        }))
        if (p.event === 'finished') setProgress((s) => (s ? { ...s, got: s.total ?? s.got } : s))
      })
      // 安装完成后应用会自动重启，这个 Promise 通常不会 resolve
      await installUpdate()
    } catch (e) {
      setInstalling(false)
      setProgress(null)
      toast(tf('about.checkFail', { e: String(e) }), 'error')
    }
  }

  const pct = progress?.total && progress.total > 0 ? Math.min(100, Math.round(((progress.got || 0) / progress.total) * 100)) : null

  return (
    <Card className="border bg-card">
      <CardHeader className="flex-row items-center gap-3 space-y-0">
        <Logo className="h-10 w-10 shrink-0" />
        <div className="min-w-0">
          <CardTitle className="flex items-center gap-2 text-base">Data Maskit <Badge variant="outline" className="font-mono text-xs">v{version || '—'}</Badge></CardTitle>
          <p className="mt-0.5 text-[11px] text-muted-foreground">{t('about.subtitle')}</p>
          {dataRoot && <p className="mt-0.5 truncate text-[11px] text-muted-foreground">{dataRoot}</p>}
        </div>
        {running != null && (
          <Badge variant="outline" className={cn('ml-auto shrink-0 text-xs', running ? 'border-emerald-500/30 text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground')}>
            <Shield className="mr-1 h-3 w-3" />
            {running ? t('common.running') : t('common.stopped')}
          </Badge>
        )}
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">{t('about.currentVersion')}</span>
          <code className="font-mono text-foreground">v{version || '—'}</code>
        </div>

        {installing ? (
          <div className="space-y-2 rounded-lg border bg-muted/30 p-3">
            <div className="flex items-center gap-2 text-xs">
              <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
              <span>{tf('about.downloading', { v: result?.version ?? '' })}</span>
              <span className="ml-auto font-mono tabular-nums text-muted-foreground">
                {progress ? fmtMB(progress.got) : ''}
                {progress?.total ? ` / ${fmtMB(progress.total)}` : ''}
              </span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
              {/* 总大小未知时用**不确定态动画**，不能给个静态宽度。
                  总大小未知时不能伪造固定百分比；不确定态应使用独立动画，避免误导进度。 */}
              {pct != null ? (
                <div
                  className="h-full rounded-full bg-primary transition-[width] duration-300"
                  style={{ width: `${pct}%` }}
                />
              ) : (
                <div className="h-full w-1/3 animate-[indeterminate_1.2s_ease-in-out_infinite] rounded-full bg-primary" />
              )}
            </div>
            <p className="text-[11px] text-muted-foreground">
              {t('about.autoInstallHint')}
            </p>
          </div>
        ) : result?.has_update ? (
          <div className="space-y-2 rounded-lg border border-primary/40 bg-primary/5 p-3">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Download className="h-3.5 w-3.5 text-primary" />
              <span className="font-semibold">{tf('about.newVersion', { v: result.version ?? '' })}</span>
              {result.pub_date && dayjs(result.pub_date).isValid() && (
                <span className="text-muted-foreground">
                  {dayjs(result.pub_date).format('YYYY-MM-DD')}
                </span>
              )}
            </div>
            {result.notes && (
              <p className="whitespace-pre-wrap text-[11px] leading-relaxed text-muted-foreground">{result.notes}</p>
            )}
            {isTauri() ? (
              <Button size="sm" className="h-8" onClick={doInstall}>
                <Download className="mr-1.5 h-3.5 w-3.5" /> {t('about.downloadInstall')}
              </Button>
            ) : (
              <div className="space-y-2.5 border-t border-border/50 pt-2.5">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
                  <Terminal className="h-3.5 w-3.5 text-primary" />
                  <span>{t('about.dockerUpdateTitle')}</span>
                </div>
                <div className="space-y-1.5 rounded-md bg-muted/60 p-2.5 font-mono text-[11px] text-foreground select-all">
                  <div className="text-[10px] text-muted-foreground"># Docker Compose:</div>
                  <div>docker compose pull && docker compose up -d</div>
                  <div className="mt-1.5 text-[10px] text-muted-foreground"># Docker CLI:</div>
                  <div>docker pull ghcr.io/xiayutian11/maskit:latest</div>
                </div>
                <div className="flex items-start gap-1.5 rounded-md border border-amber-500/20 bg-amber-500/10 p-2 text-[11px] text-amber-600 dark:text-amber-400">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>{t('about.dockerPersistWarning')}</span>
                </div>
                {result.version && (
                  <a
                    href={`https://github.com/xiaYuTian11/maskit/releases/tag/${result.version}`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                  >
                    <span>{t('about.dockerReleaseLink')}</span>
                    <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </div>
            )}
          </div>
        ) : result?.ok && !result.has_update ? (
          <p className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="h-3.5 w-3.5" /> {t('about.upToDate')}
          </p>
        ) : result && !result.ok ? (
          <p className="text-xs text-muted-foreground">
            {tf('about.checkFail', { e: result.error || t('about.networkUnreachable') })}
          </p>
        ) : null}

        {!installing && (
          <Button size="sm" variant="outline" className="h-8" onClick={doCheck} disabled={checking}>
            {checking ? (
              <><Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> {t('about.checking')}</>
            ) : (
              <><RefreshCw className="mr-1.5 h-3.5 w-3.5" /> {t('about.check')}</>
            )}
          </Button>
        )}
      </CardContent>
    </Card>
  )
}
