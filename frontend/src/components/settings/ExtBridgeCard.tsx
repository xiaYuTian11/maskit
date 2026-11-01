/**
 * 浏览器扩展（Browser Bridge）设置卡。
 *
 * 设计取舍：
 * - 只做「引擎侧」的开关与令牌管理；扩展侧的引擎地址/站点列表在扩展自己的设置页里，
 *   这里只做**只读展示**（面板不知道、也不该去驱动扩展的存储）。
 * - `ext_record_events` **不放在本卡片**：落库发生在引擎侧，开关放引擎一处生效、
 *   用户无需重装扩展，所以它和 `record_plaintext_words` 一起放
 *   「高级设置 → 日志与隐私」。本卡片只留一行只读指引，避免一个开关出现在两处。
 * - 旋转令牌的确认弹窗必须写明后果：轮换后扩展失效 → **直通、未脱敏**，
 *   以及磁盘备份仍含旧令牌（SPEC R5）。
 */
import { useCallback, useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Globe, Copy, RefreshCw, AlertTriangle, FileText, CheckCircle2, XCircle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Hint } from '@/components/common/Hint'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useI18n } from '@/lib/i18n'
import { toast } from '@/lib/toast'
import { getExtPing, rotateExtToken } from '@/api/ext'
import {
  checkOcrRuntimeUpdate,
  formatMiB,
  getOcrRuntime,
  installOcrRuntime,
  OCR_REASON_CODES,
  ocrProgressPercent,
  rollbackOcrRuntime,
  uninstallOcrRuntime,
} from '@/api/ocr'
import { ShieldApiError } from '@/lib/shield-fetch'
import type { ShieldConfig } from '@/types/api'

interface ExtBridgeCardProps {
  cfg?: ShieldConfig
  toggle: (key: keyof ShieldConfig, v: boolean) => void
  saving: boolean
}

/** 令牌掩码：只露首尾各 4 位，中间固定长度，避免长度侧信道。 */
function maskToken(token: string): string {
  if (!token) return ''
  if (token.length <= 10) return '•'.repeat(token.length)
  return `${token.slice(0, 4)}${'•'.repeat(12)}${token.slice(-4)}`
}

const KNOWN_OCR_REASONS: ReadonlySet<string> = new Set(OCR_REASON_CODES)

/** 从接口错误里取原因码（后端 `error` 字段）；不是已知码时返回空串。 */
function ocrReasonOf(e: unknown): string {
  const code = e instanceof ShieldApiError ? e.code || '' : ''
  return KNOWN_OCR_REASONS.has(code) ? code : ''
}

export function ExtBridgeCard({ cfg, toggle, saving }: ExtBridgeCardProps) {
  const { t, tf } = useI18n()
  const queryClient = useQueryClient()
  const [revealed, setRevealed] = useState(false)
  const [confirmRotate, setConfirmRotate] = useState(false)
  const [rotating, setRotating] = useState(false)
  // OCR 组件是"按需下载"的可选运行时：这里只做状态展示与三个动作，
  // 下载/校验/自检全部在引擎侧完成（失败即回滚，不留半装可用）。
  const [ocrBusy, setOcrBusy] = useState(false)

  const enabled = !!cfg?.ext_bridge_enabled
  const token = String(cfg?.ext_token ?? '')

  const ping = useQuery({
    queryKey: ['extPing'],
    queryFn: getExtPing,
    enabled,
    // 引擎可能没起，这里失败是正常状态，不要打日志刷屏
    retry: false,
    refetchInterval: 15000,
  })

  const ocrRt = useQuery({
    queryKey: ['ocrRuntime'],
    queryFn: getOcrRuntime,
    retry: false,
    // 安装中 1s 一次（画进度条），平时 15s
    refetchInterval: (q) => (q.state.data?.state === 'installing' ? 1000 : 15000),
  })

  const ocrState = ocrRt.data?.state || 'disabled'
  const ocrVersion = ocrRt.data?.version || ''
  const ocrReady = ocrState === 'enabled'
  const ocrInstalling = ocrState === 'installing'
  const ocrSystem = ocrRt.data?.source === 'system'
  const ocrProgress = ocrRt.data?.progress
  const ocrPercent = ocrProgressPercent(ocrProgress)
  const ocrLastError = ocrRt.data?.last_error
  const reasonText = useCallback((code: string) => (KNOWN_OCR_REASONS.has(code)
    ? t(`settings.extBridge.ocrReason_${code}`)
    : code), [t])

  // 后台安装结束（installing → 其它）时给一次结果提示
  const [wasInstalling, setWasInstalling] = useState(false)
  useEffect(() => {
    if (ocrInstalling) {
      setWasInstalling(true)
      return
    }
    if (!wasInstalling) return
    setWasInstalling(false)
    const reason = ocrLastError?.reason || ''
    if (reason) toast(tf('settings.extBridge.ocrFail', { e: reasonText(reason) }), 'error')
    else if (ocrReady) toast(t('settings.extBridge.ocrInstalled'))
  }, [ocrInstalling, wasInstalling, ocrLastError, ocrReady, reasonText, t, tf])

  const runOcrAction = useCallback(async (fn: () => Promise<unknown>, okKey: string) => {
    setOcrBusy(true)
    try {
      await fn()
      if (okKey) toast(t(okKey))
      await ocrRt.refetch()
    } catch (e) {
      const code = ocrReasonOf(e)
      toast(tf('settings.extBridge.ocrFail', { e: code ? reasonText(code) : String(e) }), 'error')
    } finally {
      setOcrBusy(false)
    }
  }, [ocrRt, reasonText, t, tf])

  const doOcrCheck = useCallback(async () => {
    setOcrBusy(true)
    try {
      const r = await checkOcrRuntimeUpdate()
      toast(r.newer
        ? tf('settings.extBridge.ocrUpdateFound', { v: r.version })
        : t('settings.extBridge.ocrUpToDate'))
    } catch (e) {
      const code = ocrReasonOf(e)
      toast(tf('settings.extBridge.ocrFail', { e: code ? reasonText(code) : String(e) }), 'error')
    } finally {
      setOcrBusy(false)
    }
  }, [reasonText, t, tf])

  // 关闭开关时收起明文，避免令牌一直挂在屏幕上
  useEffect(() => {
    if (!enabled) setRevealed(false)
  }, [enabled])

  const copyToken = useCallback(async () => {
    if (!token) return
    try {
      await navigator.clipboard.writeText(token)
      toast(t('settings.extBridge.copied'))
    } catch {
      // 非安全上下文下 clipboard 不可用：退化成提示用户手动点「显示」复制，
      // 不要静默失败（用户会以为复制成功了）。
      setRevealed(true)
      toast(t('settings.extBridge.tokenHint'))
    }
  }, [token, t])

  const doRotate = async () => {
    setRotating(true)
    try {
      await rotateExtToken()
      toast(t('settings.extBridge.rotateOk'))
      // 令牌真值在服务端，本地不自己改 cfg：让 /api/config 重新拉一遍，
      // 避免面板显示的令牌与引擎里的实际值分叉。
      await queryClient.invalidateQueries({ queryKey: ['config'] })
    } catch (e) {
      toast(tf('settings.extBridge.rotateFail', { e: String(e) }), 'error')
    } finally {
      setRotating(false)
      setConfirmRotate(false)
    }
  }

  const stats = ping.data?.stats
  const statsText = stats
    ? `mask ${stats.mask ?? 0} · restore ${stats.restore ?? 0}${ping.data?.version ? ` · v${ping.data.version}` : ''}`
    : t('settings.extBridge.fail')

  return (
    <Card className="border bg-card shadow-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm font-semibold">
          <Globe className="h-4 w-4 text-muted-foreground" />
          {t('settings.extBridge.title')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-xs leading-relaxed text-muted-foreground">{t('settings.extBridge.desc')}</p>

        {/* 总开关 */}
        <div className="flex items-center justify-between gap-3 border-b border-border px-1.5 py-2.5">
          <div className="flex min-w-0 items-center gap-1.5 text-[13px]">
            <span className="truncate font-medium">{t('settings.extBridge.enabled')}</span>
            <Hint text={t('settings.extBridge.enabledDesc')} />
          </div>
          <Switch
            checked={enabled}
            disabled={saving}
            onCheckedChange={(v) => toggle('ext_bridge_enabled', v)}
            aria-label={t('settings.extBridge.enabled')}
            className="scale-75"
          />
        </div>

        {/* 图片 / 内嵌图 OCR 脱敏（默认关，理由见引擎侧 default_config 的注释） */}
        <div className="flex items-center justify-between gap-3 border-b border-border px-1.5 py-2.5">
          <div className="flex min-w-0 items-center gap-1.5 text-[13px]">
            <span className="truncate font-medium">{t('settings.extBridge.multimodal')}</span>
            <Hint text={t('settings.extBridge.multimodalDesc')} />
          </div>
          <Switch
            checked={!!cfg?.multimodal_vision}
            disabled={saving}
            onCheckedChange={(v) => toggle('multimodal_vision', v)}
            aria-label={t('settings.extBridge.multimodal')}
            className="scale-75"
          />
        </div>

        {/* OCR 组件（可选运行时）：没有组件时上面的开关即使打开也不会生效 */}
        <div className="space-y-2 rounded-lg border bg-muted/20 p-2.5">
          <div className="flex items-center justify-between gap-2 text-[13px]">
            <span className="font-medium">{t('settings.extBridge.ocrRuntime')}</span>
            <span className={ocrReady ? 'text-success-ink' : 'text-muted-foreground'}>
              {ocrReady
                ? (ocrSystem
                  ? t('settings.extBridge.ocrStateSystem')
                  : tf('settings.extBridge.ocrStateEnabled', { v: ocrVersion }))
                : t(`settings.extBridge.ocrState_${ocrState}`)}
            </span>
          </div>
          {ocrInstalling && (
            <div className="space-y-1" aria-live="polite">
              <div
                className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={ocrPercent ?? undefined}
              >
                <div
                  className={ocrPercent === null
                    ? 'h-full w-1/3 animate-pulse rounded-full bg-primary'
                    : 'h-full rounded-full bg-primary transition-[width] duration-500'}
                  style={ocrPercent === null ? undefined : { width: `${ocrPercent}%` }}
                />
              </div>
              <p className="text-2xs text-muted-foreground">
                {t(`settings.extBridge.ocrPhase_${ocrProgress?.phase || 'manifest'}`)}
                {ocrProgress?.phase === 'download' && ocrProgress.bytes > 0 && (
                  <span className="ml-1 tabular-nums">
                    {ocrProgress.total > 0
                      ? `${formatMiB(ocrProgress.bytes)} / ${formatMiB(ocrProgress.total)} MB`
                      : `${formatMiB(ocrProgress.bytes)} MB`}
                  </span>
                )}
              </p>
            </div>
          )}
          <p className="text-2xs leading-snug text-muted-foreground">
            {ocrRt.data?.error
              ? tf('settings.extBridge.ocrError', { e: reasonText(ocrRt.data.error) })
              : !ocrInstalling && ocrLastError?.reason
                ? tf('settings.extBridge.ocrLastFail', { e: reasonText(ocrLastError.reason) })
                : t('settings.extBridge.ocrRuntimeHint')}
          </p>
          {ocrRt.data?.restart_required && (
            <p className="flex items-start gap-1 text-2xs leading-snug text-warning-ink">
              <AlertTriangle className="mt-px size-3 shrink-0" aria-hidden />
              {t('settings.extBridge.ocrRestartRequired')}
            </p>
          )}
          {!ocrSystem && (
          <div className="flex flex-wrap gap-1.5">
            <Button size="sm" variant="outline" disabled={ocrBusy || ocrInstalling}
              onClick={() => runOcrAction(installOcrRuntime, '')}>
              {ocrReady ? t('settings.extBridge.ocrReinstall') : t('settings.extBridge.ocrInstall')}
            </Button>
            <Button size="sm" variant="outline" disabled={ocrBusy || ocrInstalling} onClick={doOcrCheck}>
              {t('settings.extBridge.ocrCheck')}
            </Button>
            <Button size="sm" variant="outline" disabled={ocrBusy || ocrInstalling || !ocrReady}
              onClick={() => runOcrAction(rollbackOcrRuntime, 'settings.extBridge.ocrRolledBack')}>
              {t('settings.extBridge.ocrRollback')}
            </Button>
            <Button size="sm" variant="ghost"
              disabled={ocrBusy || ocrInstalling || ocrState === 'disabled'}
              onClick={() => runOcrAction(uninstallOcrRuntime, 'settings.extBridge.ocrUninstalled')}>
              {t('settings.extBridge.ocrUninstall')}
            </Button>
          </div>
          )}
        </div>

        {/* 令牌 */}
        <div className="space-y-2">
          <div className="text-[13px] font-medium">{t('settings.extBridge.token')}</div>
          <div className="flex items-center gap-2">
            <code className="min-w-0 flex-1 truncate rounded-md border bg-muted/30 px-2 py-1.5 font-mono text-xs">
              {token
                ? revealed
                  ? token
                  : maskToken(token)
                : t('settings.extBridge.tokenEmpty')}
            </code>
            <Button
              size="sm"
              variant="outline"
              className="shrink-0"
              disabled={!token}
              title={t('settings.extBridge.copy')}
              onClick={copyToken}
            >
              <Copy className="mr-1 h-3.5 w-3.5" />
              {t('settings.extBridge.copy')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="shrink-0"
              disabled={!token}
              onClick={() => setRevealed((v) => !v)}
            >
              {revealed ? t('settings.extBridge.mask') : t('settings.extBridge.reveal')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="shrink-0"
              disabled={!token || saving || rotating}
              onClick={() => setConfirmRotate(true)}
            >
              <RefreshCw className="mr-1 h-3.5 w-3.5" />
              {t('settings.extBridge.rotate')}
            </Button>
          </div>
          <p className="text-2xs leading-relaxed text-muted-foreground">
            {t('settings.extBridge.tokenHint')}
          </p>
        </div>

        {/* 引擎不可达时的行为 */}
        <div className="flex items-center justify-between gap-3 border-b border-border px-1.5 py-2.5">
          <div className="flex min-w-0 items-center gap-1.5 text-[13px]">
            <span className="truncate font-medium">{t('settings.extBridge.blockWhenDown')}</span>
            <Hint text={t('settings.extBridge.blockWhenDownDesc')} />
          </div>
          <Switch
            checked={!!cfg?.ext_block_when_engine_down}
            disabled={saving}
            onCheckedChange={(v) => toggle('ext_block_when_engine_down', v)}
            aria-label={t('settings.extBridge.blockWhenDown')}
            className="scale-75"
          />
        </div>

        {/* 老版 Office 文档自动转码脱敏 */}
        <div className="flex items-center justify-between gap-3 border-b border-border px-1.5 py-2.5">
          <div className="flex min-w-0 items-center gap-1.5 text-[13px]">
            <span className="truncate font-medium">{t('settings.extBridge.convertLegacyOffice')}</span>
            {/* 风险已在标题里写明（「有损重建，不推荐」），不再额外挂 badge 重复；
                具体丢什么、乱码怎么来的放 ? 里。 */}
            <Hint text={t('settings.extBridge.convertLegacyOfficeDesc')} />
          </div>
          <Switch
            checked={!!cfg?.ext_convert_legacy_office}
            disabled={saving || !enabled}
            onCheckedChange={(v) => toggle('ext_convert_legacy_office', v)}
            aria-label={t('settings.extBridge.convertLegacyOffice')}
            className="scale-75"
          />
        </div>

        {/* 格式支持与不支持说明备注 */}
        {/* 中性底：整站只有异常与告警才上色，信息块不该带强调色 */}
        <div className="rounded-lg border bg-muted/30 p-3 space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
            <FileText className="h-3.5 w-3.5 text-muted-foreground" />
            {t('settings.extBridge.formatsTitle')}
          </div>
          <div className="space-y-1.5 text-2xs leading-relaxed">
            <div className="flex items-start gap-1.5 text-success-ink">
              <CheckCircle2 className="h-3.5 w-3.5 shrink-0 mt-0.5" />
              <span>{t('settings.extBridge.supportedFormats')}</span>
            </div>
            <div className="flex items-start gap-1.5 text-muted-foreground">
              <XCircle className="h-3.5 w-3.5 shrink-0 mt-0.5 text-warning-ink" />
              <span>{t('settings.extBridge.unsupportedFormats')}</span>
            </div>
          </div>
        </div>

        {/* 只读信息：引擎地址 + 统计 */}
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded-lg border bg-muted/30 px-3 py-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1 text-2xs font-medium text-muted-foreground">
                {t('settings.extBridge.panelUrl')}
                <Hint text={t('settings.extBridge.panelUrlHint')} />
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="h-5 px-1.5 text-2xs text-muted-foreground hover:text-foreground"
                onClick={async () => {
                  const isTauri = typeof window !== 'undefined' && (window.location.origin.includes('tauri.localhost') || window.location.protocol === 'tauri:')
                  const targetUrl = isTauri ? 'http://127.0.0.1:5801' : window.location.origin
                  await navigator.clipboard.writeText(targetUrl)
                  toast(t('settings.extBridge.copied'))
                }}
              >
                <Copy className="mr-1 h-3 w-3" />
                {t('settings.extBridge.copy')}
              </Button>
            </div>
            <div className="mt-0.5 break-all font-mono text-xs font-semibold text-foreground">
              {typeof window !== 'undefined' && (window.location.origin.includes('tauri.localhost') || window.location.protocol === 'tauri:')
                ? 'http://127.0.0.1:5801'
                : window.location.origin}
            </div>
          </div>
          <div className="rounded-lg border bg-muted/20 px-3 py-2">
            <div className="flex items-center gap-1 text-2xs font-medium text-muted-foreground">
              {t('settings.extBridge.stats')}
              <Hint text={t('settings.extBridge.statsHint')} />
            </div>
            <div className="mt-0.5 font-mono text-xs font-semibold text-foreground">{statsText}</div>
          </div>
        </div>
      </CardContent>

      {/* 旋转确认：后果必须写清（SPEC R5） */}
      <Dialog open={confirmRotate} onOpenChange={(v) => !v && setConfirmRotate(false)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive-ink">
              <AlertTriangle className="h-4 w-4" />
              {t('settings.extBridge.rotateConfirmTitle')}
            </DialogTitle>
            <DialogDescription className="pt-2 text-sm leading-relaxed text-foreground">
              {t('settings.extBridge.rotateConfirmDesc')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button variant="outline" onClick={() => setConfirmRotate(false)} disabled={rotating}>
              {t('common.cancel')}
            </Button>
            <Button variant="destructive" onClick={doRotate} disabled={rotating}>
              {t('settings.extBridge.rotate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
