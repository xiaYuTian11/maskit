/**
 * 图片与文档脱敏（视觉脱敏）设置卡。
 *
 * 为什么从「浏览器扩展」卡里拆出来（2026-11-01 用户反馈）：
 * `multimodal_vision` 是**引擎级全局能力**——代理链路的截图、扩展上传的图片、
 * Office 内嵌图、PDF 页面全走同一条视觉脱敏管线，不是扩展专属功能。此前它随
 * 扩展图片链路一起开发落在了 ExtBridgeCard（且只在扩展内嵌设置页可见），不用
 * 扩展的用户在主设置页根本找不到这个开关。
 *
 * 组件管理：OCR 组件是"按需下载"的可选运行时，这里只做状态展示与四个动作
 * （安装/检查更新/回滚/卸载），下载/校验/自检全部在引擎侧完成（失败即回滚，
 * 不留半装可用）。
 */
import { useCallback, useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ScanText } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Hint } from '@/components/common/Hint'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { useI18n } from '@/lib/i18n'
import { toast } from '@/lib/toast'
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

interface VisualMaskingCardProps {
  cfg?: ShieldConfig
  toggle: (key: keyof ShieldConfig, v: boolean) => void
  saving: boolean
}

const KNOWN_OCR_REASONS: ReadonlySet<string> = new Set(OCR_REASON_CODES)

/** 从接口错误里取原因码（后端 `error` 字段）；不是已知码时返回空串。 */
function ocrReasonOf(e: unknown): string {
  const code = e instanceof ShieldApiError ? e.code || '' : ''
  return KNOWN_OCR_REASONS.has(code) ? code : ''
}

export function VisualMaskingCard({ cfg, toggle, saving }: VisualMaskingCardProps) {
  const { t, tf } = useI18n()
  const [ocrBusy, setOcrBusy] = useState(false)

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
    ? t(`settings.visual.ocrReason_${code}`)
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
    if (reason) toast(tf('settings.visual.ocrFail', { e: reasonText(reason) }), 'error')
    else if (ocrReady) toast(t('settings.visual.ocrInstalled'))
  }, [ocrInstalling, wasInstalling, ocrLastError, ocrReady, reasonText, t, tf])

  const runOcrAction = useCallback(async (fn: () => Promise<unknown>, okKey: string) => {
    setOcrBusy(true)
    try {
      await fn()
      if (okKey) toast(t(okKey))
      await ocrRt.refetch()
    } catch (e) {
      const code = ocrReasonOf(e)
      toast(tf('settings.visual.ocrFail', { e: code ? reasonText(code) : String(e) }), 'error')
    } finally {
      setOcrBusy(false)
    }
  }, [ocrRt, reasonText, t, tf])

  const doOcrCheck = useCallback(async () => {
    setOcrBusy(true)
    try {
      const r = await checkOcrRuntimeUpdate()
      toast(r.newer
        ? tf('settings.visual.ocrUpdateFound', { v: r.version })
        : t('settings.visual.ocrUpToDate'))
    } catch (e) {
      const code = ocrReasonOf(e)
      toast(tf('settings.visual.ocrFail', { e: code ? reasonText(code) : String(e) }), 'error')
    } finally {
      setOcrBusy(false)
    }
  }, [reasonText, t, tf])

  return (
    <Card className="border bg-card shadow-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm font-semibold">
          <ScanText className="h-4 w-4 text-muted-foreground" />
          {t('settings.visual.title')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* 图片 / 文档 / PDF 内嵌文字脱敏（默认关，理由见引擎侧 default_config 的注释） */}
        <div className="flex items-center justify-between gap-3 border-b border-border px-1.5 py-2.5">
          <div className="flex min-w-0 items-center gap-1.5 text-[13px]">
            <span className="truncate font-medium">{t('settings.visual.multimodal')}</span>
            <Hint text={t('settings.visual.multimodalDesc')} />
          </div>
          <Switch
            checked={!!cfg?.multimodal_vision}
            disabled={saving}
            onCheckedChange={(v) => toggle('multimodal_vision', v)}
            aria-label={t('settings.visual.multimodal')}
            className="scale-75"
          />
        </div>

        {/* OCR 组件（可选运行时）：没有组件时上面的开关即使打开也不会生效 */}
        <div className="space-y-2 rounded-lg border bg-muted/20 p-2.5">
          <div className="flex items-center justify-between gap-2 text-[13px]">
            <span className="font-medium">{t('settings.visual.ocrRuntime')}</span>
            <span className={ocrReady ? 'text-success-ink' : 'text-muted-foreground'}>
              {ocrReady
                ? (ocrSystem
                  ? t('settings.visual.ocrStateSystem')
                  : tf('settings.visual.ocrStateEnabled', { v: ocrVersion }))
                : t(`settings.visual.ocrState_${ocrState}`)}
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
                {t(`settings.visual.ocrPhase_${ocrProgress?.phase || 'manifest'}`)}
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
              ? tf('settings.visual.ocrError', { e: reasonText(ocrRt.data.error) })
              : !ocrInstalling && ocrLastError?.reason
                ? tf('settings.visual.ocrLastFail', { e: reasonText(ocrLastError.reason) })
                : t('settings.visual.ocrRuntimeHint')}
          </p>
          {ocrRt.data?.restart_required && (
            <p className="flex items-start gap-1 text-2xs leading-snug text-warning-ink">
              <AlertTriangle className="mt-px size-3 shrink-0" aria-hidden />
              {t('settings.visual.ocrRestartRequired')}
            </p>
          )}
          {!ocrSystem && (
          <div className="flex flex-wrap gap-1.5">
            <Button size="sm" variant="outline" disabled={ocrBusy || ocrInstalling}
              onClick={() => runOcrAction(installOcrRuntime, '')}>
              {ocrReady ? t('settings.visual.ocrReinstall') : t('settings.visual.ocrInstall')}
            </Button>
            <Button size="sm" variant="outline" disabled={ocrBusy || ocrInstalling} onClick={doOcrCheck}>
              {t('settings.visual.ocrCheck')}
            </Button>
            <Button size="sm" variant="outline" disabled={ocrBusy || ocrInstalling || !ocrReady}
              onClick={() => runOcrAction(rollbackOcrRuntime, 'settings.visual.ocrRolledBack')}>
              {t('settings.visual.ocrRollback')}
            </Button>
            <Button size="sm" variant="ghost"
              disabled={ocrBusy || ocrInstalling || ocrState === 'disabled'}
              onClick={() => runOcrAction(uninstallOcrRuntime, 'settings.visual.ocrUninstalled')}>
              {t('settings.visual.ocrUninstall')}
            </Button>
          </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
