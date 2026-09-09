/**
 * 反馈与诊断卡片。
 *
 * 为什么要有这个：用户报障时需要一份可核对的本地诊断包。崩溃现场、端口占用、错误事件
 * 本来就写在数据目录里，但用户不知道它们存在，报障时只剩一句「用不了」，
 * 来回问十轮才定位。
 *
 * 交互红线：
 * - **必须先看得见再发得出去**。诊断包虽然全程打码，但用户有权知道自己发的是什么，
 *   所以「预览」是主按钮，不是折叠在角落的次要入口。
 * - **绝不自动上报**。隐私政策承诺「原文永不离开设备」，任何自动外发都会破坏这个承诺，
 *   哪怕内容是脱敏的——用户没点过同意就发东西出去，性质是一样的。
 */
import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Bug, Copy, ExternalLink, FolderOpen, MessageSquare, ShieldCheck, Check } from 'lucide-react'
import { getDiagnostics, saveDiagnostics, type DiagnosticsBundle } from '@/api/diagnostics'
import { openDataDir } from '@/api/settings'
import { shieldFetch } from '@/lib/shield-fetch'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { toast } from '@/lib/toast'
import { useI18n } from '@/lib/i18n'

const FEEDBACK_URL = 'https://github.com/xiaYuTian11/maskit/issues'

export function FeedbackCard() {
  const [preview, setPreview] = useState<DiagnosticsBundle | null>(null)
  const [savedPath, setSavedPath] = useState('')

  const { t, tf } = useI18n()
  const gen = useMutation({
    mutationFn: getDiagnostics,
    onSuccess: (d) => setPreview(d),
    onError: (e: Error) => toast(tf('fb.genFail', { e: e.message }), 'error'),
  })

  const save = useMutation({
    mutationFn: saveDiagnostics,
    onSuccess: (r) => {
      if (r.ok && r.path) {
        setSavedPath(r.path)
        toast(t('fb.savedPath'))
      } else {
        toast(r.error || t('fb.saveFail'), 'error')
      }
    },
    onError: (e: Error) => toast(tf('fb.saveFail', { e: e.message }), 'error'),
  })

  const openFeedback = async () => {
    try {
      await shieldFetch('/api/open-url', {
        method: 'POST',
        body: JSON.stringify({ url: FEEDBACK_URL }),
      })
    } catch {
      toast(t('fb.openFail'), 'error')
    }
  }

  const [copied, setCopied] = useState(false)
  const copyPreview = async () => {
    if (!preview) return
    const text = JSON.stringify(preview, null, 2)
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
      toast(t('fb.copyOk'))
    } catch {
      toast(t('fb.copyFail'), 'error')
    }
  }

  const errCount = preview?.recent_error_count ?? 0

  return (
    <Card className="border bg-card">
      <CardHeader className="flex-row items-center gap-2 space-y-0">
        <MessageSquare className="h-4 w-4 text-muted-foreground" />
        <CardTitle className="text-sm font-semibold">{t('fb.title')}</CardTitle>
      </CardHeader>

      <CardContent className="space-y-3">
        <p className="text-[12px] leading-relaxed text-muted-foreground">
          {t('fb.desc1')}
        </p>

        {/* 隐私说明放在按钮上方而不是折叠起来：用户要发东西出去，
            有权在点击之前就知道里面是什么 */}
        <div className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2">
          <p className="flex items-start gap-1.5 text-[11px] leading-relaxed text-emerald-700 dark:text-emerald-300">
            <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>
              {t('fb.privacy')}
            </span>
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" className="h-8 gap-1.5" onClick={() => gen.mutate()} disabled={gen.isPending} loading={gen.isPending}>
            {!gen.isPending && <Bug className="h-3.5 w-3.5" />}
            {t('fb.genPreview')}
          </Button>
          <Button size="sm" variant="outline" className="h-8 gap-1.5" onClick={() => save.mutate()} disabled={save.isPending} loading={save.isPending}>
            {t('fb.saveFile')}
          </Button>
          <Button size="sm" variant="ghost" className="h-8 gap-1.5 text-xs" onClick={openFeedback}>
            {t('fb.goPage')} <ExternalLink className="h-3 w-3" />
          </Button>
        </div>

        {savedPath && (
          <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/30 px-3 py-2">
            <span className="break-all font-mono text-[11px] text-muted-foreground">{savedPath}</span>
            <Button size="sm" variant="ghost" className="ml-auto h-7 gap-1.5 text-[11px]" onClick={() => openDataDir()}>
              <FolderOpen className="h-3 w-3" /> {t('fb.openFolder')}
            </Button>
          </div>
        )}
      </CardContent>

      {/* 预览：全文可滚动。故意不做「摘要视图」——摘要等于替用户决定他该看什么 */}
      <Dialog open={!!preview} onOpenChange={(o) => !o && setPreview(null)}>
        <DialogContent className="flex max-h-[80vh] max-w-3xl flex-col">
          <DialogHeader>
            <DialogTitle>{t('fb.dialogTitle')}</DialogTitle>
            <DialogDescription>
              {tf('fb.dialogDesc', { n: errCount })}
            </DialogDescription>
          </DialogHeader>
          <pre className="flex-1 overflow-auto rounded-lg bg-muted/40 p-3 font-mono text-[11px] leading-relaxed">
            {preview ? JSON.stringify(preview, null, 2) : ''}
          </pre>
          <DialogFooter>
            <Button size="sm" variant="outline" className="gap-1.5" onClick={copyPreview} disabled={save.isPending}>
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
              {copied ? t('detail.copied') : t('fb.copyAll')}
            </Button>
            <Button size="sm" className="gap-1.5" onClick={() => { save.mutate(); setPreview(null) }} loading={save.isPending}>
              {t('fb.saveFile')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
