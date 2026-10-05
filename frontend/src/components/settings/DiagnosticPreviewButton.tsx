/** Explicit local snapshot preview; browser downloads and desktop saves never regenerate it. */
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { previewDiagnostics, saveDiagnostics, type DiagnosticPreview, type DiagnosticsBundle } from '@/api/diagnostics'
import { isTauri } from '@/lib/shield-fetch'
import { useI18n } from '@/lib/i18n'
import { toast } from '@/lib/toast'

export function DiagnosticPreviewButton() {
  const { t, tf } = useI18n()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [preview, setPreview] = useState<DiagnosticPreview | null>(null)
  const [saved, setSaved] = useState<{ path: string; size: number } | null>(null)
  const bundle = preview ? JSON.parse(preview.body) as DiagnosticsBundle : null

  const generate = async () => {
    setBusy(true)
    setPreview(null)
    setSaved(null)
    try {
      setPreview(await previewDiagnostics())
      setOpen(true)
    } catch (error) { toast(String(error), 'error') }
    finally { setBusy(false) }
  }

  const save = async () => {
    if (!preview) return
    setBusy(true)
    try {
      if (isTauri()) {
        const result = await saveDiagnostics(preview.id)
        if (!result.ok || !result.path || result.size === undefined) throw new Error(result.error ?? t('p6.diagnostics.failed'))
        setSaved({ path: result.path, size: result.size })
      } else {
        const url = URL.createObjectURL(new Blob([preview.body], { type: 'application/json;charset=utf-8' }))
        const link = document.createElement('a')
        link.href = url
        link.download = `maskit-diagnostics-${Math.floor(preview.generated_at)}.json`
        link.click()
        setTimeout(() => URL.revokeObjectURL(url), 1000)
      }
    } catch (error) { toast(String(error), 'error') }
    finally { setBusy(false) }
  }

  return <>
    <Button size="sm" variant="outline" loading={busy} onClick={generate}>{t('p6.diagnostics.preview')}</Button>
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-h-[85vh] max-w-3xl overflow-y-auto">
        <DialogHeader><DialogTitle>{t('p6.diagnostics.preview')}</DialogTitle></DialogHeader>
        <p className="text-sm text-muted-foreground">{t('p6.diagnostics.hint')}</p>
        {bundle?.selfcheck && <p className="text-sm">{bundle.selfcheck.summary_line}</p>}
        {preview && <>
          <p className="text-xs text-muted-foreground">{new Date(preview.generated_at * 1000).toLocaleString()} · {preview.size.toLocaleString()} B · {t('p6.diagnostics.snapshot')}</p>
          <pre className="max-h-[45vh] overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/30 p-3 text-xs">{preview.body}</pre>
          <div className="flex gap-2">
            <Button size="sm" loading={busy} onClick={save}>{t(isTauri() ? 'p6.diagnostics.save' : 'p6.diagnostics.download')}</Button>
            <Button size="sm" variant="outline" disabled={busy} onClick={generate}>{t('p6.diagnostics.refresh')}</Button>
          </div>
        </>}
        {saved && <p role="status" className="break-all text-sm">{tf('p6.diagnostics.saved', { path: saved.path, size: saved.size.toLocaleString() })}</p>}
      </DialogContent>
    </Dialog>
  </>
}
