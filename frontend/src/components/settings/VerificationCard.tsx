/** Reuses the saved client list; it never edits host configuration or calls an upstream. */
import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { getVerification, startVerification, type Verification } from '@/api/onboarding'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { EventDetailDialog } from '@/components/events/EventDetailDialog'
import { useI18n } from '@/lib/i18n'
import { toast } from '@/lib/toast'

export function VerificationCard({ upstreams }: { upstreams: { name: string }[] }) {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const [selection, setSelection] = useState('proxy')
  const [busy, setBusy] = useState(false)
  const [issued, setIssued] = useState<Verification | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)
  const query = useQuery({
    queryKey: ['onboardingVerification'], queryFn: getVerification,
    refetchInterval: (q) => ['pending', 'observed'].includes(q.state.data?.status ?? '') ? 5000 : false,
  })
  const result = query.data
  const marker = issued?.id === result?.id ? issued?.marker : null
  const start = async (mode: 'marker' | 'window') => {
    setBusy(true)
    try {
      const next = await startVerification(selection === 'ext' ? 'ext' : 'proxy',
        selection.startsWith('client:') ? selection.slice(7) : '', mode)
      setIssued(next)
      queryClient.setQueryData(['onboardingVerification'], next)
    } catch (error) { toast(String(error), 'error') }
    finally { setBusy(false) }
  }

  return <Card>
    <CardHeader className="pb-3"><CardTitle className="text-base">{t('p6.verify.title')}</CardTitle></CardHeader>
    <CardContent className="space-y-3">
      <p className="text-sm text-muted-foreground">{t('p6.verify.steps')}</p>
      <Select value={selection} onValueChange={setSelection}>
        <SelectTrigger aria-label={t('p6.verify.entry')}><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="proxy">{t('p6.verify.proxy')}</SelectItem>
          <SelectItem value="ext">{t('p6.verify.ext')}</SelectItem>
          {upstreams.map((upstream) => <SelectItem key={upstream.name} value={`client:${upstream.name}`}>{upstream.name}</SelectItem>)}
        </SelectContent>
      </Select>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" loading={busy} onClick={() => start('marker')}>{t('p6.verify.start')}</Button>
        <Button size="sm" variant="outline" disabled={busy} onClick={() => start('window')}>{t('p6.verify.weakStart')}</Button>
      </div>
      <p className="text-xs text-muted-foreground">{t('p6.verify.limit')}</p>
      {query.isError ? <p role="alert" className="text-sm text-destructive">{t('p6.verify.unavailable')} {String(query.error)}</p> : result && result.status !== 'idle' && <div className="space-y-2 rounded-md border p-3" aria-live="polite">
        <p className="text-sm font-medium">{t(`p6.verify.${result.status}`)}</p>
        <p className="text-xs">{result.upstream || t(result.ingress === 'ext' ? 'p6.verify.ext' : 'p6.verify.proxy')} · {t(result.mode === 'window' ? 'p6.verify.weak' : 'p6.verify.strong')}</p>
        {result.status === 'pending' && result.mode === 'marker' && <>
          <p className="text-xs text-muted-foreground">{t(marker ? 'p6.verify.typeMarker' : 'p6.verify.lostMarker')}</p>
          {marker && <code className="block select-all break-all rounded bg-muted p-2 text-sm">{marker}</code>}
        </>}
        {result.evidence && <>
          <p className="text-xs text-muted-foreground">{new Date(result.evidence.ts * 1000).toLocaleString()} · {t('p6.verify.observedLimit')}</p>
          <Button size="sm" variant="outline" onClick={() => setDetailOpen(true)}>{t('p6.verify.detail')}</Button>
        </>}
        <p className="text-xs text-muted-foreground">{t('p6.verify.checked')} {new Date(query.dataUpdatedAt).toLocaleTimeString()}</p>
      </div>}
      <EventDetailDialog open={detailOpen} onOpenChange={setDetailOpen} seq={result?.evidence?.seq ?? null} />
    </CardContent>
  </Card>
}
