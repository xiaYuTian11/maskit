import { useState } from 'react'
import { BookOpen, CircleHelp, ExternalLink, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useI18n } from '@/lib/i18n'
import { shieldFetch } from '@/lib/shield-fetch'

const TUTORIAL_URL = 'https://github.com/xiaYuTian11/maskit/blob/master/docs/TUTORIAL.md'
const SETTINGS_DOC_URL = 'https://github.com/xiaYuTian11/maskit/blob/master/docs/SETTINGS.md'

/** i18n key 必须写成字面量：`t(`help.page.${x}.title`)` 这种拼接形态
 *  `scripts/check-i18n.mjs` 扫不到，key 漏了或拼错只会静默显示裸 key。 */
const PAGES = [
  { titleKey: 'help.page.dashboard.title', descKey: 'help.page.dashboard.description' },
  { titleKey: 'help.page.logs.title', descKey: 'help.page.logs.description' },
  { titleKey: 'help.page.stats.title', descKey: 'help.page.stats.description' },
  { titleKey: 'help.page.clients.title', descKey: 'help.page.clients.description' },
  { titleKey: 'help.page.extension.title', descKey: 'help.page.extension.description' },
  { titleKey: 'help.page.words.title', descKey: 'help.page.words.description' },
  { titleKey: 'help.page.audit.title', descKey: 'help.page.audit.description' },
  { titleKey: 'help.page.settings.title', descKey: 'help.page.settings.description' },
]

/** 常驻帮助入口：提供页面导览、核心使用路径和完整教程入口。 */
export function HelpCenter({ onRestartTour }: { onRestartTour: () => void }) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)

  const openDoc = async (url: string) => {
    try {
      const response = await shieldFetch('/api/open-url', {
        method: 'POST',
        body: JSON.stringify({ url }),
      })
      if (!(response as { ok?: boolean })?.ok) window.open(url, '_blank', 'noopener,noreferrer')
    } catch {
      window.open(url, '_blank', 'noopener,noreferrer')
    }
  }

  return (
    <>
      <Button
        size="sm"
        variant="ghost"
        onClick={() => setOpen(true)}
        title={t('help.open')}
        aria-label={t('help.open')}
        className="h-8 gap-1.5 px-2 text-xs text-muted-foreground hover:text-foreground"
      >
        <CircleHelp className="h-4 w-4" />
        <span className="hidden md:inline">{t('help.open')}</span>
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><BookOpen className="h-5 w-5 text-primary" />{t('help.title')}</DialogTitle>
            <DialogDescription>{t('help.description')}</DialogDescription>
          </DialogHeader>
          <div className="max-h-[65vh] space-y-5 overflow-y-auto pr-1">
            <section>
              <h3 className="text-sm font-semibold">{t('help.quickTitle')}</h3>
              <ol className="mt-2 list-decimal space-y-2 pl-5 text-sm leading-6 text-muted-foreground">
                <li>{t('help.quick1')}</li>
                <li>{t('help.quick2')}</li>
                <li>{t('help.quick3')}</li>
              </ol>
            </section>
            <section>
              <h3 className="text-sm font-semibold">{t('help.pagesTitle')}</h3>
              <dl className="mt-2 grid gap-2 sm:grid-cols-2">
                {PAGES.map((page) => (
                  <div key={page.titleKey} className="rounded-lg border bg-muted/20 p-2.5">
                    <dt className="text-xs font-semibold">{t(page.titleKey)}</dt>
                    <dd className="mt-1 text-xs leading-5 text-muted-foreground">{t(page.descKey)}</dd>
                  </div>
                ))}
              </dl>
            </section>
            <section>
              <h3 className="text-sm font-semibold">{t('help.faqTitle')}</h3>
              <div className="mt-2 space-y-3 text-sm">
                <div><p className="font-medium">{t('help.faq1.q')}</p><p className="mt-1 text-muted-foreground">{t('help.faq1.a')}</p></div>
                <div><p className="font-medium">{t('help.faq2.q')}</p><p className="mt-1 text-muted-foreground">{t('help.faq2.a')}</p></div>
                <div><p className="font-medium">{t('help.faq3.q')}</p><p className="mt-1 text-muted-foreground">{t('help.faq3.a')}</p></div>
              </div>
            </section>
          </div>
          <div className="flex flex-wrap justify-between gap-2 border-t pt-4">
            <Button variant="outline" size="sm" onClick={() => { setOpen(false); onRestartTour() }}>
              <RotateCcw className="mr-1.5 h-3.5 w-3.5" />{t('help.restartTour')}
            </Button>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={() => { void openDoc(SETTINGS_DOC_URL) }}>
                {t('help.settingsDoc')}<ExternalLink className="ml-1.5 h-3.5 w-3.5" />
              </Button>
              <Button size="sm" onClick={() => { void openDoc(TUTORIAL_URL) }}>
                {t('help.fullManual')}<ExternalLink className="ml-1.5 h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
