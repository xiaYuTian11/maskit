import { useEffect, useRef, useState } from 'react'
import { ArrowRight, FileLock2, ScanText, Sparkles, X } from 'lucide-react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useI18n } from '@/lib/i18n'
import {
  compareVersions,
  consumePendingSpotlight,
  getUnreadHighlights,
  latestWhatsNewVersion,
  markFeatureSeen,
  readSeenVersion,
  shouldAutoOpenWhatsNew,
  triggerFeatureSpotlight,
  WHATS_NEW_ITEMS,
  writeSeenVersion,
  type FeatureHighlight,
  type SpotlightPayload,
} from '@/lib/whatsNew'
import { ONBOARDING_STORAGE_KEY } from '@/components/onboarding/OnboardingWizard'

type WhatsNewDialogProps = {
  open?: boolean
  onOpenChange?: (open: boolean) => void
  currentVersion?: string
  firstRun?: boolean
}

function FeatureIcon({ kind }: { kind: FeatureHighlight['icon'] }) {
  if (kind === 'files') return <FileLock2 className="h-4 w-4 text-primary-ink" />
  return <ScanText className="h-4 w-4 text-primary-ink" />
}

/** 版本升级后的轻量「新功能亮点」引导窗，仅在版本跨越时自动展示一次。 */
export function WhatsNewDialog({
  open,
  onOpenChange,
  currentVersion,
  firstRun,
}: WhatsNewDialogProps) {
  const { t, tf } = useI18n()
  const navigate = useNavigate()
  const [internalOpen, setInternalOpen] = useState(false)
  const [items, setItems] = useState<FeatureHighlight[]>(WHATS_NEW_ITEMS)
  const autoCheckedRef = useRef(false)
  const isOpen = open ?? internalOpen

  useEffect(() => {
    if (autoCheckedRef.current || !currentVersion || firstRun === undefined) return
    autoCheckedRef.current = true
    const seenVersion = readSeenVersion()
    let onboardingCompleted = false
    let hasFirstSeenAt = false
    try {
      onboardingCompleted = localStorage.getItem(ONBOARDING_STORAGE_KEY) === '1'
      hasFirstSeenAt = Boolean(localStorage.getItem('maskit_first_seen_at'))
    } catch {
      // 存储不可用时不自动弹出，避免打扰
      return
    }
    const decision = shouldAutoOpenWhatsNew({
      currentVersion,
      seenVersion,
      isFirstRun: firstRun,
      onboardingCompleted,
      hasFirstSeenAt,
    })
    if (decision.seedVersion) {
      writeSeenVersion(decision.seedVersion)
      return
    }
    if (decision.open) {
      const unread = getUnreadHighlights(seenVersion)
      setItems(unread.length > 0 ? unread : WHATS_NEW_ITEMS)
      setInternalOpen(true)
    }
  }, [currentVersion, firstRun])

  useEffect(() => {
    if (open) {
      setItems(WHATS_NEW_ITEMS)
    }
  }, [open])

  const ackVersion = () => {
    const latest = latestWhatsNewVersion()
    const cleanCur = String(currentVersion || '').trim().replace(/^v/i, '')
    const target = cleanCur && compareVersions(cleanCur, latest) > 0 ? cleanCur : latest
    writeSeenVersion(target)
  }

  const close = () => {
    ackVersion()
    setInternalOpen(false)
    onOpenChange?.(false)
  }

  const visitFeature = (item: FeatureHighlight) => {
    ackVersion()
    markFeatureSeen(item.id)
    setInternalOpen(false)
    onOpenChange?.(false)
    navigate(item.route)
    triggerFeatureSpotlight({
      targetId: item.targetId,
      title: t(item.titleKey),
      desc: t(item.descKey),
    })
  }

  const displayVersion = (currentVersion || latestWhatsNewVersion()).replace(/^v/i, '')

  return (
    <Dialog open={isOpen} onOpenChange={(nextOpen) => (nextOpen ? onOpenChange?.(true) : close())}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <span className="rounded-lg bg-primary/10 p-2 text-primary-ink">
              <Sparkles className="h-5 w-5" />
            </span>
            <span>{t('whatsNew.title')}</span>
            <Badge variant="secondary" className="font-mono text-[10px]">
              v{displayVersion}
            </Badge>
          </DialogTitle>
          <DialogDescription>
            {tf('whatsNew.subtitle', { v: displayVersion })}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 py-1">
          {items.map((item) => (
            <div
              key={item.id}
              className="flex flex-col gap-3 rounded-xl border border-border/70 bg-muted/20 p-4 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="flex min-w-0 items-start gap-3">
                <span className="mt-0.5 shrink-0 rounded-lg bg-primary/10 p-2">
                  <FeatureIcon kind={item.icon} />
                </span>
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold">{t(item.titleKey)}</h3>
                    <span className="rounded bg-primary/15 px-1.5 py-px text-[9.5px] font-semibold uppercase text-primary-ink">
                      {t('whatsNew.badge')}
                    </span>
                  </div>
                  <p className="text-xs leading-5 text-muted-foreground">{t(item.descKey)}</p>
                </div>
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="shrink-0 gap-1"
                onClick={() => visitFeature(item)}
              >
                {t('whatsNew.goTo')}
                <ArrowRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          ))}
        </div>

        <DialogFooter>
          <Button size="sm" onClick={close}>
            {t('whatsNew.gotIt')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** 跨路由目标元素脉冲高亮与底部轻提示，4.5 秒或手动关闭后自动消隐。 */
export function FeatureSpotlight() {
  const { t } = useI18n()
  const location = useLocation()
  const [banner, setBanner] = useState<SpotlightPayload | null>(null)
  const activeElRef = useRef<HTMLElement | null>(null)
  const dismissTimerRef = useRef<number | null>(null)
  const pollTimerRef = useRef<number | null>(null)

  const clearSpotlight = () => {
    if (dismissTimerRef.current !== null) {
      window.clearTimeout(dismissTimerRef.current)
      dismissTimerRef.current = null
    }
    if (pollTimerRef.current !== null) {
      window.clearInterval(pollTimerRef.current)
      pollTimerRef.current = null
    }
    if (activeElRef.current) {
      activeElRef.current.classList.remove('feature-spotlight')
      activeElRef.current = null
    }
    setBanner(null)
  }

  const startLocate = (payload: SpotlightPayload) => {
    clearSpotlight()
    const deadline = Date.now() + 2500
    const tryAttach = () => {
      const el = document.querySelector<HTMLElement>(`[data-feature-id="${payload.targetId}"]`)
      if (el) {
        if (pollTimerRef.current !== null) {
          window.clearInterval(pollTimerRef.current)
          pollTimerRef.current = null
        }
        el.scrollIntoView({ behavior: 'smooth', block: 'center' })
        el.classList.add('feature-spotlight')
        activeElRef.current = el
        setBanner(payload)
        dismissTimerRef.current = window.setTimeout(clearSpotlight, 4500)
        return true
      }
      if (Date.now() >= deadline && pollTimerRef.current !== null) {
        window.clearInterval(pollTimerRef.current)
        pollTimerRef.current = null
      }
      return false
    }
    if (!tryAttach()) {
      pollTimerRef.current = window.setInterval(tryAttach, 100)
    }
  }

  useEffect(() => {
    const pending = consumePendingSpotlight()
    if (pending) startLocate(pending)
    const onEvent = (e: Event) => {
      consumePendingSpotlight()
      const detail = (e as CustomEvent<SpotlightPayload>).detail
      if (detail?.targetId) startLocate(detail)
    }
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') clearSpotlight()
    }
    window.addEventListener('maskit:spotlight', onEvent)
    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('maskit:spotlight', onEvent)
      window.removeEventListener('keydown', onKeyDown)
      clearSpotlight()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // 路由切换离开当前目标页时自动清理上一页残留的高亮样式
  useEffect(() => {
    const pending = consumePendingSpotlight()
    if (pending) {
      startLocate(pending)
    } else if (activeElRef.current && !document.body.contains(activeElRef.current)) {
      clearSpotlight()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname, location.search])

  if (!banner) return null

  return (
    <div className="pointer-events-auto fixed bottom-5 left-1/2 z-50 flex w-[min(460px,calc(100vw-2rem))] -translate-x-1/2 items-start gap-3 rounded-xl border border-primary/40 bg-background/95 p-3.5 shadow-xl backdrop-blur">
      <span className="mt-0.5 shrink-0 rounded-lg bg-primary/15 p-1.5 text-primary-ink">
        <Sparkles className="h-4 w-4" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-semibold">{banner.title}</div>
        <p className="mt-0.5 text-[12px] leading-5 text-muted-foreground">{banner.desc}</p>
      </div>
      <button
        type="button"
        onClick={clearSpotlight}
        title={t('whatsNew.closeSpotlight')}
        aria-label={t('whatsNew.closeSpotlight')}
        className="shrink-0 rounded p-1 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}
