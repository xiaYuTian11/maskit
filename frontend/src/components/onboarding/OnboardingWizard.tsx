import { useEffect, useRef, useState } from 'react'
import { ArrowRight, Check, ChevronLeft, ChevronRight, ShieldCheck, Sparkles, TestTube2 } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useI18n } from '@/lib/i18n'

/** 完成标记：帮助中心的「重新打开首次引导」要清同一个键，两处不能各写一份字面量。 */
export const ONBOARDING_STORAGE_KEY = 'maskit_onboarding_completed'

type OnboardingWizardProps = {
  open?: boolean
  onOpenChange?: (open: boolean) => void
  /** 首次运行判定（未配置任何上游）。undefined 表示还没拿到面板状态。 */
  firstRun?: boolean
}

/** 首次使用的三步引导：只解释最短可用路径，不替用户修改客户端或上游配置。 */
export function OnboardingWizard({ open, onOpenChange, firstRun }: OnboardingWizardProps) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [internalOpen, setInternalOpen] = useState(false)
  // 引导只自动弹一次：面板状态是异步拿到的，拿到后要能弹，但重渲染不得反复弹。
  const autoPrompted = useRef(false)
  const [step, setStep] = useState(0)
  const isOpen = open ?? internalOpen

  useEffect(() => {
    if (autoPrompted.current || firstRun !== true) return
    autoPrompted.current = true
    let untouched = false
    try {
      // 读不到 localStorage（受限 WebView / 无痕）时不弹：弹窗会被当成 bug，
      // 而帮助中心里的手动入口本来就能拿到同样的内容。
      untouched = localStorage.getItem(ONBOARDING_STORAGE_KEY) !== '1'
    } catch {
      untouched = false
    }
    if (untouched) setInternalOpen(true)
  }, [firstRun])

  const close = () => {
    try {
      localStorage.setItem(ONBOARDING_STORAGE_KEY, '1')
    } catch {
      // 受限 WebView 中无法持久化时仍允许本次关闭
    }
    setInternalOpen(false)
    onOpenChange?.(false)
  }

  useEffect(() => {
    if (isOpen) setStep(0)
  }, [isOpen])

  const goTo = (path: string) => {
    close()
    navigate(path)
  }

  const steps = [
    {
      icon: ShieldCheck,
      title: t('onboarding.step1.title'),
      description: t('onboarding.step1.description'),
      action: t('onboarding.step1.action'),
      path: '/clients',
    },
    {
      icon: Sparkles,
      title: t('onboarding.step2.title'),
      description: t('onboarding.step2.description'),
      action: t('onboarding.step2.action'),
      path: '/clients',
    },
    {
      icon: TestTube2,
      title: t('onboarding.step3.title'),
      description: t('onboarding.step3.description'),
      action: t('onboarding.step3.action'),
      path: '/',
    },
  ]
  const current = steps[step]
  const Icon = current.icon

  return (
    <Dialog open={isOpen} onOpenChange={(nextOpen) => nextOpen ? onOpenChange?.(true) : close()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <span className="rounded-lg bg-primary/10 p-2 text-primary"><Icon className="h-5 w-5" /></span>
            {t('onboarding.title')}
          </DialogTitle>
          <DialogDescription>{t('onboarding.description')}</DialogDescription>
        </DialogHeader>

        <div className="space-y-5 py-2">
          <div className="flex items-center gap-2" aria-label={t('onboarding.progressLabel')}>
            {steps.map((item, index) => (
              <div key={item.title} className="flex flex-1 items-center gap-2">
                <button
                  type="button"
                  aria-label={`${index + 1}`}
                  onClick={() => setStep(index)}
                  className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-semibold transition-colors ${
                    index === step ? 'bg-primary text-primary-foreground' : index < step ? 'bg-primary/15 text-primary' : 'bg-muted text-muted-foreground'
                  }`}
                >
                  {index < step ? <Check className="h-3.5 w-3.5" /> : index + 1}
                </button>
                {index < steps.length - 1 && <span className={`h-px flex-1 ${index < step ? 'bg-primary/40' : 'bg-border'}`} />}
              </div>
            ))}
          </div>

          <div className="rounded-xl border bg-muted/20 p-5">
            <h3 className="text-base font-semibold">{current.title}</h3>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">{current.description}</p>
            <Button variant="outline" size="sm" className="mt-4 gap-1.5" onClick={() => goTo(current.path)}>
              {current.action}<ArrowRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>

        <DialogFooter className="flex-row items-center justify-between sm:justify-between">
          <Button variant="ghost" size="sm" onClick={close}>{t('onboarding.skip')}</Button>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={step === 0} onClick={() => setStep((value) => value - 1)}>
              <ChevronLeft className="mr-1 h-4 w-4" />{t('onboarding.previous')}
            </Button>
            {step < steps.length - 1 ? (
              <Button size="sm" onClick={() => setStep((value) => value + 1)}>{t('onboarding.next')}<ChevronRight className="ml-1 h-4 w-4" /></Button>
            ) : (
              <Button size="sm" onClick={close}>{t('onboarding.done')}</Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
