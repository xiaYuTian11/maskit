/**
 * 赞助弹窗：纯自愿赞赏入口。
 *
 * 边界（重要，勿改）：
 *  - 本弹窗**不承载任何功能锁**。赞助是无偿支持，不构成任何服务对价；
 *  - 因此这里不做授权校验、不做设备绑定，也不触及「个人收款码不得用于经营性收款」的口径；
 *  - 若将来要做「赞助回赠激活码」，请单独做授权模块（见 docs/SPONSOR.md），不要在此处掺杂判断。
 *
 * 二维码资源：frontend/public/sponsor/wechat.png 与 alipay.png。
 * 缺图时给文字兜底而不是空白，避免首屏出现「加载失败」的破图。
 */
import { useState } from 'react'
import { Heart } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useI18n } from '@/lib/i18n'

const CHANNELS = [
  { key: 'wechat', src: '/sponsor/wechat.png' },
  { key: 'alipay', src: '/sponsor/alipay.png' },
] as const

export function SponsorDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
}) {
  const { t } = useI18n()
  const [failed, setFailed] = useState<Record<string, boolean>>({})

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Heart className="h-4 w-4 text-rose-500" />
            {t('sponsor.title')}
          </DialogTitle>
          <DialogDescription>{t('sponsor.subtitle')}</DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {CHANNELS.map((c) => (
            <div
              key={c.key}
              className="rounded-lg border border-border/60 bg-muted/20 p-3 text-center"
            >
              <div className="text-[13px] font-medium">{t(`sponsor.${c.key}`)}</div>
              <div className="mt-2 flex h-44 items-center justify-center rounded-md bg-background">
                {failed[c.key] ? (
                  <div className="px-2 text-2xs leading-5 text-muted-foreground">
                    {t('sponsor.missing')}
                  </div>
                ) : (
                  <img
                    src={c.src}
                    alt={t(`sponsor.${c.key}`)}
                    className="h-40 w-40 object-contain"
                    onError={() => setFailed((f) => ({ ...f, [c.key]: true }))}
                  />
                )}
              </div>
            </div>
          ))}
        </div>

        <p className="text-2xs leading-5 text-muted-foreground">{t('sponsor.note')}</p>
      </DialogContent>
    </Dialog>
  )
}
