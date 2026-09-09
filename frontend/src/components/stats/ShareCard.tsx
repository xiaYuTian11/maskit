/**
 * 战绩卡片：把本地统计画成一张可分享的图。
 *
 * 为什么是「画图 + 用户自己发」而不是「上传排行榜」：
 * 调用次数、脱敏次数这些数据源头全在用户机器上，服务端没有任何验证手段，
 * 一旦上榜带奖励就必然被脚本刷爆。而且排行榜会暴露团队规模与项目节奏，
 * 对企业用户是泄密。用户主动晒出去的一张图，传播效果反而更好。
 *
 * 隐私红线：**图上只能出现聚合数字，绝不能出现任何命中原文**。
 * 数据来自 /api/stats/highlights，它只读 daily_words 的 label 与 cnt，不碰 word 列。
 * 这张图是要发到公网的，带一个词就可能把用户的公司名/客户名晒出去。
 *
 * 全程 canvas 本地绘制，零上传、零后端。
 */
import { ttf } from '@/lib/i18n'
import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download, Loader2, Share2, Check, Copy } from 'lucide-react'
import { shieldFetch } from '@/lib/shield-fetch'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { toast } from '@/lib/toast'
import { useI18n } from '@/lib/i18n'

interface Highlights {
  ok: boolean
  days: number
  total: { requests: number; mask_events: number; restored: number; tokens_prompt: number; tokens_completion: number }
  masked_items: number
  labels: Record<string, number>
}

/** 规则标签 → 卡片短名（i18n key）。长名字会把条形图挤变形，所以不复用后端那份带说明的。 */
const LABEL_KEYS: Record<string, string> = {
  PHONE: 'share.labelPhone', EMAIL: 'share.labelEmail', IDCARD: 'share.labelIdcard',
  CARD: 'share.labelCard', IBAN: 'share.labelIban', PLATE: 'share.labelPlate', LANDLINE: 'share.labelLandline',
  HKID: 'share.labelHkid', IP_PRIVATE: 'share.labelIp', IP_INTERNAL: 'share.labelIp', MAC: 'share.labelMac',
  USCC: 'share.labelUscc', API_KEY: 'share.labelApiKey', ACCESS_KEY: 'share.labelAccessKey', JWT: 'share.labelJwt',
  TOKEN: 'share.labelToken', SECRET: 'share.labelSecret', PRIVATE_KEY: 'share.labelPrivateKey',
  CONNSTR: 'share.labelConnstr',
}

const PERIODS = [
  { days: 7, labelKey: 'share.days7' },
  { days: 30, labelKey: 'share.daysN' },
]

function fmt(n: number): string {
  const trim = (x: number) => x.toFixed(1).replace(/\.0$/, '')
  if (ttf('stats.unitSystem') === 'cjk') {
    if (n >= 100_000_000) return trim(n / 100_000_000) + ttf('stats.numUnit')
    if (n >= 10_000) return trim(n / 10_000) + ttf('stats.tenThousandUnit')
    return n.toLocaleString('zh-CN')
  }
  if (n >= 1_000_000_000) return trim(n / 1e9) + 'B'
  if (n >= 1_000_000) return trim(n / 1e6) + 'M'
  return n.toLocaleString('en-US')
}

export function ShareCard() {
  const { t, tf } = useI18n()
  const [open, setOpen] = useState(false)
  const [days, setDays] = useState(7)
  const canvasRef = useRef<HTMLCanvasElement>(null)

  const { data, isLoading } = useQuery<Highlights>({
    queryKey: ['stats-highlights', days],
    queryFn: () => shieldFetch(`/api/stats/highlights?days=${days}`),
    enabled: open,
  })

  useEffect(() => {
    if (!open || !data?.ok) return
    const cv = canvasRef.current
    if (!cv) return
    draw(cv, data, days, t, tf)
  }, [open, data, days, t, tf])

  const download = () => {
    const cv = canvasRef.current
    if (!cv) return
    cv.toBlob((blob) => {
      if (!blob) return toast(t('share.exportFail'), 'error')
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = tf('share.fileName', { d: days })
      a.click()
      // 立刻回收：Tauri webview 里 objectURL 不会自动释放
      setTimeout(() => URL.revokeObjectURL(url), 1000)
      toast(t('share.saved'))
    }, 'image/png')
  }

  const [copied, setCopied] = useState(false)
  const copy = async () => {
    const cv = canvasRef.current
    if (!cv) return
    cv.toBlob(async (blob) => {
      if (!blob) return
      try {
        await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })])
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
        toast(t('share.copyOk'))
      } catch {
        toast(t('share.copyFail'), 'error')
      }
    }, 'image/png')
  }

  return (
    <>
      <Button size="sm" variant="outline" className="h-8 gap-1.5" onClick={() => setOpen(true)}>
        <Share2 className="h-3.5 w-3.5" /> {t('share.gen')}
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t('share.dialogTitle')}</DialogTitle>
            <DialogDescription>
              {t('share.dialogDesc')}
            </DialogDescription>
          </DialogHeader>

          <div className="flex items-center gap-2">
            {PERIODS.map((p) => (
              <Button
                key={p.days}
                size="sm"
                variant={days === p.days ? 'default' : 'outline'}
                className="h-7 text-xs"
                onClick={() => setDays(p.days)}
              >
                {p.labelKey === 'share.days7' ? t('share.days7') : tf('share.daysN', { n: p.days })}
              </Button>
            ))}
            {isLoading && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
          </div>

          <div className="overflow-hidden rounded-xl border">
            <canvas ref={canvasRef} className="block w-full" />
          </div>

          <div className="flex flex-wrap gap-2">
            <Button size="sm" className="gap-1.5" onClick={download}>
              <Download className="h-3.5 w-3.5" /> {t('share.saveImg')}
            </Button>
            <Button size="sm" variant="outline" onClick={copy} className="gap-1.5">
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
              {copied ? t('detail.copied') : t('share.copyClipboard')}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}

/** 卡片绘制。逻辑集中在这里，改版式不影响上面的数据与交互。 */
function draw(cv: HTMLCanvasElement, d: Highlights, days: number, t: (k: string) => string, tf: (k: string, v?: Record<string, string | number>) => string) {
  // 画布高度为 660：为 6 条柱和页脚各留出稳定的垂直空间，避免窄视口裁切。
  const W = 1000, H = 660
  // devicePixelRatio 放大再缩回，否则在高分屏上导出的图是糊的
  const dpr = Math.min(window.devicePixelRatio || 1, 2)
  cv.width = W * dpr
  cv.height = H * dpr
  cv.style.aspectRatio = `${W} / ${H}`
  const g = cv.getContext('2d')
  if (!g) return
  g.scale(dpr, dpr)

  const FONT = '"Inter", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif'

  const bg = g.createLinearGradient(0, 0, W, H)
  bg.addColorStop(0, '#0a1020')
  bg.addColorStop(0.55, '#0d1428')
  bg.addColorStop(1, '#111a33')
  g.fillStyle = bg
  g.fillRect(0, 0, W, H)

  // 右上角光晕，避免整张图死板
  const halo = g.createRadialGradient(W - 120, 60, 10, W - 120, 60, 380)
  halo.addColorStop(0, 'rgba(129,140,248,0.20)')
  halo.addColorStop(1, 'rgba(129,140,248,0)')
  g.fillStyle = halo
  g.fillRect(0, 0, W, H)

  // ---- 头部 ----
  g.fillStyle = '#e2e8f0'
  g.font = `600 26px ${FONT}`
  g.fillText('Data Maskit', 56, 66)
  g.fillStyle = '#64748b'
  g.font = `400 16px ${FONT}`
  g.fillText(t('share.cardTitle'), 56, 92)

  g.textAlign = 'right'
  g.fillStyle = '#818cf8'
  g.font = `600 16px ${FONT}`
  g.fillText(days === 7 ? t('share.days7') : tf('share.daysN', { n: days }), W - 56, 66)
  g.textAlign = 'left'

  // ---- 主数字 ----
  g.fillStyle = '#94a3b8'
  g.font = `400 17px ${FONT}`
  g.fillText(t('share.maskedLabel'), 56, 168)

  // 主数字**不缩写**：49,413 比「4.9 万」更有冲击力，也更像真实数据。
  // 副统计仍用 fmt 缩写，否则三个长数字会互相挤。
  const main = d.masked_items.toLocaleString('zh-CN')
  g.font = `700 76px ${FONT}`
  const grad = g.createLinearGradient(56, 190, 560, 260)
  grad.addColorStop(0, '#a5b4fc')
  grad.addColorStop(1, '#22d3ee')
  g.fillStyle = grad
  g.fillText(main, 56, 250)
  const mainW = g.measureText(main).width
  g.fillStyle = '#64748b'
  g.font = `500 24px ${FONT}`
  g.fillText(t('share.unit'), 56 + mainW + 14, 250)

  // ---- 三个副统计 ----
  const subs: [string, string][] = [
    [t('share.sub1'), fmt(d.total.requests)],
    [t('share.sub2'), fmt(d.total.restored)],
    [t('share.sub3'), fmt(d.total.tokens_prompt + d.total.tokens_completion)],
  ]
  subs.forEach(([k, v], i) => {
    const x = 56 + i * 200
    g.fillStyle = '#e2e8f0'
    g.font = `600 27px ${FONT}`
    g.fillText(v, x, 322)
    g.fillStyle = '#64748b'
    g.font = `400 14px ${FONT}`
    g.fillText(k, x, 346)
  })

  // 分隔线
  g.strokeStyle = 'rgba(255,255,255,0.07)'
  g.lineWidth = 1
  g.beginPath(); g.moveTo(56, 378); g.lineTo(W - 56, 378); g.stroke()

  // ---- 类型分布（Top 6 条形图）----
  const top = Object.entries(d.labels)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
  const max = top[0]?.[1] || 1

  g.fillStyle = '#94a3b8'
  g.font = `500 15px ${FONT}`
  g.fillText(t('share.mainTypes'), 56, 412)

  top.forEach(([label, n], i) => {
    const y = 444 + i * 26
    const name = t(LABEL_KEYS[label] || '') || label   // 自定义分组直接用用户起的组名（是分类名不是命中词）
    g.fillStyle = '#cbd5e1'
    g.font = `400 14px ${FONT}`
    g.fillText(name, 56, y + 12)

    const barX = 200, barW = 560
    g.fillStyle = 'rgba(255,255,255,0.05)'
    g.fillRect(barX, y, barW, 14)
    const w = Math.max(6, (n / max) * barW)
    const bg2 = g.createLinearGradient(barX, 0, barX + w, 0)
    bg2.addColorStop(0, '#818cf8')
    bg2.addColorStop(1, '#22d3ee')
    g.fillStyle = bg2
    g.fillRect(barX, y, w, 14)

    g.fillStyle = '#94a3b8'
    g.font = `500 13px ${FONT}`
    g.textAlign = 'right'
    g.fillText(fmt(n), W - 56, y + 12)
    g.textAlign = 'left'
  })

  // ---- 页脚 ----
  g.fillStyle = 'rgba(255,255,255,0.05)'
  g.fillRect(0, H - 56, W, 56)
  g.fillStyle = '#475569'
  g.font = `400 13px ${FONT}`
  g.fillText(t('share.footer'), 56, H - 22)
  g.textAlign = 'right'
  g.fillStyle = '#64748b'
  g.fillText('Data Maskit', W - 56, H - 22)
  g.textAlign = 'left'
}
