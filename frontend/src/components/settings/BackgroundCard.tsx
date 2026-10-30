/**
 * 个性化背景设置：自定义背景图 + 透明度 + 模糊度 + 卡片毛玻璃 + 预设壁纸。
 *
 * 设计取舍：
 * - 纯前端偏好（localStorage），不进后端 config——背景是个人视觉偏好，
 *   混进 config.json 会让配置导出带上无意义的用户图数据。
 * - 前端 Canvas 智能等比缩放与 WebP 压缩：解除 2MB 严苛限制（支持至 15MB 原图），
 *   自动缩放到最大 1920×1080 并转 82% WebP，单图体积压至 100~250KB，彻底杜绝 localStorage 爆满。
 * - 透明度滑块控制背景层 opacity（0=不可见，100=全显）；
 * - 模糊度滑块控制背景图高斯模糊（0~20px，默认 0px），将复杂壁纸转化为柔和氛围光；
 * - 卡片不透明度滑块控制内容区卡片的透明度与磨砂毛玻璃（30%~100%，默认 80%），
 *   有背景图时优雅透光并通过 backdrop-blur 保证文字可读性，无图时自动回退为纯色不透明；
 * - 内置精选极简矢量暗色预设，免找图即刻体验毛玻璃视觉。
 */
import { useState } from 'react'
import { Image as ImageIcon, X, Upload, RotateCcw, Loader2, Sparkles } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/lib/i18n'
import { toast } from '@/lib/toast'
import {
  PRESET_WALLPAPERS,
  DEFAULT_OPACITY,
  PRESET_OPACITY,
  DEFAULT_BLUR,
  DEFAULT_CARD_OPACITY,
  DEFAULT_WALLPAPER_DATA_URL,
  getStoredWallpaperConfig,
} from '@/lib/wallpaper'

/**
 * 前端 Canvas 智能等比缩放与 WebP 压缩
 * 将任意大尺寸原图缩放至最大 1920×1080 并转换为 82% 质量 WebP，体积稳定在 100~250KB
 */
async function compressImage(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new Error('read_failed'))
    reader.onload = () => {
      const img = new Image()
      img.onerror = () => reject(new Error('decode_failed'))
      img.onload = () => {
        const MAX_WIDTH = 1920
        const MAX_HEIGHT = 1080
        let w = img.width
        let h = img.height

        if (w > MAX_WIDTH || h > MAX_HEIGHT) {
          const ratio = Math.min(MAX_WIDTH / w, MAX_HEIGHT / h)
          w = Math.round(w * ratio)
          h = Math.round(h * ratio)
        }

        const canvas = document.createElement('canvas')
        canvas.width = w
        canvas.height = h
        const ctx = canvas.getContext('2d')
        if (!ctx) {
          resolve(img.src)
          return
        }
        ctx.drawImage(img, 0, 0, w, h)

        try {
          const webp = canvas.toDataURL('image/webp', 0.82)
          if (webp.startsWith('data:image/webp')) {
            resolve(webp)
            return
          }
        } catch { /* fallback */ }
        resolve(canvas.toDataURL('image/jpeg', 0.85))
      }
      img.src = reader.result as string
    }
    reader.readAsDataURL(file)
  })
}

export function BackgroundCard() {
  const { t } = useI18n()
  const [initCfg] = useState(() => getStoredWallpaperConfig())
  const [bgImage, setBgImage] = useState<string>(initCfg.bgImage)
  const [opacity, setOpacity] = useState<number>(initCfg.bgOpacity)
  const [bgBlur, setBgBlur] = useState<number>(initCfg.bgBlur)
  const [cardOpacity, setCardOpacity] = useState<number>(initCfg.cardOpacity)
  const [processing, setProcessing] = useState(false)

  const applyImage = (val: string) => {
    setBgImage(val)
    try {
      if (val) localStorage.setItem('shield_bg_image', val)
      else localStorage.removeItem('shield_bg_image')
    } catch {
      toast(t('settings.bg.saveFail'), 'error')
    }
    // storage 事件只在跨标签触发，同标签手动派发让 AppLayout 即时刷新
    window.dispatchEvent(new StorageEvent('storage', { key: 'shield_bg_image', newValue: val }))
  }

  const applyOpacity = (val: number) => {
    setOpacity(val)
    try { localStorage.setItem('shield_bg_opacity', String(val)) } catch { /* ignore */ }
    window.dispatchEvent(new StorageEvent('storage', { key: 'shield_bg_opacity', newValue: String(val) }))
  }

  const applyBlur = (val: number) => {
    setBgBlur(val)
    try { localStorage.setItem('shield_bg_blur', String(val)) } catch { /* ignore */ }
    window.dispatchEvent(new StorageEvent('storage', { key: 'shield_bg_blur', newValue: String(val) }))
  }

  const applyCardOpacity = (val: number) => {
    setCardOpacity(val)
    try { localStorage.setItem('shield_card_opacity', String(val)) } catch { /* ignore */ }
    window.dispatchEvent(new StorageEvent('storage', { key: 'shield_card_opacity', newValue: String(val) }))
  }

  const handleResetDefault = () => {
    // 恢复默认外观 = 恢复到系统推荐的星云流光默认预设
    applyImage(DEFAULT_WALLPAPER_DATA_URL)
    applyOpacity(DEFAULT_OPACITY)
    applyBlur(DEFAULT_BLUR)
    applyCardOpacity(DEFAULT_CARD_OPACITY)
    toast(t('settings.bg.resetDone'))
  }

  const applyPreset = (dataUrl: string) => {
    applyImage(dataUrl)
    // DEFAULT_OPACITY 为 0（初始不启用），选预设时必须抬到可见值，否则点了没反应
    if (opacity === 0) applyOpacity(PRESET_OPACITY)
    toast(t('settings.bg.applied'))
  }

  const onUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    if (!file.type.startsWith('image/')) {
      toast(t('settings.bg.notImage'), 'error')
      return
    }
    // 放宽至 15MB，前端 Canvas 会自动等比缩放和压缩为 WebP
    if (file.size > 15 * 1024 * 1024) {
      toast(t('settings.bg.tooLarge'), 'error')
      return
    }
    setProcessing(true)
    try {
      const optimizedBase64 = await compressImage(file)
      applyImage(optimizedBase64)
      if (opacity === 0) applyOpacity(PRESET_OPACITY)
      toast(t('settings.bg.applied'))
    } catch {
      toast(t('settings.bg.readFail'), 'error')
    } finally {
      setProcessing(false)
      e.target.value = ''
    }
  }

  return (
    <Card className="border bg-card shadow-card">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-sm font-semibold">
            <ImageIcon className="h-4 w-4 text-muted-foreground" />
            {t('settings.bg.title')}
          </CardTitle>
          {(bgImage !== DEFAULT_WALLPAPER_DATA_URL || opacity !== DEFAULT_OPACITY || cardOpacity !== DEFAULT_CARD_OPACITY || bgBlur !== DEFAULT_BLUR) && (
            <Button
              variant="ghost"
              size="sm"
              onClick={handleResetDefault}
              className="h-7 gap-1 px-2 text-muted-foreground hover:text-foreground"
            >
              <RotateCcw className="h-3 w-3" />
              <span>{t('settings.bg.resetDefault')}</span>
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* 当前背景预览 */}
        {bgImage && (
          <div className="relative overflow-hidden rounded-lg border">
            <img
              src={bgImage}
              alt={t('settings.bg.previewAlt')}
              className="h-28 w-full object-cover transition-all"
              style={{
                filter: bgBlur > 0 ? `blur(${bgBlur}px)` : undefined,
                transform: bgBlur > 0 ? 'scale(1.05)' : undefined,
              }}
            />
            <Button
              size="icon"
              variant="destructive"
              className="absolute right-2 top-2 h-7 w-7 shadow-sm"
              title={t('common.clear')}
              aria-label={t('common.clear')}
              onClick={() => { applyImage(''); applyOpacity(0) }}
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
        )}

        {/* 预设壁纸推荐 */}
        <div>
          <div className="mb-2 flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
            <Sparkles className="h-3.5 w-3.5 text-primary-ink" />
            <span>{t('settings.bg.presets')}</span>
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {PRESET_WALLPAPERS.map((p) => {
              const isSelected = bgImage === p.dataUrl
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => applyPreset(p.dataUrl)}
                  className={`group relative overflow-hidden rounded-lg border text-left transition-all ${
                    isSelected
                      ? 'border-primary ring-2 ring-primary/30'
                      : 'border-border hover:border-primary/50'
                  }`}
                >
                  <img
                    src={p.dataUrl}
                    alt={t(p.labelKey)}
                    className="h-14 w-full object-cover transition-transform duration-300 group-hover:scale-105"
                  />
                  <div className="absolute inset-x-0 bottom-0 bg-background/80 px-2 py-0.5 text-2xs font-medium backdrop-blur-sm truncate">
                    {t(p.labelKey)}
                  </div>
                </button>
              )
            })}
          </div>
        </div>

        {/* 控制滑块区（有图才显示） */}
        {bgImage && (
          <div className="space-y-3.5 border-t pt-3">
            {/* 1. 背景透明度滑块 */}
            <div>
              <div className="mb-1.5 flex items-center justify-between text-xs">
                <span className="text-muted-foreground">{t('settings.bg.opacity')}</span>
                <span className="font-mono tabular-nums">{opacity}%</span>
              </div>
              <input
                type="range"
                min={0}
                max={100}
                value={opacity}
                aria-label={t('settings.bg.opacity')}
                onChange={(e) => applyOpacity(Number(e.target.value))}
                className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-muted accent-primary"
              />
              <p className="mt-1 text-2xs text-muted-foreground">{t('settings.bg.opacityHint')}</p>
            </div>

            {/* 2. 背景虚化模糊度滑块 */}
            <div>
              <div className="mb-1.5 flex items-center justify-between text-xs">
                <span className="text-muted-foreground">{t('settings.bg.blur')}</span>
                <span className="font-mono tabular-nums">{bgBlur}px</span>
              </div>
              <input
                type="range"
                min={0}
                max={20}
                value={bgBlur}
                aria-label={t('settings.bg.blur')}
                onChange={(e) => applyBlur(Number(e.target.value))}
                className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-muted accent-primary"
              />
              <p className="mt-1 text-2xs text-muted-foreground">{t('settings.bg.blurHint')}</p>
            </div>

            {/* 3. 卡片不透明度滑块 */}
            <div>
              <div className="mb-1.5 flex items-center justify-between text-xs">
                <span className="text-muted-foreground">{t('settings.bg.cardOpacity')}</span>
                <span className="font-mono tabular-nums">{cardOpacity}%</span>
              </div>
              <input
                type="range"
                min={30}
                max={100}
                value={cardOpacity}
                aria-label={t('settings.bg.cardOpacity')}
                onChange={(e) => applyCardOpacity(Number(e.target.value))}
                className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-muted accent-primary"
              />
              <p className="mt-1 text-2xs text-muted-foreground">{t('settings.bg.cardOpacityHint')}</p>
            </div>
          </div>
        )}

        {/* 上传自定义图片按钮 */}
        <div className="flex items-center gap-2 border-t pt-3">
          <label>
            <input
              type="file"
              accept="image/*"
              className="hidden"
              disabled={processing}
              onChange={onUpload}
            />
            <span className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-md bg-primary px-3 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-opacity disabled:opacity-50">
              {processing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
              {processing ? t('settings.bg.compressing') : t('settings.bg.upload')}
            </span>
          </label>
          {!bgImage && (
            <p className="text-2xs text-muted-foreground">{t('settings.bg.emptyHint')}</p>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
