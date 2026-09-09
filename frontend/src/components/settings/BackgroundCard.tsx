/**
 * 个性化背景设置：自定义背景图 + 透明度。
 *
 * 设计取舍：
 * - 纯前端偏好（localStorage），不进后端 config——背景是个人视觉偏好，
 *   混进 config.json 会让配置导出带上无意义的用户图数据。
 * - 本地上传转 base64：Tauri 无需文件系统权限，图跟着偏好走。
 *   代价是 base64 体积大（几百 KB），localStorage 5MB 上限够用。
 * - 透明度滑块控制背景层 opacity（0=完全透明不可见，100=全显），
 *   内容区卡片始终不透明保证可读性，背景只在卡片间隙透出。
 */
import { useState } from 'react'
import { Image as ImageIcon, X, Upload } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/lib/i18n'
import { toast } from '@/lib/toast'

export function BackgroundCard() {
  const { t } = useI18n()
  const [bgImage, setBgImage] = useState<string>(() => {
    try { return localStorage.getItem('shield_bg_image') || '' } catch { return '' }
  })
  const [opacity, setOpacity] = useState<number>(() => {
    try { return Number(localStorage.getItem('shield_bg_opacity')) || 0 } catch { return 0 }
  })

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

  const onUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    if (!file.type.startsWith('image/')) {
      toast(t('settings.bg.notImage'), 'error')
      return
    }
    // 限制 2MB：base64 会膨胀 ~33%，localStorage 上限 5MB
    if (file.size > 2 * 1024 * 1024) {
      toast(t('settings.bg.tooLarge'), 'error')
      return
    }
    const reader = new FileReader()
    reader.onload = () => {
      const base64 = reader.result as string
      applyImage(base64)
      // 首次上传自动给一个默认透明度，避免传了图但 opacity=0 看不到
      if (opacity === 0) applyOpacity(20)
      toast(t('settings.bg.applied'))
    }
    reader.onerror = () => toast(t('settings.bg.readFail'), 'error')
    reader.readAsDataURL(file)
    // 清空 input 让同一文件可重复选
    e.target.value = ''
  }

  return (
    <Card className="border bg-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm font-semibold">
          <ImageIcon className="h-4 w-4 text-muted-foreground" />
          {t('settings.bg.title')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* 当前背景预览 */}
        {bgImage && (
          <div className="relative overflow-hidden rounded-lg border">
            <img src={bgImage} alt="bg" className="h-28 w-full object-cover" />
            <Button
              size="icon"
              variant="destructive"
              className="absolute right-2 top-2 h-7 w-7"
              onClick={() => { applyImage(''); applyOpacity(0) }}
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
        )}

        {/* 透明度滑块（有图才显示） */}
        {bgImage && (
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
              onChange={(e) => applyOpacity(Number(e.target.value))}
              className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-muted accent-primary"
            />
            <p className="mt-1 text-[11px] text-muted-foreground">{t('settings.bg.opacityHint')}</p>
          </div>
        )}

        {/* 上传按钮 */}
        <div className="flex items-center gap-2">
          <label>
            <input type="file" accept="image/*" className="hidden" onChange={onUpload} />
            <span className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-md bg-primary px-3 text-xs font-medium text-primary-foreground hover:bg-primary/90">
              <Upload className="h-3.5 w-3.5" /> {t('settings.bg.upload')}
            </span>
          </label>
          {!bgImage && (
            <p className="text-[11px] text-muted-foreground">{t('settings.bg.emptyHint')}</p>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
