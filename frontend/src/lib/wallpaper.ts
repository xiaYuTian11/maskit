/**
 * 全局壁纸与毛玻璃外观配置
 *
 * 设计取舍：
 * - 纯前端偏好（localStorage），不进后端 config.json；
 * - 针对暗色网关 UI 专属定制 4 套高级矢量微光壁纸：
 *   ① 星云流光（旗舰推荐）：深邃星云天青、深靛与暗罗兰自然弥散，层次丰富舒缓；
 *   ② 极光暗夜：幽林深绿与冰川湛蓝极光帷幔，静谧深远；
 *   ③ 深海星辉：深海冷钴蓝漫射光束，硬核专注科技感；
 *   ④ 黑曜微光：黑曜石炭黑底色搭配低调暗金微光，轻奢抗疲劳。
 * - 全新未配置用户默认启用「星云流光（55% 透明度 + 78% 卡片磨砂）」，开箱即享高端毛玻璃；
 * - 若用户曾上传自定义图片或选择其他预设，100% 优先保留用户配置，绝不覆盖；
 * - 若用户曾主动清空/关闭背景，保持关闭状态，尊重用户偏好。
 */

export const DEFAULT_OPACITY = 55
/** 用户主动选预设/传图时给的可见度 */
export const PRESET_OPACITY = 55
export const DEFAULT_BLUR = 6
export const DEFAULT_CARD_OPACITY = 78

const LEGACY_BG_MIGRATED_KEY = 'shield_bg_migrated_v2'

/**
 * 预设 1：星云流光（旗舰自适应·全屏柔和弥散星云·免网络离线可用）
 */
export const DEFAULT_WALLPAPER_DATA_URL = `data:image/svg+xml;utf8,${encodeURIComponent(`
<svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080" viewBox="0 0 1920 1080" fill="none">
  <defs>
    <radialGradient id="neb-blue" cx="20%" cy="22%" r="68%">
      <stop offset="0%" stop-color="#1e40af" stop-opacity="0.55"/>
      <stop offset="40%" stop-color="#0284c7" stop-opacity="0.25"/>
      <stop offset="100%" stop-color="#0284c7" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="neb-indigo" cx="78%" cy="25%" r="65%">
      <stop offset="0%" stop-color="#4338ca" stop-opacity="0.48"/>
      <stop offset="45%" stop-color="#6366f1" stop-opacity="0.18"/>
      <stop offset="100%" stop-color="#4338ca" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="neb-purple" cx="50%" cy="58%" r="60%">
      <stop offset="0%" stop-color="#581c87" stop-opacity="0.32"/>
      <stop offset="50%" stop-color="#7e22ce" stop-opacity="0.12"/>
      <stop offset="100%" stop-color="#581c87" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="neb-emerald" cx="85%" cy="80%" r="55%">
      <stop offset="0%" stop-color="#065f46" stop-opacity="0.35"/>
      <stop offset="50%" stop-color="#0d9488" stop-opacity="0.12"/>
      <stop offset="100%" stop-color="#065f46" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="neb-cyan" cx="15%" cy="75%" r="55%">
      <stop offset="0%" stop-color="#1e3a8a" stop-opacity="0.42"/>
      <stop offset="60%" stop-color="#0284c7" stop-opacity="0.10"/>
      <stop offset="100%" stop-color="#1e3a8a" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="100%" height="100%" fill="#0a0d14"/>
  <rect width="100%" height="100%" fill="url(#neb-blue)"/>
  <rect width="100%" height="100%" fill="url(#neb-indigo)"/>
  <rect width="100%" height="100%" fill="url(#neb-purple)"/>
  <rect width="100%" height="100%" fill="url(#neb-cyan)"/>
  <rect width="100%" height="100%" fill="url(#neb-emerald)"/>
</svg>
`.trim())}`

export interface PresetWallpaper {
  id: string
  labelKey: string
  dataUrl: string
}

export const PRESET_WALLPAPERS: PresetWallpaper[] = [
  {
    id: 'ambient',
    labelKey: 'settings.bg.presetAmbient',
    dataUrl: DEFAULT_WALLPAPER_DATA_URL,
  },
  {
    id: 'aurora',
    labelKey: 'settings.bg.presetAurora',
    dataUrl: `data:image/svg+xml;utf8,${encodeURIComponent(`
      <svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080" viewBox="0 0 1920 1080" fill="none">
        <defs>
          <radialGradient id="aur-green" cx="30%" cy="28%" r="70%">
            <stop offset="0%" stop-color="#065f46" stop-opacity="0.55"/>
            <stop offset="35%" stop-color="#059669" stop-opacity="0.28"/>
            <stop offset="70%" stop-color="#10b981" stop-opacity="0.08"/>
            <stop offset="100%" stop-color="#065f46" stop-opacity="0"/>
          </radialGradient>
          <radialGradient id="aur-cyan" cx="75%" cy="32%" r="65%">
            <stop offset="0%" stop-color="#0c4a6e" stop-opacity="0.55"/>
            <stop offset="40%" stop-color="#0284c7" stop-opacity="0.22"/>
            <stop offset="80%" stop-color="#38bdf8" stop-opacity="0.06"/>
            <stop offset="100%" stop-color="#0c4a6e" stop-opacity="0"/>
          </radialGradient>
          <radialGradient id="aur-purple" cx="55%" cy="80%" r="65%">
            <stop offset="0%" stop-color="#1e1b4b" stop-opacity="0.50"/>
            <stop offset="50%" stop-color="#312e81" stop-opacity="0.18"/>
            <stop offset="100%" stop-color="#1e1b4b" stop-opacity="0"/>
          </radialGradient>
        </defs>
        <rect width="100%" height="100%" fill="#05080e"/>
        <rect width="100%" height="100%" fill="url(#aur-green)"/>
        <rect width="100%" height="100%" fill="url(#aur-cyan)"/>
        <rect width="100%" height="100%" fill="url(#aur-purple)"/>
      </svg>
    `.trim())}`,
  },
  {
    id: 'space',
    labelKey: 'settings.bg.presetSpace',
    dataUrl: `data:image/svg+xml;utf8,${encodeURIComponent(`
      <svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080" viewBox="0 0 1920 1080" fill="none">
        <defs>
          <radialGradient id="sp-blue" cx="50%" cy="18%" r="75%">
            <stop offset="0%" stop-color="#1d4ed8" stop-opacity="0.52"/>
            <stop offset="40%" stop-color="#2563eb" stop-opacity="0.24"/>
            <stop offset="75%" stop-color="#60a5fa" stop-opacity="0.06"/>
            <stop offset="100%" stop-color="#1d4ed8" stop-opacity="0"/>
          </radialGradient>
          <radialGradient id="sp-deep" cx="18%" cy="75%" r="60%">
            <stop offset="0%" stop-color="#075985" stop-opacity="0.42"/>
            <stop offset="50%" stop-color="#0369a1" stop-opacity="0.14"/>
            <stop offset="100%" stop-color="#075985" stop-opacity="0"/>
          </radialGradient>
          <radialGradient id="sp-indigo" cx="82%" cy="70%" r="58%">
            <stop offset="0%" stop-color="#1e3a8a" stop-opacity="0.38"/>
            <stop offset="55%" stop-color="#3b82f6" stop-opacity="0.10"/>
            <stop offset="100%" stop-color="#1e3a8a" stop-opacity="0"/>
          </radialGradient>
        </defs>
        <rect width="100%" height="100%" fill="#040711"/>
        <rect width="100%" height="100%" fill="url(#sp-blue)"/>
        <rect width="100%" height="100%" fill="url(#sp-deep)"/>
        <rect width="100%" height="100%" fill="url(#sp-indigo)"/>
      </svg>
    `.trim())}`,
  },
  {
    id: 'cyber',
    labelKey: 'settings.bg.presetCyber',
    dataUrl: `data:image/svg+xml;utf8,${encodeURIComponent(`
      <svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080" viewBox="0 0 1920 1080" fill="none">
        <defs>
          <radialGradient id="ob-gold" cx="72%" cy="26%" r="65%">
            <stop offset="0%" stop-color="#78350f" stop-opacity="0.42"/>
            <stop offset="40%" stop-color="#b45309" stop-opacity="0.18"/>
            <stop offset="75%" stop-color="#d97706" stop-opacity="0.05"/>
            <stop offset="100%" stop-color="#78350f" stop-opacity="0"/>
          </radialGradient>
          <radialGradient id="ob-purple" cx="28%" cy="65%" r="60%">
            <stop offset="0%" stop-color="#4c1d95" stop-opacity="0.36"/>
            <stop offset="45%" stop-color="#6d28d9" stop-opacity="0.12"/>
            <stop offset="100%" stop-color="#4c1d95" stop-opacity="0"/>
          </radialGradient>
          <radialGradient id="ob-zinc" cx="45%" cy="30%" r="55%">
            <stop offset="0%" stop-color="#27272a" stop-opacity="0.45"/>
            <stop offset="60%" stop-color="#3f3f46" stop-opacity="0.10"/>
            <stop offset="100%" stop-color="#27272a" stop-opacity="0"/>
          </radialGradient>
        </defs>
        <rect width="100%" height="100%" fill="#08080a"/>
        <rect width="100%" height="100%" fill="url(#ob-zinc)"/>
        <rect width="100%" height="100%" fill="url(#ob-gold)"/>
        <rect width="100%" height="100%" fill="url(#ob-purple)"/>
      </svg>
    `.trim())}`,
  },
]

/**
 * 获取当前存储的壁纸设置
 * - 全新未配置用户：默认启用推荐的第 1 套旗舰星云壁纸与毛玻璃卡片；
 * - 已有自定义图片或已选预设的用户：100% 保持用户既有配置，绝不覆盖；
 * - 主动清空/关闭过壁纸的用户（savedImg === '' 且已配置过）：保持关闭。
 */
export function getStoredWallpaperConfig() {
  try {
    const savedImg = localStorage.getItem('shield_bg_image')
    const savedOpacity = localStorage.getItem('shield_bg_opacity')
    const savedBlur = localStorage.getItem('shield_bg_blur')
    const savedCardOpacity = localStorage.getItem('shield_card_opacity')

    // 未做任何配置的全新状态（null）
    const isInitial = savedImg === null && savedOpacity === null

    // ===== 一次性迁移：仅首次升级时清掉旧版自动写入的默认壁纸 =====
    const migrated = localStorage.getItem(LEGACY_BG_MIGRATED_KEY) === '1'
    if (!migrated) {
      try {
        localStorage.setItem(LEGACY_BG_MIGRATED_KEY, '1')
      } catch {
        /* ignore */
      }
      const isBuiltinPreset = (savedImg ?? '').startsWith('data:image/svg+xml')
      const legacyDefaultBg = isBuiltinPreset && Number(savedOpacity ?? 0) === 60
      if (legacyDefaultBg) {
        try {
          localStorage.removeItem('shield_bg_image')
          localStorage.removeItem('shield_bg_opacity')
          localStorage.removeItem('shield_card_opacity')
          localStorage.removeItem('shield_bg_blur')
        } catch {
          /* ignore */
        }
        // 清除旧默认后，自动无缝升级为新版默认星云流光
        return {
          bgImage: DEFAULT_WALLPAPER_DATA_URL,
          bgOpacity: DEFAULT_OPACITY,
          bgBlur: DEFAULT_BLUR,
          cardOpacity: DEFAULT_CARD_OPACITY,
        }
      }
    }

    // 全新用户：默认启用星云流光；老用户有图片取图片；主动关闭者取空
    const bgImage = isInitial ? DEFAULT_WALLPAPER_DATA_URL : (savedImg || '')
    const bgOpacity = isInitial
      ? DEFAULT_OPACITY
      : (savedOpacity !== null ? Number(savedOpacity) : 0)
    const bgBlur = savedBlur !== null ? Number(savedBlur) : DEFAULT_BLUR
    const cardOpacity =
      savedCardOpacity !== null ? Number(savedCardOpacity) : DEFAULT_CARD_OPACITY

    return { bgImage, bgOpacity, bgBlur, cardOpacity }
  } catch {
    return {
      bgImage: DEFAULT_WALLPAPER_DATA_URL,
      bgOpacity: DEFAULT_OPACITY,
      bgBlur: DEFAULT_BLUR,
      cardOpacity: DEFAULT_CARD_OPACITY,
    }
  }
}
