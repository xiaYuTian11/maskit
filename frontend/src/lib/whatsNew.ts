/**
 * 版本更新亮点与新功能聚焦引导状态管理。
 *
 * 设计口径（克制不打扰）：
 * - 全新安装用户优先走首次引导（OnboardingWizard），不叠弹新功能框，而是静默种下当前版本；
 * - 已有用户升级到包含未读亮点的版本时，仅自动弹一次轻量亮点卡片；
 * - 点击「去看看」后跳至目标页面/Tab，并触发短暂的非阻塞高亮脉冲 + 胶囊提示；
 * - 侧栏与新配置项上的 NEW 徽标在用户查看后即永久消除。
 */

export const WHATS_NEW_SEEN_VERSION_KEY = 'maskit_whats_new_seen_version'
export const WHATS_NEW_SEEN_FEATURES_KEY = 'maskit_whats_new_seen_features'

export interface FeatureHighlight {
  id: string
  since: string
  route: string
  navId?: string
  targetId: string
  icon: 'files' | 'visual'
  titleKey: string
  descKey: string
}

export interface SpotlightPayload {
  targetId: string
  title: string
  desc: string
}

export const WHATS_NEW_ITEMS: FeatureHighlight[] = [
  {
    id: 'files-workbench',
    since: '0.22.0',
    route: '/files',
    navId: 'files',
    targetId: 'files-dropzone',
    icon: 'files',
    titleKey: 'whatsNew.item.files.title',
    descKey: 'whatsNew.item.files.desc',
  },
  {
    id: 'visual-masking',
    since: '0.22.0',
    route: '/settings?tab=advanced',
    targetId: 'settings-visual-masking',
    icon: 'visual',
    titleKey: 'whatsNew.item.visual.title',
    descKey: 'whatsNew.item.visual.desc',
  },
]

function parseSemver(ver: string): [number, number, number] {
  const clean = String(ver || '').trim().replace(/^v/i, '').split('-')[0]
  const parts = clean.split('.').map((x) => parseInt(x, 10) || 0)
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0]
}

export function compareVersions(a: string, b: string): number {
  const pa = parseSemver(a)
  const pb = parseSemver(b)
  for (let i = 0; i < 3; i++) {
    if (pa[i] > pb[i]) return 1
    if (pa[i] < pb[i]) return -1
  }
  return 0
}

export function latestWhatsNewVersion(): string {
  let latest = '0.0.0'
  for (const item of WHATS_NEW_ITEMS) {
    if (compareVersions(item.since, latest) > 0) latest = item.since
  }
  return latest
}

export function getUnreadHighlights(seenVersion: string | null): FeatureHighlight[] {
  if (!seenVersion) return WHATS_NEW_ITEMS
  return WHATS_NEW_ITEMS.filter((item) => compareVersions(item.since, seenVersion) > 0)
}

export function shouldAutoOpenWhatsNew(opts: {
  currentVersion: string
  seenVersion: string | null
  isFirstRun: boolean
  onboardingCompleted: boolean
  hasFirstSeenAt: boolean
}): { open: boolean; seedVersion?: string } {
  const cur = String(opts.currentVersion || '').trim().replace(/^v/i, '')
  if (!cur) return { open: false }
  const latest = latestWhatsNewVersion()
  const seen = opts.seenVersion ? opts.seenVersion.trim().replace(/^v/i, '') : null

  if (!seen) {
    // 全新安装（未配上游且无任何历史使用痕迹）：不抢首次安装引导的注意力，直接记录当前版本
    if (opts.isFirstRun && !opts.onboardingCompleted && !opts.hasFirstSeenAt) {
      return { open: false, seedVersion: cur }
    }
    if (compareVersions(cur, latest) >= 0) {
      return { open: true }
    }
    return { open: false, seedVersion: cur }
  }

  if (compareVersions(latest, seen) > 0 && compareVersions(cur, seen) >= 0) {
    return { open: true }
  }
  return { open: false }
}

export function readSeenVersion(): string | null {
  try {
    if (typeof localStorage === 'undefined') return null
    const val = localStorage.getItem(WHATS_NEW_SEEN_VERSION_KEY)
    return val ? val.trim() : null
  } catch {
    return null
  }
}

export function writeSeenVersion(version: string): void {
  const clean = String(version || '').trim().replace(/^v/i, '')
  if (!clean) return
  try {
    if (typeof localStorage === 'undefined') return
    localStorage.setItem(WHATS_NEW_SEEN_VERSION_KEY, clean)
  } catch {
    // 受限 WebView 下允许忽略持久化异常
  }
}

export function readSeenFeatures(): Set<string> {
  try {
    if (typeof localStorage === 'undefined') return new Set()
    const raw = localStorage.getItem(WHATS_NEW_SEEN_FEATURES_KEY)
    if (!raw) return new Set()
    const parsed = JSON.parse(raw) as unknown
    if (Array.isArray(parsed)) {
      return new Set(parsed.filter((x): x is string => typeof x === 'string'))
    }
    return new Set()
  } catch {
    return new Set()
  }
}

export function isFeatureSeen(featureId: string): boolean {
  // 新装用户未曾经过任何更新周期时，若已种下当前版本且从未记录过 seenFeatures？
  // 这里用显式集合存储已点开过的功能，进入页面或点击即消除 NEW 徽标。
  return readSeenFeatures().has(featureId)
}

export function markFeatureSeen(featureId: string): Set<string> {
  const set = readSeenFeatures()
  if (set.has(featureId)) return set
  set.add(featureId)
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(WHATS_NEW_SEEN_FEATURES_KEY, JSON.stringify([...set]))
    }
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('maskit:feature_seen', { detail: { id: featureId } }))
    }
  } catch {
    // 忽略受限存储异常
  }
  return set
}

export function hasUnseenNavFeature(navId: string, seenFeatures: Set<string>): boolean {
  return WHATS_NEW_ITEMS.some((item) => item.navId === navId && !seenFeatures.has(item.id))
}

let pendingSpotlight: SpotlightPayload | null = null

export function triggerFeatureSpotlight(payload: SpotlightPayload): void {
  pendingSpotlight = payload
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('maskit:spotlight', { detail: payload }))
  }
}

export function consumePendingSpotlight(): SpotlightPayload | null {
  const cur = pendingSpotlight
  pendingSpotlight = null
  return cur
}
