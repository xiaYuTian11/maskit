/**
 * OCR 组件（可选运行时）控制面 API。
 *
 * 安装是**后台**执行的：`installOcrRuntime` 立即返回（202），UI 轮询
 * `getOcrRuntime().progress` 画进度条，结束后看 `last_error`。
 * 为什么不同步：组件 60~90MB，慢网下会先撞上请求超时——用户看到「失败」而引擎
 * 还在装，再点一次就是两个写者。
 */
import { shieldFetch } from '@/lib/shield-fetch'

export type OcrPhase = '' | 'manifest' | 'download' | 'verify' | 'extract' | 'selftest'

export interface OcrInstallProgress {
  active: boolean
  phase: OcrPhase
  /** 已下载字节 */
  bytes: number
  /** 总字节（服务端没给 Content-Length 时为 0） */
  total: number
  version: string
  started_at: number
}

export interface OcrLastError {
  /** 原因码（空串 = 最近一次安装没有失败） */
  reason: string
  detail: string
  /** 秒级时间戳；0 = 无 */
  at: number
}

export interface OcrRuntimeStatus {
  ok: boolean
  state: 'disabled' | 'installing' | 'enabled' | 'error'
  version: string
  path: string
  /** state=error 时的原因：component_missing / component_damaged */
  error: string
  /** component = 下载的组件；system = 系统预装（服务器/Docker）；空 = 不可用 */
  source: '' | 'component' | 'system'
  manifest_url: boolean
  root: string
  engine_available?: boolean
  progress?: OcrInstallProgress
  last_error?: OcrLastError
  /** 版本已切换，但进程里还是旧版（原生库无法热替换），重启后生效 */
  restart_required?: boolean
}

export function getOcrRuntime(): Promise<OcrRuntimeStatus> {
  return shieldFetch<OcrRuntimeStatus>('/api/ocr/runtime')
}

export interface OcrRuntimeUpdate {
  ok: boolean
  version: string
  current: string
  url: string
  sha256: string
  newer: boolean
}

/** 只查清单，不下载。 */
export function checkOcrRuntimeUpdate(): Promise<OcrRuntimeUpdate> {
  return shieldFetch<OcrRuntimeUpdate>('/api/ocr/runtime/check', { method: 'POST' })
}

/** 开始后台安装，立即返回当前状态（state=installing）。 */
export function installOcrRuntime(): Promise<OcrRuntimeStatus> {
  return shieldFetch<OcrRuntimeStatus>('/api/ocr/runtime/install', {
    method: 'POST',
    body: JSON.stringify({}),
  })
}

export function rollbackOcrRuntime(): Promise<OcrRuntimeStatus> {
  return shieldFetch<OcrRuntimeStatus>('/api/ocr/runtime/rollback', { method: 'POST' })
}

export function uninstallOcrRuntime(): Promise<OcrRuntimeStatus> {
  return shieldFetch<OcrRuntimeStatus>('/api/ocr/runtime/uninstall', { method: 'POST' })
}

/** 已知原因码（i18n 键 `settings.extBridge.ocrReason_<code>` 必须一一存在）。 */
export const OCR_REASON_CODES = [
  'manifest_missing',
  'manifest_invalid',
  'download_failed',
  'package_too_large',
  'checksum_mismatch',
  'package_path_unsafe',
  'package_symlink',
  'package_layout_invalid',
  'selftest_failed',
  'install_in_progress',
  'install_failed',
  'component_missing',
  'component_damaged',
  'no_previous_version',
  'not_installed',
  'platform_unsupported',
] as const

/** 进度百分比；拿不到总大小时返回 null（UI 画不定进度条）。 */
export function ocrProgressPercent(p?: OcrInstallProgress): number | null {
  if (!p || !p.active) return null
  if (p.phase === 'download') {
    return p.total > 0 ? Math.min(100, Math.round((p.bytes / p.total) * 100)) : null
  }
  if (p.phase === 'verify' || p.phase === 'extract' || p.phase === 'selftest') return 100
  return null
}

export function formatMiB(bytes: number): string {
  return (bytes / 1024 / 1024).toFixed(1)
}
