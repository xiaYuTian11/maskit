/**
 * 诊断包 API。
 *
 * 存在的理由：崩溃现场、端口占用、错误事件本来就写在数据目录里，
 * 但用户不知道，报障时只剩一句「用不了」。
 *
 * 隐私约束（与 panel._diagnostics_payload 一致，改动必须同步）：
 * 包里不含任何还原正文、凭据或词库内容；日志与崩溃现场已过打码。
 * **不做自动上报**——生成后由用户预览、自己决定发不发。
 */
import { shieldFetch } from '@/lib/shield-fetch'

export interface DiagnosticsBundle {
  schema: number
  generated_at: number
  masked: boolean
  fatal?: string
  app?: Record<string, unknown>
  proxy?: Record<string, unknown>
  ports?: unknown
  upstreams?: unknown[]
  settings?: Record<string, unknown>
  license?: Record<string, unknown>
  recent_errors?: unknown
  recent_error_count?: number
  stats_today?: Record<string, unknown>
  crash_dumps?: unknown
  log_tail?: string[]
}

export function getDiagnostics(): Promise<DiagnosticsBundle> {
  return shieldFetch('/api/diagnostics')
}

export function saveDiagnostics(): Promise<{ ok: boolean; path?: string; size?: number; error?: string }> {
  return shieldFetch('/api/diagnostics/save', { method: 'POST' })
}
