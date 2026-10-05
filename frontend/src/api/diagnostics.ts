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
import { getI18nLang } from '@/lib/i18n'

export interface DiagnosticsBundle {
  schema: number
  generated_at: number
  masked: boolean
  fatal?: string
  app?: Record<string, unknown>
  proxy?: Record<string, unknown>
  /** schema 2 起内嵌：结论给人看、证据给维护者，同一个文件。 */
  selfcheck?: SelfCheckResult
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
  // 结论跟界面语言走：包里内嵌的自检结论应与用户看到的同语言（与 saveDiagnostics 对齐）。
  return shieldFetch('/api/diagnostics?lang=' + encodeURIComponent(getI18nLang()))
}

export function saveDiagnostics(previewId?: string): Promise<{ ok: boolean; path?: string; size?: number; error?: string }> {
  // 结论跟界面语言走：英文界面导出的诊断包里不该出现中文结论。
  return shieldFetch('/api/diagnostics/save?lang=' + encodeURIComponent(getI18nLang()), {
    method: 'POST', timeoutMs: 30000,
    ...(previewId ? { body: JSON.stringify({ preview_id: previewId }) } : {}),
  })
}

/** Immutable preview snapshot, held locally for ten minutes; exports use these bytes. */
export interface DiagnosticPreview {
  ok: boolean
  id: string
  body: string
  size: number
  generated_at: number
  expires_at: number
}

export function previewDiagnostics(): Promise<DiagnosticPreview> {
  return shieldFetch('/api/diagnostics/preview?lang=' + encodeURIComponent(getI18nLang()), {
    method: 'POST', timeoutMs: 30000,
  })
}

/** 一键自检结论（§16）。与诊断包的分工：这里是**结论**，诊断包是**原始证据**。 */
export interface SelfCheckFinding {
  id: string
  severity: 'high' | 'medium' | 'low' | 'ok'
  title: string
  evidence: string
  action: string
  /** false = 数据不足，界面必须标出来（不要当成"没问题"） */
  verified?: boolean
}

export interface SelfCheckResult {
  schema: number
  generated_at: number
  overall: 'high' | 'medium' | 'ok'
  /** 一句话结论：设计成能直接复制给别人看 */
  summary_line: string
  findings: SelfCheckFinding[]
  fired_ids?: string[]
  ok_items?: { id: string; note: string }[]
  input_errors?: { rule?: string; source?: string; error: string }[]
}

export interface SelfCheckResponse {
  ok: boolean
  selfcheck?: SelfCheckResult
  engine_metrics_stale?: boolean
  error?: string
}

/** 跑一次自检（只读；不产生任何外发请求）。 */
export function runSelfCheck(): Promise<SelfCheckResponse> {
  return shieldFetch<SelfCheckResponse>('/api/selfcheck?lang=' + encodeURIComponent(getI18nLang()))
}
