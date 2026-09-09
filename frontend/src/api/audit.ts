/**
 * 审计 API（真实后端契约：/api/audit/*）
 * - /api/audit/events 返回 {events, count}
 * - /api/audit/run 需要 confirm=true 二次确认（探针消耗 token）
 */
import { shieldFetch } from '@/lib/shield-fetch'
import type { AuditEventsResponse, AuditJob } from '@/types/api'

export function getAuditEvents(since = 0, limit = 500): Promise<AuditEventsResponse> {
  return shieldFetch<AuditEventsResponse>(
    `/api/audit/events?since=${since}&limit=${limit}`,
  )
}

export function getAuditJob(): Promise<AuditJob> {
  return shieldFetch<AuditJob>('/api/audit/job')
}

export interface RunAuditOptions {
  confirm?: boolean
  upstream_name?: string
  model?: string
  profile?: string
}

export function runAudit(opts: RunAuditOptions = {}): Promise<{ ok: boolean; error?: string }> {
  return shieldFetch('/api/audit/run', {
    method: 'POST',
    body: JSON.stringify({
      confirm: opts.confirm ?? true,
      ...(opts.upstream_name ? { upstream_name: opts.upstream_name } : {}),
      ...(opts.model ? { model: opts.model } : {}),
      ...(opts.profile ? { profile: opts.profile } : {}),
    }),
  })
}

export function cancelAudit(): Promise<{ ok: boolean }> {
  return shieldFetch('/api/audit/cancel', { method: 'POST' })
}

export function clearAudit(): Promise<{ ok: boolean }> {
  return shieldFetch('/api/audit/clear', { method: 'POST' })
}

export function getAuditReport(): Promise<{ ok: boolean; report?: string; error?: string }> {
  return shieldFetch('/api/audit/report/latest')
}
