/**
 * 代理相关 API（真实后端契约：/api/status /api/proxy/start /api/proxy/stop）
 */
import { shieldFetch } from '@/lib/shield-fetch'
import type { ProxyStatus } from '@/types/api'

export function getStatus(): Promise<ProxyStatus> {
  return shieldFetch<ProxyStatus>('/api/status', { noToken: false })
}

export function startProxy(): Promise<{ ok: boolean; message?: string; error?: string }> {
  return shieldFetch('/api/proxy/start', { method: 'POST', timeoutMs: 70000 })
}

export function stopProxy(): Promise<{ ok: boolean; error?: string }> {
  return shieldFetch('/api/proxy/stop', { method: 'POST', timeoutMs: 30000 })
}

export function dismissAutoRecover(): Promise<{ ok: boolean }> {
  return shieldFetch('/api/auto_recover/dismiss', { method: 'POST' })
}
