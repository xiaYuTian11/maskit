/** Local ingress evidence; observing a request does not authenticate a host process. */
import { shieldFetch } from '@/lib/shield-fetch'

export interface Verification {
  ok: boolean
  id?: string
  ingress?: 'proxy' | 'ext'
  upstream?: string
  mode?: 'marker' | 'window'
  status: 'idle' | 'pending' | 'observed' | 'expired' | 'stale'
  marker?: string | null
  started_at?: number
  expires_at?: number
  evidence?: { seq: number; ts: number; sid?: string; decision?: string; completeness?: string }
}

export function getVerification(): Promise<Verification> {
  return shieldFetch('/api/onboarding/verification')
}

export function startVerification(ingress: 'proxy' | 'ext', upstream: string, mode: 'marker' | 'window'): Promise<Verification> {
  return shieldFetch('/api/onboarding/verification', {
    method: 'POST', body: JSON.stringify({ ingress, upstream, mode }),
  })
}
