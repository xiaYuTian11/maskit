/** 文件脱敏工作台 API（T4）：所有请求经 shieldFetch，不直连 fetch。 */
import { shieldFetch } from '@/lib/shield-fetch'

export interface FilesCapabilities {
  ok: boolean
  enabled: boolean
  carriers: string[]
  extensions: string[]
  text_extensions: string[]
  path_source: boolean
  max_size_mb: number
  max_text_mb: number
}

export interface FileJobView {
  id: string
  status: string
  carrier: string
  filename: string
  size: number
  page_count?: number | null
  mode?: string
  progress?: Record<string, unknown>
  coverage?: Record<string, unknown>
  warnings?: string[]
  hit_count?: number
  position?: number | null
  error?: string
  created_at?: number
  expires_at?: number
}

export interface FileHitView {
  hit_id: string
  token: string
  label: string
  source: string
  count: number
  locations: string[]
  editable: boolean
  can_keep: boolean
  original?: string
  preview?: string
  digest?: string
}

export interface TextEdit {
  hit_id: string
  action: 'replace' | 'keep'
  text?: string
}

export interface Redaction {
  id: string
  page: number
  kind: 'rect' | 'path' | 'full'
  rect?: [number, number, number, number]
  points?: [number, number][]
  width?: number
  source: 'auto' | 'manual'
  label?: string
}

export interface ApplyOptions {
  clear_docinfo?: boolean
  keep_embedded_objects?: boolean
  keep_attachments?: boolean
  keep_icc?: boolean
}

type Json<T> = T & { ok: boolean }

export function getCapabilities() {
  return shieldFetch<Json<FilesCapabilities>>('/api/files/capabilities')
}

export function listJobs() {
  return shieldFetch<Json<{ jobs: FileJobView[] }>>('/api/files/jobs')
}

export function getJob(id: string) {
  return shieldFetch<Json<{ job: FileJobView }>>(`/api/files/jobs/${id}`)
}

export function createJob(file: File) {
  const form = new FormData()
  form.append('file', file, file.name)
  return shieldFetch<Json<{ job: FileJobView }>>('/api/files/jobs', { method: 'POST', body: form })
}

export function scanJob(id: string, mode: 'manual' | 'auto') {
  return shieldFetch<Json<{ job: FileJobView }>>(`/api/files/jobs/${id}/scan`, {
    method: 'POST',
    body: JSON.stringify({ mode }),
  })
}

export function getHits(id: string) {
  return shieldFetch<Json<{ hits: FileHitView[] }>>(`/api/files/jobs/${id}/hits`)
}

export function getPreview(id: string, page: number) {
  return shieldFetch<Json<{ data: string }>>(`/api/files/jobs/${id}/preview?page=${page}`)
}

export function applyJob(
  id: string,
  edits: TextEdit[],
  redactions: Redaction[],
  options: ApplyOptions,
) {
  return shieldFetch<Json<{ job: FileJobView }>>(`/api/files/jobs/${id}/apply`, {
    method: 'POST',
    body: JSON.stringify({ edits, redactions, options }),
  })
}

export function cancelJob(id: string) {
  return shieldFetch<Json<{ job: FileJobView }>>(`/api/files/jobs/${id}/cancel`, { method: 'POST' })
}

export function deleteJob(id: string) {
  return shieldFetch<Json<{ deleted: boolean }>>(`/api/files/jobs/${id}`, { method: 'DELETE' })
}

/** 一次性 nonce → raw 下载 → blob 触发浏览器保存（token 不进 URL）。 */
export async function downloadJob(id: string, filename: string) {
  const res = await shieldFetch<{ ok: boolean; url: string }>(`/api/files/jobs/${id}/nonce`, {
    method: 'POST',
  })
  const raw = await shieldFetch<Response>(res.url, { raw: true, timeoutMs: 0 })
  const blob = await raw.blob()
  const href = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = href
  a.download = filename || 'masked'
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(href)
}
