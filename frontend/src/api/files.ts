/** 文件脱敏工作台 API（T4）：所有请求经 shieldFetch，不直连 fetch。 */
import { isTauri, shieldFetch } from '@/lib/shield-fetch'

export interface FilesCapabilities {
  ok: boolean
  enabled: boolean
  carriers: string[]
  extensions: string[]
  text_extensions: string[]
  ocr_available?: boolean
  path_source: boolean
  max_size_mb: number
  max_text_mb: number
  queue_max?: number
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
  batch_id?: string
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

export interface MergedHitFileRef {
  job_id: string
  filename: string
  hit_id: string
  count: number
}

export interface MergedFileHitView {
  merge_id: string
  label: string
  source: string
  count: number
  locations: string[]
  editable: boolean
  can_keep: boolean
  original?: string
  preview?: string
  digest?: string
  files: MergedHitFileRef[]
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

export interface PreviewBox {
  id: string
  kind: 'rect' | 'full'
  rect?: [number, number, number, number]
  source: string
  label?: string
  hit_id?: string
  can_dismiss?: boolean
}

export interface ApplyOptions {
  clear_docinfo?: boolean
  keep_embedded_objects?: boolean
  keep_attachments?: boolean
  keep_icc?: boolean
  strip_non_image_media?: boolean
  dismissed_boxes?: string[]
}

export interface FileHistoryEntry {
  id: string
  ts: number
  name_preview: string
  ext: string
  size: number
  carrier: string
  mode: string
  status: string
  hit_count: number
  page_count?: number | null
  cost_ms: number
  error?: string
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

export function createJob(file: File, batchId?: string) {
  const form = new FormData()
  form.append('file', file, file.name)
  if (batchId) form.append('batch_id', batchId)
  return shieldFetch<Json<{ job: FileJobView }>>('/api/files/jobs', {
    method: 'POST',
    body: form,
    timeoutMs: 0,
  })
}

export function createJobFromPath(path: string, batchId?: string) {
  return shieldFetch<Json<{ job: FileJobView }>>('/api/files/jobs', {
    method: 'POST',
    body: JSON.stringify(batchId ? { path, batch_id: batchId } : { path }),
    timeoutMs: 0,
  })
}

export function scanJob(id: string, mode: 'manual' | 'auto') {
  return shieldFetch<Json<{ job: FileJobView }>>(`/api/files/jobs/${id}/scan`, {
    method: 'POST',
    body: JSON.stringify({ mode }),
  })
}

export function getHits(id: string) {
  return shieldFetch<Json<{ hits: FileHitView[] }>>(`/api/files/jobs/${id}/hits`, {
    timeoutMs: 120000,
  })
}

export function getMergedHits(jobIds: string[]) {
  return shieldFetch<Json<{ hits: MergedFileHitView[]; job_count: number; total_occurrences: number }>>(
    '/api/files/hits/merged',
    {
      method: 'POST',
      body: JSON.stringify({ job_ids: jobIds }),
      timeoutMs: 120000,
    },
  )
}

export function getPreview(id: string, page: number) {
  return shieldFetch<Json<{ data: string; boxes?: PreviewBox[] }>>(
    `/api/files/jobs/${id}/preview?page=${page}`,
    { timeoutMs: 120000 },
  )
}

export function saveJob(id: string, destDir: string, overwrite = false) {
  return shieldFetch<Json<{ path: string }>>(`/api/files/jobs/${id}/save`, {
    method: 'POST',
    body: JSON.stringify({ dest_dir: destDir, overwrite }),
    timeoutMs: 120000,
  })
}

export function listHistory() {
  return shieldFetch<Json<{ history: FileHistoryEntry[] }>>('/api/files/history')
}

export function isDesktopApp(): boolean {
  return isTauri()
}

export async function pickDesktopDirectory(): Promise<string | null> {
  if (!isTauri()) return null
  const { open } = await import('@tauri-apps/plugin-dialog')
  const picked = await open({ directory: true, multiple: false })
  return typeof picked === 'string' && picked ? picked : null
}

export async function pickDesktopFile(extensions: string[]): Promise<string | null> {
  if (!isTauri()) return null
  const { open } = await import('@tauri-apps/plugin-dialog')
  const picked = await open({
    directory: false,
    multiple: false,
    filters: extensions.length ? [{ name: 'Files', extensions }] : undefined,
  })
  return typeof picked === 'string' && picked ? picked : null
}

export async function pickDesktopFiles(extensions: string[]): Promise<string[]> {
  if (!isTauri()) return []
  const { open } = await import('@tauri-apps/plugin-dialog')
  const picked = await open({
    directory: false,
    multiple: true,
    filters: extensions.length ? [{ name: 'Files', extensions }] : undefined,
  })
  if (Array.isArray(picked)) {
    return picked.filter((p): p is string => typeof p === 'string' && p.length > 0)
  }
  return typeof picked === 'string' && picked ? [picked] : []
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

export async function downloadJobsZip(jobIds: string[], filename = 'maskit-masked-files.zip') {
  const raw = await shieldFetch<Response>('/api/files/export-zip', {
    method: 'POST',
    body: JSON.stringify({ job_ids: jobIds }),
    raw: true,
    timeoutMs: 0,
  })
  const blob = await raw.blob()
  const href = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = href
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(href)
}
