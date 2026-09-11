/**
 * Data Maskit 统一 API 客户端
 *
 * 规则（方案 §13.3）：
 * - 所有请求必须过 shieldFetch，禁止页面直接 fetch/axios
 * - Tauri 下走 @tauri-apps/plugin-http（Rust reqwest 代发，绕开浏览器 CORS）
 * - 浏览器 dev 模式（无 Tauri 时）回退 window.fetch
 * - token 从 authStore 内存取（启动时 IPC get_shield_token 调一次）
 */
import { useAuthStore } from '@/stores/authStore'
import { getShieldToken } from '@/lib/tauri'

/** 引擎 API 端口（默认 panel.py PANEL_PORT=5801；测试时由 SHIELD_ENGINE_PORT 覆盖，经 engine_state IPC 下发） */
let enginePort = 5801

export function initEnginePort(port: number) {
  if (port > 0 && port < 65536) enginePort = port
}

function engineBase(): string {
  // 浏览器生产态（Docker / 无头部署）：SPA 由 panel.py 同源托管，直接用当前 origin，
  // 否则远程用户的浏览器会去请求他自己电脑上的 127.0.0.1。
  // Tauri 与 vite dev（5173 端口）仍指向本机引擎端口。
  if (!isTauri() && !import.meta.env.DEV && typeof window !== 'undefined') {
    return window.location.origin
  }
  return `http://127.0.0.1:${enginePort}`
}

/** 是否运行在 Tauri 环境 */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
}

export class ShieldApiError extends Error {
  status: number
  body: string
  code?: string

  constructor(status: number, body: string, message?: string, code?: string) {
    super(message || `HTTP ${status}: ${body.slice(0, 200)}`)
    this.status = status
    this.body = body
    this.code = code
  }
}

interface ShieldFetchOptions extends RequestInit {
  /** 不注入 token（极少数公开端点用） */
  noToken?: boolean
  /** 返回原始 Response（导出下载等场景） */
  raw?: boolean
}

export async function shieldFetch<T>(
  url: string,
  options: ShieldFetchOptions = {},
): Promise<T> {
  const { noToken, raw, ...rest } = options
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(rest.headers as Record<string, string> | undefined),
  }
  if (!noToken) {
    const token = useAuthStore.getState().token
    if (token) headers['X-Shield-Token'] = token
  }

  let resp: Response
  if (isTauri()) {
    // Rust reqwest 代发，无浏览器 CORS
    const { fetch: tauriFetch } = await import('@tauri-apps/plugin-http')
    resp = await tauriFetch(`${engineBase()}${url}`, { ...rest, headers })
  } else {
    resp = await window.fetch(`${engineBase()}${url}`, { ...rest, headers })
  }

  if (!resp.ok) {
    const body = await resp.text().catch(() => '')
    let errCode: string | undefined
    try {
      const parsed = JSON.parse(body)
      if (parsed && typeof parsed.error === 'string') {
        errCode = parsed.error
      }
    } catch {
      // 非 JSON 响应忽略解析
    }

    // 浏览器模式 403：若是令牌错误/过期，清掉本 tab 保存的 token 让 App 重新弹出输入框；
    // 若是因为反向代理 Origin 校验拦截 (origin_rejected)，绝不清空 token，避免死锁踢出！
    if (resp.status === 403 && !options.noToken && !isTauri()) {
      if (errCode === 'invalid_token' || (!errCode && !body.includes('origin_rejected'))) {
        clearBrowserToken()
        useAuthStore.getState().setToken('')
      }
    }
    if (errCode === 'origin_rejected' && typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('shield:origin_rejected'))
    }
    // 403：引擎重启后 token 过期，自动重读一次再试（时序竞态兜底）
    if (resp.status === 403 && !options.noToken && isTauri()) {
      try {
        const fresh = await getShieldToken()
        if (fresh) {
          useAuthStore.getState().setToken(fresh)
          headers['X-Shield-Token'] = fresh
          const retry = await (isTauri()
            ? (await import('@tauri-apps/plugin-http')).fetch(`${engineBase()}${url}`, { ...rest, headers })
            : window.fetch(`${engineBase()}${url}`, { ...rest, headers }))
          if (retry.ok) {
            if (raw) return retry as unknown as T
            return (await retry.json()) as T
          }
          const retryBody = await retry.text().catch(() => '')
          throw new ShieldApiError(retry.status, retryBody, undefined, errCode)
        }
      } catch {
        // 重读失败走原错误
      }
    }
    throw new ShieldApiError(resp.status, body, undefined, errCode)
  }
  if (raw) return resp as unknown as T
  return (await resp.json()) as T
}

/**
 * 浏览器模式 token 存取（Docker / 无头部署）。
 * 只用 sessionStorage：关 tab 即失效，避免共享机器上长期留存；Tauri 模式不走这里。
 */
const BROWSER_TOKEN_KEY = 'shield_token'

export function readBrowserToken(): string {
  try { return sessionStorage.getItem(BROWSER_TOKEN_KEY) || '' } catch { return '' }
}

export function saveBrowserToken(token: string) {
  try { sessionStorage.setItem(BROWSER_TOKEN_KEY, token) } catch { /* 隐私模式等场景忽略 */ }
}

export function clearBrowserToken() {
  try { sessionStorage.removeItem(BROWSER_TOKEN_KEY) } catch { /* ignore */ }
}

/** 引擎是否就绪（TCP 探测由 Rust 侧负责；此处按需轮询状态接口即可） */
export function engineBaseUrl(): string {
  return engineBase()
}
