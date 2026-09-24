/**
 * Tauri 壳层 IPC 封装（方案 §4.2）
 * - get_shield_token：从 Rust 读引擎 proxy_token（内存态，不进 HTML）
 * - engine_state：引擎就绪/崩溃状态（§4.7）
 */
import { invoke } from '@tauri-apps/api/core'
import { isTauri, shieldFetch, ShieldApiError } from './shield-fetch'

export interface EngineState {
  ready: boolean
  port: number
  started_at: string | null
  pid: number | null
  last_error: string | null
}

export async function getShieldToken(): Promise<string> {
  const token = await invoke<string>('get_shield_token')
  return token || ''
}

export async function getEngineState(): Promise<EngineState> {
  return await invoke<EngineState>('engine_state')
}

export async function restartEngine(): Promise<{ ok: boolean; error?: string }> {
  return await invoke('restart_engine')
}

/** 开机自启（Rust 写 winreg 指向壳 exe；再调 panel /api/autostart 同步 config） */
export async function setAutostartTauri(enabled: boolean): Promise<boolean> {
  const ok = await invoke<boolean>('set_autostart', { enabled })
  // 同步 panel config（panel 在引擎 sidecar 模式下只更新 config.json，不覆盖 reg）
  try {
    await shieldFetch('/api/autostart', { method: 'POST', body: JSON.stringify({ enabled }) })
  } catch (e) {
    // panel 不可用时 reg 已写，config 下次面板启动会从 reg 读回
    console.warn('[tauri] 同步 autostart 到 panel 失败(忽略):', e)
  }
  return ok
}

/** 检查更新：Rust 侧 check_update 命令在开源配签名密钥后启用，
 *  当前不注册（避免 invoke 报 Command not found），UI 入口提示『开源后启用』。 */

// ========== 在线更新 ==========

export interface UpdateCheck {
  ok: boolean
  has_update: boolean
  version?: string
  current_version?: string
  notes?: string
  pub_date?: string
  error?: string
}

export interface UpdateProgress {
  event: 'started' | 'progress' | 'finished'
  version?: string
  downloaded?: number
  total?: number | null
}

function compareSemver(a: string, b: string): number {
  const pa = a.replace(/^v/, '').split('.').map((x) => parseInt(x, 10) || 0)
  const pb = b.replace(/^v/, '').split('.').map((x) => parseInt(x, 10) || 0)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] ?? 0
    const nb = pb[i] ?? 0
    if (na > nb) return 1
    if (na < nb) return -1
  }
  return 0
}

/** 浏览器直连 GitHub API 探测最新版本（超时 8s）。
 *
 * 为什么保留浏览器直连：出网能力到底属于谁，取决于部署环境——
 *  - 浏览器能上 GitHub、服务器不能（国内服务器 + 用户本地有代理）→ 必须走这条；
 *  - 浏览器不能、服务器能（内网/离线终端 + 服务器有出口）→ 由下面的服务端代理兜底。
 * 两种环境都存在，所以两条路都要留着，用「先直连、失败再问服务器」的顺序覆盖。
 *
 * 注意：这条 fetch 需要面板 CSP 的 `connect-src` 放行 api.github.com
 * （见 engine/panel.py `security_headers`）。CSP 拦截在 Firefox 里抛的正是
 * `TypeError: NetworkError when attempting to fetch resource.`，
 * 与真的网络不通表现一致，排查时容易误判成「网络问题」。
 *
 * 报错文案只说「更新服务」不写 GitHub：这条路径失败后还会退到服务端探测，
 * 两个源都可能失败。写死 "GitHub API HTTP xxx" 会在服务端失败时把人引向
 * 错误方向——实测踩过这个坑（请求压根没到 GitHub，文案却说是 GitHub 的问题）。
 */
async function fetchLatestFromGitHub(): Promise<{ version?: string; notes?: string; pub_date?: string }> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 8000)
  try {
    const resp = await fetch('https://api.github.com/repos/xiaYuTian11/maskit/releases/latest', {
      headers: { Accept: 'application/vnd.github.v3+json' },
      signal: controller.signal,
    })
    if (!resp.ok) throw new Error(`更新服务返回 HTTP ${resp.status}`)
    const d = (await resp.json()) as { tag_name?: string; body?: string; published_at?: string }
    return { version: d.tag_name, notes: d.body, pub_date: d.published_at }
  } finally {
    clearTimeout(timeout)
  }
}

/**
 * 检查更新。
 * 桌面端（Tauri）走 Rust Updater 插件并校验签名；
 * Web / Docker 容器端先由浏览器直连 GitHub API，失败再问本机引擎
 * `/api/update/check`（服务端出网探测），覆盖「浏览器能通/服务器能通」两种部署环境。
 * 约定：网络/服务端异常返回 ok=false 而不是抛异常——检查更新失败不该弹错误框打断用户。
 */
export async function checkUpdate(currentVersion?: string): Promise<UpdateCheck> {
  if (isTauri()) {
    try {
      return await invoke<UpdateCheck>('check_update')
    } catch (e) {
      return { ok: false, has_update: false, error: String(e) }
    }
  }

  try {
    let curVer = currentVersion
    if (!curVer) {
      try {
        const st = await shieldFetch<{ version: string }>('/api/status', { noToken: false })
        curVer = st.version
      } catch {
        curVer = ''
      }
    }

    // 先试浏览器直连（用户的浏览器能上 GitHub 时最直接、不占服务器出口），
    // 失败再退到服务端代理（服务器能上 GitHub、浏览器不能时兜底）。
    let data: { version?: string; notes?: string; pub_date?: string }
    let browserErr = ''
    try {
      data = await fetchLatestFromGitHub()
    } catch (e) {
      browserErr = e instanceof Error ? e.message : String(e)
      try {
        data = await shieldFetch<{ version?: string; notes?: string; pub_date?: string }>(
          '/api/update/check',
          { timeoutMs: 20000 }, // 比服务端 15s 探测超时略宽，让服务端先给出可读错误
        )
      } catch (e2) {
        // 两边都失败。若浏览器侧拿到的是明确 HTTP 状态（如 403 限流），那比
        // 「连不上」更有诊断价值——GitHub 其实是通的，只是限流了——优先报它。
        // 否则报服务端那句可读原因（shieldFetch 对非 2xx 抛 ShieldApiError，
        // 取 body 里的 error 字段，避免把整段 JSON 丢给用户）。
        let serverErr = String(e2)
        if (e2 instanceof ShieldApiError && e2.body) {
          try {
            const parsed = JSON.parse(e2.body)
            if (parsed && typeof parsed.error === 'string' && parsed.error) serverErr = parsed.error
          } catch {
            serverErr = e2.message || serverErr
          }
        }
        return {
          ok: false,
          has_update: false,
          error: /HTTP \d{3}/.test(browserErr) ? browserErr : serverErr,
        }
      }
    }

    const latestTag = String(data.version || '').trim()
    const cleanLatest = latestTag.replace(/^v/, '')
    const cleanCur = (curVer || '').replace(/^v/, '')
    const hasUpdate = Boolean(cleanLatest && cleanCur && compareSemver(cleanLatest, cleanCur) > 0)

    return {
      ok: true,
      has_update: hasUpdate,
      version: latestTag,
      current_version: curVer ? `v${cleanCur}` : undefined,
      notes: data.notes || '',
      pub_date: data.pub_date,
    }
  } catch (e) {
    return { ok: false, has_update: false, error: String(e) }
  }
}

/** 下载并安装更新，完成后应用自动重启（调用后本进程即将退出，不要期待返回值）。 */
export async function installUpdate(): Promise<void> {
  await invoke('install_update')
}

/** 订阅下载进度。返回取消订阅函数。 */
export async function onUpdateProgress(cb: (p: UpdateProgress) => void): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event')
  const un = await listen<UpdateProgress>('update://progress', (e) => cb(e.payload))
  return un
}

/** 同步代理运行状态到系统托盘菜单（运行中显示「停止代理」，已停止显示「启动代理」） */
export async function updateTrayProxyStatus(running: boolean): Promise<void> {
  try {
    await invoke('update_tray_proxy_status', { running })
  } catch {
    // 浏览器调试或非 Tauri 环境静默忽略
  }
}

