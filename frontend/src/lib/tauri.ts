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

/**
 * 检查更新。
 * 桌面端（Tauri）走 Rust Updater 插件并校验签名；
 * Web / Docker 容器端问本机引擎的 `/api/update/check`（服务端出网探测最新版本）。
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

  // 非 Tauri 桌面环境（Web 控制台 / Docker 容器部署）：由服务端探测最新版本。
  //
  // 这里**必须**走 shieldFetch 问自己的服务器，不能让浏览器直连 api.github.com：
  // 出网能力属于服务器，而国内用户/内网部署的浏览器到 GitHub 是不通的，
  // 直连会拿到 `TypeError: NetworkError when attempting to fetch resource.`。
  // 服务端按「自定义源 → 静态 latest.json → GitHub API」回退并归一化字段，
  // 前端只管读 version / notes / pub_date。
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

    let data: { version?: string; notes?: string; pub_date?: string }
    try {
      data = await shieldFetch<{ version?: string; notes?: string; pub_date?: string }>(
        '/api/update/check',
        { timeoutMs: 20000 }, // 比服务端 15s 探测超时略宽，让服务端先给出可读错误
      )
    } catch (e) {
      // 服务端探测失败返回 502 + 可读原因（shieldFetch 对非 2xx 抛 ShieldApiError）。
      // 把 body 里的 error 取出来展示，避免把 ShieldApiError 的整段 JSON 丢给用户。
      let msg = String(e)
      if (e instanceof ShieldApiError && e.body) {
        try {
          const parsed = JSON.parse(e.body)
          if (parsed && typeof parsed.error === 'string' && parsed.error) msg = parsed.error
        } catch {
          msg = e.message || msg
        }
      }
      return { ok: false, has_update: false, error: msg }
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

