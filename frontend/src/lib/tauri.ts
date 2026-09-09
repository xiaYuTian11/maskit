/**
 * Tauri 壳层 IPC 封装（方案 §4.2）
 * - get_shield_token：从 Rust 读引擎 proxy_token（内存态，不进 HTML）
 * - engine_state：引擎就绪/崩溃状态（§4.7）
 */
import { invoke } from '@tauri-apps/api/core'
import { shieldFetch } from './shield-fetch'

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

/**
 * 检查更新。
 * 约定：网络/服务端异常返回 ok=false 而不是抛异常——检查更新失败不该弹错误框打断用户。
 */
export async function checkUpdate(): Promise<UpdateCheck> {
  return await invoke<UpdateCheck>('check_update')
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

