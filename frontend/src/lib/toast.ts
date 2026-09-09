/**
 * 轻量 toast（无外部依赖，替代 sonner——保持依赖面最小）
 * 全局单例挂载点：#toastHost
 */
type ToastKind = 'default' | 'error' | 'success'

let host: HTMLElement | null = null

function ensureHost(): HTMLElement {
  if (!host) {
    host = document.createElement('div')
    host.id = 'shield-toast-host'
    host.className =
      'fixed top-16 right-5 z-[200] flex flex-col gap-2 pointer-events-none'
    document.body.appendChild(host)
  }
  return host
}

export function toast(message: string, kind: ToastKind = 'success', duration = 2500) {
  const el = document.createElement('div')
  const color =
    kind === 'error'
      ? 'text-destructive border-destructive/30'
      : kind === 'success'
        ? 'text-foreground border-border'
        : 'text-foreground border-border'
  el.className = `pointer-events-auto flex items-center gap-2 rounded-lg border bg-card px-3.5 py-2.5 text-sm shadow-lg animate-[toast-in_0.2s_ease] ${color}`
  el.textContent = message
  ensureHost().appendChild(el)
  setTimeout(() => {
    el.style.opacity = '0'
    el.style.transition = 'opacity 0.2s'
    setTimeout(() => el.remove(), 220)
  }, duration)
}
