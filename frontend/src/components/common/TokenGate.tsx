/**
 * 浏览器模式登录门（Docker / 无头部署）。
 *
 * 桌面版 token 由 Tauri 壳经 IPC 下发，用户永远看不到这一页；只有 SPA 直接跑在
 * 浏览器里且拿不到 token 时才渲染。token 来自引擎启动日志（docker logs）或
 * MASKIT_PANEL_TOKEN 环境变量，输入后存本 tab 的 sessionStorage。
 */
import { useState, type FormEvent } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Logo } from '@/components/brand/Logo'
import { useI18n } from '@/lib/i18n'
import { saveBrowserToken, shieldFetch } from '@/lib/shield-fetch'
import { useAuthStore } from '@/stores/authStore'

export function TokenGate() {
  const { t } = useI18n()
  const setToken = useAuthStore((s) => s.setToken)
  const [value, setValue] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const token = value.trim()
    if (!token) return
    setBusy(true)
    setError('')
    // 先探一次 /api/status 验证 token，错了不进主界面（否则每个页面都会报 403）
    try {
      await shieldFetch('/api/status', { headers: { 'X-Shield-Token': token } })
      saveBrowserToken(token)
      setToken(token)
    } catch {
      setError(t('tokenGate.invalid'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-lg border bg-card p-6 shadow-sm">
        <div className="flex items-center gap-2">
          <Logo className="h-6 w-6" />
          <span className="text-sm font-semibold">{t('tokenGate.title')}</span>
        </div>
        <p className="text-xs text-muted-foreground">{t('tokenGate.desc')}</p>
        <Input
          type="password"
          autoFocus
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={t('tokenGate.placeholder')}
        />
        {error && <p className="text-xs text-red-600 dark:text-red-400">{error}</p>}
        <Button type="submit" className="w-full" disabled={busy || !value.trim()}>
          {t('tokenGate.submit')}
        </Button>
      </form>
    </div>
  )
}
