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
import { saveBrowserToken, shieldFetch, ShieldApiError } from '@/lib/shield-fetch'
import { emergencyDisableOriginCheck } from '@/api/settings'
import { useAuthStore } from '@/stores/authStore'

export function TokenGate() {
  const { t } = useI18n()
  const setToken = useAuthStore((s) => s.setToken)
  const [value, setValue] = useState('')
  const [error, setError] = useState('')
  const [originRejected, setOriginRejected] = useState(false)
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const token = value.trim()
    if (!token) return
    setBusy(true)
    setError('')
    setOriginRejected(false)
    // 先探一次 /api/status 验证 token，错了不进主界面（否则每个页面都会报 403）
    try {
      await shieldFetch('/api/status', { headers: { 'X-Shield-Token': token } })
      saveBrowserToken(token)
      setToken(token)
    } catch (err: unknown) {
      if (err instanceof ShieldApiError && err.code === 'origin_rejected') {
        setOriginRejected(true)
      } else {
        setError(t('tokenGate.invalid'))
      }
    } finally {
      setBusy(false)
    }
  }

  const handleDisableOriginAndLogin = async () => {
    const token = value.trim()
    if (!token) return
    setBusy(true)
    setError('')
    try {
      await emergencyDisableOriginCheck(token)
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
          onChange={(e) => {
            setValue(e.target.value)
            setOriginRejected(false)
            setError('')
          }}
          placeholder={t('tokenGate.placeholder')}
        />
        {error && <p className="text-xs text-destructive-ink">{error}</p>}
        {originRejected && (
          <div className="space-y-2 rounded-md border border-warning/30 bg-warning/10 p-3 text-xs text-warning-ink">
            <p>{t('tokenGate.originMismatch')}</p>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="w-full border-warning/40 text-warning-ink hover:bg-warning/20"
              onClick={handleDisableOriginAndLogin}
              disabled={busy}
            >
              {busy ? t('tokenGate.disabling') : t('tokenGate.disableOriginAndLogin')}
            </Button>
          </div>
        )}
        <Button type="submit" className="w-full" disabled={busy || !value.trim()}>
          {t('tokenGate.submit')}
        </Button>
      </form>
    </div>
  )
}
