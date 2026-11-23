/**
 * 赞助轻提示（**非模态**，右下角小卡片）。
 *
 * 为什么不是启动弹窗 / 每日弹窗：
 *  - 启动弹窗直接打断「我今天要用它干活」这件事，换来的是卸载和差评，而不是打赏；
 *  - 每日弹窗等于每天提醒一次「你在薅我羊毛」，对 AGPL 项目的口碑是净损失；
 *  - 真正有效的时机是「用户已经获益之后」——所以这里用累计脱敏事件数当门槛。
 *
 * 节奏（用户可感知的三条）：
 *  1. **第 7 天**才第一次出现（且累计 MASK 事件 ≥ 300，真被保护过，不是刚装上就讨钱）
 *  2. 之后**每 30 天最多一次**（不是每天弹，也不是只弹一次就永别）
 *  3. **随时可永久关闭**：右上角 X 或「不再提示」都写 `off`，之后永不再出现
 *
 * 状态存 `localStorage.maskit_sponsor_nudge`（JSON: `{ off?: boolean, nextAt?: number }`）。
 * 兼容旧值 `off` 与 `snooze:<毫秒>`，避免升级后重复打扰。
 */
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Heart, X } from 'lucide-react'
import { getTodayStats } from '@/api/settings'
import { useI18n } from '@/lib/i18n'

const FIRST_SEEN_KEY = 'maskit_first_seen_at'
const STATE_KEY = 'maskit_sponsor_nudge'
const THRESHOLD_EVENTS = 300
const FIRST_DELAY_MS = 7 * 24 * 60 * 60 * 1000
const REPEAT_INTERVAL_MS = 30 * 24 * 60 * 60 * 1000

type NudgeState = { off?: boolean; nextAt?: number }

function readState(): NudgeState {
  try {
    const raw = localStorage.getItem(STATE_KEY) || ''
    if (!raw) return {}
    if (raw === 'off') return { off: true }
    if (raw.startsWith('snooze:')) return { nextAt: Number(raw.slice(7)) || 0 }
    const parsed = JSON.parse(raw) as unknown
    if (parsed && typeof parsed === 'object') return parsed as NudgeState
    return {}
  } catch {
    return { off: true } // 存储不可用就不打扰
  }
}

function writeState(next: NudgeState) {
  try {
    localStorage.setItem(STATE_KEY, JSON.stringify(next))
  } catch {}
}

export function SponsorNudge({ onSponsor }: { onSponsor: () => void }) {
  const { t, tf } = useI18n()
  const [visible, setVisible] = useState(false)
  const { data } = useQuery({
    queryKey: ['stats', 'today', 'sponsor-nudge'],
    queryFn: () => getTodayStats('30d'),
    staleTime: 5 * 60_000,
    retry: false,
  })

  // 首次启动时间：只写一次，用于「用了多久」的门槛
  useEffect(() => {
    try {
      if (!localStorage.getItem(FIRST_SEEN_KEY)) {
        localStorage.setItem(FIRST_SEEN_KEY, String(Date.now()))
      }
    } catch {}
  }, [])

  useEffect(() => {
    if (!data) return
    const state = readState()
    if (state.off) return
    if ((state.nextAt ?? 0) > Date.now()) return
    let firstSeen = 0
    try {
      firstSeen = Number(localStorage.getItem(FIRST_SEEN_KEY)) || 0
    } catch {}
    if (!firstSeen) return
    if (Date.now() - firstSeen < FIRST_DELAY_MS) return
    if ((data.mask_events || 0) < THRESHOLD_EVENTS) return

    // 出现即记账：本轮出现后 30 天内不再自动触发（用户即使不理会也不会被反复打扰）
    writeState({ ...state, nextAt: Date.now() + REPEAT_INTERVAL_MS })
    setVisible(true)
  }, [data])

  if (!visible) return null

  // 文案里放真实数字：用户看到「已有 12,557 次请求在发出前完成脱敏」时，
  // 获益是他自己算出来的，比你写十句「请支持」都有效。
  const maskLabel = (data?.mask_events ?? 0).toLocaleString('en-US')

  const snooze = () => {
    writeState({ ...readState(), nextAt: Date.now() + REPEAT_INTERVAL_MS })
    setVisible(false)
  }
  const off = () => {
    writeState({ off: true })
    setVisible(false)
  }

  return (
    <div className="fixed bottom-4 right-4 z-40 w-[300px] max-w-[calc(100vw-2rem)] rounded-xl border border-border/60 bg-background/95 p-3 shadow-lg backdrop-blur">
      <div className="flex items-start gap-2">
        <Heart className="mt-0.5 h-4 w-4 shrink-0 text-rose-500" />
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-medium">{tf('sponsor.nudgeTitle', { n: maskLabel })}</div>
          <div className="mt-1 text-2xs leading-5 text-muted-foreground">
            {t('sponsor.nudgeDesc')}
          </div>
        </div>
        <button
          onClick={off}
          className="shrink-0 rounded p-0.5 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          title={t('sponsor.nudgeOff')}
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="mt-2.5 flex items-center gap-2">
        <button
          onClick={() => {
            onSponsor()
            snooze()
          }}
          className="rounded-md bg-primary px-2.5 py-1.5 text-2xs font-medium text-primary-foreground transition-opacity hover:opacity-90"
        >
          {t('sponsor.nudgeCta')}
        </button>
        <button
          onClick={snooze}
          className="rounded-md px-2 py-1.5 text-2xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
        >
          {t('sponsor.nudgeLater')}
        </button>
        <button
          onClick={off}
          className="ml-auto rounded-md px-2 py-1.5 text-2xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
        >
          {t('sponsor.nudgeOff')}
        </button>
      </div>
    </div>
  )
}
