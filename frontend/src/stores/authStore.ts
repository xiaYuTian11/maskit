/**
 * 认证状态：引擎 token 仅存内存（方案 §4.2，token 不进 HTML/localStorage）
 */
import { create } from 'zustand'

interface AuthState {
  token: string
  engineReady: boolean
  engineError: string | null
  setToken: (token: string) => void
  setEngineReady: (ready: boolean) => void
  setEngineError: (err: string | null) => void
}

export const useAuthStore = create<AuthState>((set) => ({
  token: '',
  engineReady: false,
  engineError: null,
  setToken: (token) => set({ token }),
  setEngineReady: (ready) => set({ engineReady: ready }),
  setEngineError: (err) => set({ engineError: err }),
}))
