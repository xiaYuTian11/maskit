/**
 * Data Maskit 品牌 Logo（SVG 内联，无外部资源）
 * 盾牌 + 渐变 + 对勾；与旧面板蓝色盾牌一脉相承，但更精致
 */
import { cn } from '@/lib/utils'

export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" fill="none" className={cn('h-8 w-8', className)}>
      <defs>
        <linearGradient id="shield-grad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#3b82f6" />
          <stop offset="55%" stopColor="#6366f1" />
          <stop offset="100%" stopColor="#06b6d4" />
        </linearGradient>
      </defs>
      {/* 盾形外廓 */}
      <path
        d="M16 2.5 L28 7.5 V16.5 C28 23.5 22.8 28.5 16 30 C9.2 28.5 4 23.5 4 16.5 V7.5 Z"
        fill="url(#shield-grad)"
      />
      {/* 内芯 */}
      <path
        d="M16 8 L22 10.5 V16 C22 20.3 19.6 23.3 16 24.8 C12.4 23.3 10 20.3 10 16 V10.5 Z"
        fill="white"
        opacity="0.94"
      />
      {/* 对勾 */}
      <path
        d="M13.4 16.4 L15.4 18.4 L19 13.8"
        stroke="#0ea5e9"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}
