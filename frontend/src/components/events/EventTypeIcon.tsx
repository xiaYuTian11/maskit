/**
 * 事件类型图标映射（方案功能覆盖清单：10 种事件类型全覆盖）
 * 颜色语义：MASK 蓝 / RESTORE 绿 / BLOCK+ERR 红 / SCAN_WARN+DNS_ERROR 琥珀 / 其余灰
 * CANCEL/DNS_ERROR 不是故障（AGENTS.md 红线），视觉上不归为红色
 */
import {
  Shield,
  RotateCcw,
  ArrowRight,
  FilterX,
  SkipForward,
  Ban,
  TriangleAlert,
  ScanSearch,
  CircleSlash,
  Globe,
  type LucideIcon,
} from 'lucide-react'
import type { EventType } from '@/types/api'
import { cn } from '@/lib/utils'

export interface EventTypeMeta {
  icon: LucideIcon
  /** i18n key（label 中文兜底） */
  labelKey?: string
  /** Tailwind 颜色类（图标色） */
  color: string
  /** 中文标签 */
  label: string
  /** 是否视为异常（进 alerts） */
  alert: boolean
}

export const EVENT_TYPE_META: Record<EventType, EventTypeMeta> = {
  MASK: { icon: Shield, color: 'text-blue-500', labelKey: 'evt.mask', label: '脱敏', alert: false },
  RESTORE: { icon: RotateCcw, color: 'text-emerald-500', labelKey: 'evt.restore', label: '还原', alert: false },
  PASS: { icon: ArrowRight, color: 'text-slate-400', labelKey: 'evt.pass', label: '透传', alert: false },
  BYPASS: { icon: FilterX, color: 'text-slate-400', labelKey: 'evt.bypass', label: '绕过', alert: false },
  SKIP: { icon: SkipForward, color: 'text-slate-400', labelKey: 'evt.skip', label: '跳过', alert: false },
  BLOCK: { icon: Ban, color: 'text-red-500', labelKey: 'evt.block', label: '阻断', alert: true },
  ERR: { icon: TriangleAlert, color: 'text-red-500', labelKey: 'evt.err', label: '错误', alert: true },
  SCAN_WARN: { icon: ScanSearch, color: 'text-amber-500', labelKey: 'evt.scanWarn', label: '扫描告警', alert: true },
  CANCEL: { icon: CircleSlash, color: 'text-slate-400', labelKey: 'evt.cancel', label: '取消', alert: false },
  DNS_ERROR: { icon: Globe, color: 'text-amber-500', labelKey: 'evt.dns', label: 'DNS 错误', alert: false },
}

export function getEventTypeMeta(type: string): EventTypeMeta {
  return EVENT_TYPE_META[type as EventType] ?? {
    icon: CircleSlash,
    color: 'text-slate-400',
    label: type,
    alert: false,
  }
}

/** 事件类型图标（含颜色） */
export function EventTypeIcon({
  type,
  className,
}: {
  type: string
  className?: string
}) {
  const meta = getEventTypeMeta(type)
  const Icon = meta.icon
  return <Icon className={cn(meta.color, className)} />
}
