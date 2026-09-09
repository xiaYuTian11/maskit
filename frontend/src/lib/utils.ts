import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** shadcn/ui 类名合并工具 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * 复制文本到剪贴板（带回退）。
 * WebView2 下 navigator.clipboard 在某些安全上下文下不可用，
 * 回退到 document.execCommand('copy')。
 */
export async function copyText(text: string): Promise<void> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
      return
    }
  } catch {
    // 回退到 execCommand
  }
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  ta.focus()
  ta.select()
  try {
    document.execCommand('copy')
  } finally {
    document.body.removeChild(ta)
  }
}
