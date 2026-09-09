/** 敏感词库（独立页）：直接渲染设置页的敏感词 tab 内容（URL 保持 #/words） */
import SettingsPage from '@/pages/Settings'

export default function WordsPage() {
  return <SettingsPage embeddedTab="words" />
}
