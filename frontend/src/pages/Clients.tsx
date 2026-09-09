/** 客户端管理（独立页）：直接渲染设置页的客户端 tab 内容（URL 保持 #/clients） */
import SettingsPage from '@/pages/Settings'

export default function ClientsPage() {
  return <SettingsPage embeddedTab="clients" />
}
