/**
 * 占位符 Skill（行为契约）下载卡片。
 *
 * 为什么需要它：Skill 是宿主侧资产，网关代装不了（方案 §F1）——Claude Code /
 * Cursor / Codex 各自有目录或 rules 机制。装到 Program Files / /Applications 的
 * 用户拿不到仓库文件，也不一定会去翻 Release，所以面板必须能直接把包递出去。
 *
 * 包内容与 Release 资产**同源**：都由 `engine/skill_bundle.py` 打同一份
 * `agent-bundle/maskit-placeholders`，不存在第二条打包路径（写两份必然漂移）。
 */
import { useState } from 'react'
import { BookOpen, Copy, Download, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { toast } from '@/lib/toast'
import { useI18n } from '@/lib/i18n'
import { isTauri } from '@/lib/shield-fetch'
import { downloadSkillBundle } from '@/api/settings'

export function SkillBundleCard({ version }: { version?: string }) {
  const { t, tf } = useI18n()
  const [downloading, setDownloading] = useState(false)

  const fileName = `Maskit_${version || 'latest'}_skill.zip`
  // 安装命令按平台给一条：解压到用户级 skills 目录后就是一个可直接被发现的技能目录
  //（zip 内顶层目录名固定为 `maskit-placeholders`）。其它宿主的装法在包内 README。
  const isWindows = typeof navigator !== 'undefined' && /win/i.test(navigator.userAgent)
  const installCommand = isWindows
    ? `Expand-Archive .\\${fileName} -DestinationPath "$env:USERPROFILE\\.claude\\skills\\" -Force`
    : `unzip -o ${fileName} -d ~/.claude/skills/`

  const doDownload = async () => {
    if (downloading) return
    setDownloading(true)
    try {
      const resp = await downloadSkillBundle()
      const blob = await resp.blob()
      if (isTauri()) {
        const { save } = await import('@tauri-apps/plugin-dialog')
        const { writeFile } = await import('@tauri-apps/plugin-fs')
        const buf = new Uint8Array(await blob.arrayBuffer())
        const path = await save({ defaultPath: fileName, filters: [{ name: 'ZIP', extensions: ['zip'] }] })
        if (path) {
          await writeFile(path, buf)
          toast(t('settings.skill.saved'))
        }
      } else {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = fileName
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
        toast(t('settings.skill.saved'))
      }
    } catch (e) {
      toast(tf('settings.skill.fail', { e: String(e) }), 'error')
    } finally {
      setDownloading(false)
    }
  }

  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(installCommand)
      toast(t('settings.skill.copied'))
    } catch (e) {
      toast(tf('settings.skill.fail', { e: String(e) }), 'error')
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <BookOpen className="h-4 w-4" />
          {t('settings.skill.title')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-[13px] leading-relaxed text-muted-foreground">{t('settings.skill.desc')}</p>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="outline" className="h-7 text-xs" onClick={doDownload} disabled={downloading}>
            {downloading ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : <Download className="mr-1 h-3 w-3" />}
            {t('settings.skill.download')}
          </Button>
          <Button size="sm" variant="outline" className="h-7 text-xs" onClick={copyCommand}>
            <Copy className="mr-1 h-3 w-3" />
            {t('settings.skill.copyCmd')}
          </Button>
        </div>
        <code className="block overflow-x-auto rounded-md bg-muted/40 px-2 py-1.5 font-mono text-[11px] text-muted-foreground">
          {installCommand}
        </code>
        <p className="text-[11px] leading-snug text-muted-foreground/80">{t('settings.skill.hint')}</p>
      </CardContent>
    </Card>
  )
}
