/**
 * 敏感词库导入对话框：支持导入 JSON 备份文件或粘贴 JSON 内容。
 * 支持增量合并与完全覆盖两种模式。
 */
import { useMemo, useRef, useState } from 'react'
import { Upload, FileText, CheckCircle2, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { useI18n } from '@/lib/i18n'
import { toast } from '@/lib/toast'

interface WordsImportDialogProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  currentSensitive: Record<string, string[]>
  currentSensitiveDisabled: string[]
  currentSensitiveWordDisabled: Record<string, string[]>
  currentSensitiveWordWhole: string[]
  onImport: (
    payload: {
      sensitive: Record<string, string[]>
      sensitive_disabled: string[]
      sensitive_word_disabled: Record<string, string[]>
      sensitive_word_whole: string[]
      _allow_shrink?: boolean
    },
    message: string,
  ) => void
}

interface ParsedWordsData {
  sensitive: Record<string, string[]>
  sensitive_disabled: string[]
  sensitive_word_disabled: Record<string, string[]>
  sensitive_word_whole: string[]
  totalCats: number
  totalWords: number
}

function parseImportText(text: string): ParsedWordsData | null {
  const trimmed = text.trim()
  if (!trimmed) return null

  let obj: unknown
  try {
    obj = JSON.parse(trimmed)
  } catch {
    return null
  }

  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null

  const root = obj as Record<string, unknown>
  let rawSensitive: Record<string, unknown> = {}
  let rawDisabled: string[] = []
  let rawWordDisabled: Record<string, unknown> = {}
  let rawWordWhole: string[] = []

  // 判断是否为完整备份格式
  if ('sensitive' in root && typeof root.sensitive === 'object' && root.sensitive !== null && !Array.isArray(root.sensitive)) {
    rawSensitive = root.sensitive as Record<string, unknown>
    if (Array.isArray(root.sensitive_disabled)) {
      rawDisabled = root.sensitive_disabled.map(String)
    }
    if (typeof root.sensitive_word_disabled === 'object' && root.sensitive_word_disabled !== null && !Array.isArray(root.sensitive_word_disabled)) {
      rawWordDisabled = root.sensitive_word_disabled as Record<string, unknown>
    }
    if (Array.isArray(root.sensitive_word_whole)) {
      rawWordWhole = root.sensitive_word_whole.map(String)
    }
  } else {
    // 简易格式：key 即分类名
    rawSensitive = root
  }

  const cleanSensitive: Record<string, string[]> = {}
  let wordsCount = 0

  for (const [cat, val] of Object.entries(rawSensitive)) {
    const catName = cat.trim()
    if (!catName) continue

    let list: string[] = []
    if (Array.isArray(val)) {
      list = val.map((x) => String(x ?? '').trim()).filter(Boolean)
    } else if (typeof val === 'object' && val !== null && 'words' in val && Array.isArray((val as { words: unknown[] }).words)) {
      list = (val as { words: unknown[] }).words.map((x) => String(x ?? '').trim()).filter(Boolean)
    }
    if (list.length > 0) {
      const uniq = Array.from(new Set(list))
      cleanSensitive[catName] = uniq
      wordsCount += uniq.length
    }
  }

  const cleanWordDisabled: Record<string, string[]> = {}
  for (const [cat, val] of Object.entries(rawWordDisabled)) {
    if (Array.isArray(val)) {
      const list = val.map((x) => String(x ?? '').trim()).filter(Boolean)
      if (list.length) cleanWordDisabled[cat.trim()] = Array.from(new Set(list))
    }
  }

  return {
    sensitive: cleanSensitive,
    sensitive_disabled: Array.from(new Set(rawDisabled.map((x) => x.trim()).filter(Boolean))),
    sensitive_word_disabled: cleanWordDisabled,
    sensitive_word_whole: Array.from(new Set(rawWordWhole.map((x) => x.trim()).filter(Boolean))),
    totalCats: Object.keys(cleanSensitive).length,
    totalWords: wordsCount,
  }
}

export function WordsImportDialog({
  open,
  onOpenChange,
  currentSensitive,
  currentSensitiveDisabled,
  currentSensitiveWordDisabled,
  currentSensitiveWordWhole,
  onImport,
}: WordsImportDialogProps) {
  const { t, tf } = useI18n()
  const [rawText, setRawText] = useState('')
  const [mode, setMode] = useState<'merge' | 'overwrite'>('merge')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const parsed = useMemo(() => parseImportText(rawText), [rawText])

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (event) => {
      const content = String(event.target?.result ?? '')
      setRawText(content)
    }
    reader.onerror = () => {
      toast(tf('settings.words.envReadFail', { e: 'File read error' }), 'error')
    }
    reader.readAsText(file, 'utf-8')
    e.target.value = ''
  }

  const handleConfirm = () => {
    if (!parsed || parsed.totalWords === 0) {
      toast(t('settings.words.importEmpty'), 'error')
      return
    }

    if (mode === 'overwrite') {
      const ok = window.confirm(t('settings.words.importConfirmOverwrite'))
      if (!ok) return
      onImport(
        {
          sensitive: parsed.sensitive,
          sensitive_disabled: parsed.sensitive_disabled,
          sensitive_word_disabled: parsed.sensitive_word_disabled,
          sensitive_word_whole: parsed.sensitive_word_whole,
          _allow_shrink: true,
        },
        tf('settings.words.importSuccess', { cats: parsed.totalCats, words: parsed.totalWords }),
      )
    } else {
      // 增量合并
      const nextSensitive: Record<string, string[]> = { ...currentSensitive }
      for (const [cat, words] of Object.entries(parsed.sensitive)) {
        const cur = nextSensitive[cat] ?? []
        nextSensitive[cat] = Array.from(new Set([...cur, ...words]))
      }

      const nextDisabled = Array.from(new Set([...currentSensitiveDisabled, ...parsed.sensitive_disabled]))
      const nextWordDisabled: Record<string, string[]> = { ...currentSensitiveWordDisabled }
      for (const [cat, words] of Object.entries(parsed.sensitive_word_disabled)) {
        const cur = nextWordDisabled[cat] ?? []
        nextWordDisabled[cat] = Array.from(new Set([...cur, ...words]))
      }

      const nextWordWhole = Array.from(new Set([...currentSensitiveWordWhole, ...parsed.sensitive_word_whole]))

      const totalCats = Object.keys(nextSensitive).length
      const totalWords = Object.values(nextSensitive).reduce((a, b) => a + b.length, 0)

      onImport(
        {
          sensitive: nextSensitive,
          sensitive_disabled: nextDisabled,
          sensitive_word_disabled: nextWordDisabled,
          sensitive_word_whole: nextWordWhole,
        },
        tf('settings.words.importSuccess', { cats: totalCats, words: totalWords }),
      )
    }

    onOpenChange(false)
    setRawText('')
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Upload className="h-4 w-4" />
            {t('settings.words.importTitle')}
          </DialogTitle>
          <DialogDescription>{t('settings.words.importDesc')}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* 选择文件 */}
          <div>
            <Label className="text-xs">{t('settings.words.importPickFile')}</Label>
            <div className="mt-1.5 flex items-center gap-2">
              <input
                ref={fileInputRef}
                type="file"
                accept=".json"
                className="hidden"
                onChange={handleFileChange}
              />
              <Button
                size="sm"
                variant="outline"
                className=""
                onClick={() => fileInputRef.current?.click()}
              >
                <FileText className="mr-1.5 h-3.5 w-3.5" />
                {t('settings.words.importPickFile')}
              </Button>
            </div>
          </div>

          {/* 粘贴 JSON */}
          <div>
            <Label className="text-xs">{t('settings.words.importPasteLabel')}</Label>
            <Textarea
              className="mt-1.5 h-32 font-mono text-xs"
              placeholder={t('settings.words.importPastePh')}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
            />
          </div>

          {/* 导入模式 */}
          <div className="space-y-2">
            <Label className="text-xs font-semibold">{t('settings.words.importMode')}</Label>
            <div className="space-y-2">
              <label className="flex items-start gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="import-mode"
                  value="merge"
                  checked={mode === 'merge'}
                  onChange={() => setMode('merge')}
                  className="mt-0.5 text-primary-ink focus:ring-primary"
                />
                <span className="text-xs leading-normal">
                  {t('settings.words.importModeMerge')}
                </span>
              </label>
              <label className="flex items-start gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="import-mode"
                  value="overwrite"
                  checked={mode === 'overwrite'}
                  onChange={() => setMode('overwrite')}
                  className="mt-0.5 text-primary-ink focus:ring-primary"
                />
                <span className="text-xs leading-normal text-muted-foreground hover:text-foreground">
                  {t('settings.words.importModeOverwrite')}
                </span>
              </label>
            </div>
          </div>

          {/* 解析摘要 */}
          {rawText.trim() && (
            <div className="rounded-md border p-2.5 text-xs">
              {parsed && parsed.totalWords > 0 ? (
                <div className="flex items-center gap-2 text-success-ink">
                  <CheckCircle2 className="h-4 w-4 shrink-0" />
                  <span>{tf('settings.words.importSummary', { cats: parsed.totalCats, words: parsed.totalWords })}</span>
                </div>
              ) : (
                <div className="flex items-center gap-2 text-warning-ink">
                  <AlertTriangle className="h-4 w-4 shrink-0" />
                  <span>{t('settings.words.importEmpty')}</span>
                </div>
              )}
            </div>
          )}
        </div>

        <DialogFooter className="mt-2">
          <Button size="sm" variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.cancel')}
          </Button>
          <Button
            size="sm"
            disabled={!parsed || parsed.totalWords === 0}
            onClick={handleConfirm}
          >
            <Upload className="mr-1 h-3.5 w-3.5" />
            {t('settings.words.import')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
