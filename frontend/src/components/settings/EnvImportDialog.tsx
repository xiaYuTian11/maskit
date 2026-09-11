/**
 * 「从 .env 导入敏感词」对话框。
 *
 * 三个改之前必须先读懂的点：
 *
 * 1. **分类名就是占位符标签**。引擎按 `label in CREDENTIAL_LABELS` 决定事件库
 *    写不写原文（非凭据类写 `items[].original` 明文，凭据类只写 digest + preview）。
 *    所以被判定为凭据的行，目标分类**只能**从 `CREDENTIAL_LABELS` 里选 ——
 *    否则等于把密钥明文写进本地 SQLite，与「凭据永不落库」的红线冲突。
 * 2. **后端 `POST /api/config` 是顶层浅合并**：`sensitive` 一出现在请求体里就整体
 *    替换，所以合入必须带上完整分类映射（`mergeEntries` 已按此实现）。
 * 3. 默认只勾选凭据行；非凭据行默认不勾选，且必须显式选好目标分类才会被导入。
 *
 * 解析规则与分类启发式都在 `@/lib/env-import`，纯函数、可单独跑
 * `scripts/check-env-import.mjs` 验证；这里只做交互与呈现。
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronRight, FileText, Upload, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Textarea } from '@/components/ui/textarea'
import { useI18n } from '@/lib/i18n'
import { toast } from '@/lib/toast'
import { cn } from '@/lib/utils'
import {
  CREDENTIAL_LABELS,
  mergeEntries,
  parseDotEnv,
  previewValue,
  type EnvParseResult,
} from '@/lib/env-import'

/** 单个 .env 的体积上限：.env 是纯文本配置，正常都在几 KB；超了多半是选错文件。 */
const MAX_FILE_BYTES = 512 * 1024

interface EnvImportDialogProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  /** 现有词库的**完整**分类映射（合入时必须原样带上，见文件头注释 2） */
  words: Record<string, string[]>
  /** 目标分类候选：引擎内置规则标签（= `cfg.builtin_rules` 的键），避免用户还要先手工建分类 */
  builtinLabels: string[]
  /** 落库回调（父组件接 save({sensitive: next}, msg)） */
  onImport: (next: Record<string, string[]>, message: string) => void
}

export function EnvImportDialog({
  open,
  onOpenChange,
  words,
  builtinLabels,
  onImport,
}: EnvImportDialogProps) {
  const { t, tf } = useI18n()
  const [raw, setRaw] = useState('')
  const [parsed, setParsed] = useState<EnvParseResult | null>(null)
  const [picked, setPicked] = useState<boolean[]>([])
  const [targets, setTargets] = useState<string[]>([])
  const [showSkipped, setShowSkipped] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  // 关闭即清空：粘贴进来的内容是明文凭据，不让它留在组件状态里跨次打开
  useEffect(() => {
    if (!open) {
      setRaw('')
      setParsed(null)
      setPicked([])
      setTargets([])
      setShowSkipped(false)
    }
  }, [open])

  // 非凭据行的候选分类：内置标签 ∪ 凭据标签 ∪ 已有自定义分类。
  // 始终并入凭据标签，是为了在 cfg 还没加载出来（builtin_rules 为空）时，
  // 凭据行仍有一个合法且安全的去处。
  const allOptions = useMemo(() => {
    const set = new Set<string>([...builtinLabels, ...CREDENTIAL_LABELS, ...Object.keys(words ?? {})])
    return [...set].sort()
  }, [builtinLabels, words])

  const entries = parsed?.entries ?? []

  // 只有「勾选 + 选好分类」的行才真正会被写入，按钮上的计数与它一致。
  // 这里刻意不用 useMemo：entries 每次渲染都是新数组（`parsed?.entries ?? []`），
  // 把它列进依赖等于永不命中缓存，反而白多一层开销；数组规模也就在几十到几百。
  const readyCount = entries.filter((_, i) => picked[i] && targets[i]).length
  const needCat = entries.filter((_, i) => picked[i] && !targets[i]).length

  const reparse = (text: string) => {
    setRaw(text)
    const r = parseDotEnv(text)
    setParsed(r)
    // 默认只勾凭据行；目标分类用启发式结果（凭据行必定是凭据标签，非凭据行为空待选）
    setPicked(r.entries.map((e) => e.secret))
    setTargets(r.entries.map((e) => e.label))
    setShowSkipped(false)
  }

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = '' // 清空以便重复选同一个文件
    if (!file) return
    if (file.size > MAX_FILE_BYTES) {
      toast(tf('settings.words.envFileTooLarge', { n: Math.round(MAX_FILE_BYTES / 1024) }), 'error')
      return
    }
    const reader = new FileReader()
    reader.onload = () => reparse(String(reader.result ?? ''))
    reader.onerror = () => toast(tf('settings.words.envReadFail', { e: file.name }), 'error')
    reader.readAsText(file)
  }

  const doImport = () => {
    if (readyCount === 0) {
      toast(t('settings.words.envNoPick'), 'error')
      return
    }
    const items = entries
      .map((e, i) => ({ value: e.value, label: targets[i], on: !!picked[i] && !!targets[i] }))
      .filter((it) => it.on)
      .map((it) => ({ value: it.value, label: it.label }))
    const { next, added, dup, overflow } = mergeEntries(words ?? {}, items)
    if (added === 0) {
      // 一个字都没写进去。这里必须区分「全是已存在的词」和「根本没勾」——
      // 早先两种情况都报「请至少勾选一项」，重复导入时用户会以为自己没勾。
      if (dup || overflow) {
        let m = dup ? tf('settings.words.envAllDup', { n: dup }) : ''
        if (overflow) m += tf('settings.words.envImportedOverflow', { n: overflow })
        toast(m.trim(), 'error')
      } else {
        toast(t('settings.words.envNoPick'), 'error')
      }
      return
    }
    // 真正被写入的分类数：按「前后词数变化」判定，比统计 items 里的 label 更准
    const cats = Object.keys(next).filter(
      (c) => (next[c]?.length ?? 0) !== ((words ?? {})[c]?.length ?? 0),
    ).length
    let msg = tf('settings.words.envImported', { n: added, c: cats })
    if (dup) msg += tf('settings.words.envImportedDup', { n: dup })
    if (overflow) msg += tf('settings.words.envImportedOverflow', { n: overflow })
    if (needCat) msg += ` ${tf('settings.words.envNeedCat', { n: needCat })}`
    onImport(next, msg)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {/* 用 flex 列 + 单一滚动区，而不是 DialogContent 自带的 grid：
          grid 容器上的 max-h 不会让行收缩，内容一高就会把 DialogFooter 顶出可视区
          （被 overflow-hidden 裁掉，实测底部按钮不可见）。 */}
      <DialogContent className="flex max-h-[86vh] max-w-3xl flex-col overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-muted-foreground" />
            {t('settings.words.envTitle')}
          </DialogTitle>
          <DialogDescription className="text-[11px] leading-relaxed">
            {t('settings.words.envCredHint')}
          </DialogDescription>
        </DialogHeader>

        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto pr-1">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-muted-foreground">
              {t('settings.words.envPasteLabel')}
            </span>
            <div className="flex items-center gap-1">
              <input
                ref={fileRef}
                type="file"
                accept=".env,text/plain"
                className="hidden"
                onChange={onFile}
              />
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs"
                onClick={() => fileRef.current?.click()}
              >
                <Upload className="mr-1 h-3 w-3" />
                {t('settings.words.envPickFile')}
              </Button>
              {raw && (
                <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => reparse('')}>
                  <X className="mr-1 h-3 w-3" />
                  {t('common.clear')}
                </Button>
              )}
            </div>
          </div>

          <Textarea
            className="h-28 resize-none font-mono text-[11px] leading-relaxed"
            placeholder={t('settings.words.envPastePh')}
            value={raw}
            onChange={(e) => reparse(e.target.value)}
            spellCheck={false}
          />

          {entries.length > 0 && (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] text-muted-foreground">
                  {tf('settings.words.envSummary', {
                    n: entries.length,
                    s: entries.filter((e) => e.secret).length,
                  })}
                </span>
                <div className="flex items-center gap-0.5">
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 px-2 text-[11px]"
                    onClick={() => setPicked(entries.map((_, i) => !!targets[i]))}
                  >
                    {t('settings.words.envSelectAll')}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 px-2 text-[11px]"
                    onClick={() => setPicked(entries.map((e) => e.secret))}
                  >
                    {t('settings.words.envSelectSecrets')}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 px-2 text-[11px]"
                    onClick={() => setPicked(entries.map(() => false))}
                  >
                    {t('settings.words.envSelectNone')}
                  </Button>
                </div>
              </div>

              {/* 表格自身不再限制高度：滚动统一交给上面那个 flex-1 容器，
                  表头的 sticky 会贴着该容器顶部生效（两个嵌套滚动区反而更难用）。 */}
              <div className="overflow-x-auto rounded-lg border">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-muted/80 backdrop-blur">
                    <tr className="text-muted-foreground">
                      <th className="w-8 px-3 py-2" />
                      <th className="px-2 py-2 font-medium">{t('settings.words.envColKey')}</th>
                      <th className="px-2 py-2 font-medium">{t('settings.words.envColValue')}</th>
                      <th className="w-44 px-2 py-2 font-medium">{t('settings.words.envColCat')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {entries.map((e, i) => {
                      // 凭据行的可选分类被收窄到 CREDENTIAL_LABELS：分类名就是占位符
                      // label，选到别的分类会把密钥明文写进事件库（见文件头注释 1）。
                      const options: readonly string[] = e.secret ? CREDENTIAL_LABELS : allOptions
                      return (
                        <tr key={`${e.key}:${e.line}`} className={cn(picked[i] && 'bg-primary/[0.04]')}>
                          <td className="px-3 py-1.5">
                            <input
                              type="checkbox"
                              className="h-3.5 w-3.5 accent-primary"
                              checked={!!picked[i]}
                              onChange={(ev) =>
                                setPicked((p) => p.map((v, k) => (k === i ? ev.target.checked : v)))
                              }
                            />
                          </td>
                          <td className="px-2 py-1.5">
                            <div className="flex items-center gap-1.5">
                              <span className="font-mono text-[11px]">{e.key}</span>
                              {e.secret && (
                                <Badge
                                  variant="outline"
                                  className="h-4 shrink-0 px-1 text-[9px] font-normal text-amber-600 dark:text-amber-400"
                                >
                                  {t('settings.words.envSecretBadge')}
                                </Badge>
                              )}
                            </div>
                            <div className="text-[10px] text-muted-foreground/70">
                              {tf('settings.words.envLine', { n: e.line })}
                            </div>
                          </td>
                          <td
                            className="max-w-0 truncate px-2 py-1.5 font-mono text-[11px] text-muted-foreground"
                            title={previewValue(e.value, e.secret)}
                          >
                            {previewValue(e.value, e.secret)}
                          </td>
                          <td className="px-2 py-1.5">
                            {/* 用原生 select 而不是 Radix Select：这里可能有几十行，
                                每行一个 Radix Select 会带来几十个 portal 与焦点管理开销，
                                而 Radix Select 嵌在 Radix Dialog 的焦点陷阱里也更容易出怪问题。 */}
                            <select
                              className={cn(
                                'h-6 w-full rounded-md border bg-background px-1 text-[11px]',
                                targets[i] ? 'border-input text-foreground' : 'border-dashed border-border text-muted-foreground',
                              )}
                              value={targets[i] ?? ''}
                              onChange={(ev) =>
                                setTargets((p) => p.map((v, k) => (k === i ? ev.target.value : v)))
                              }
                            >
                              <option value="">—</option>
                              {options.map((c) => (
                                <option key={c} value={c}>
                                  {c}
                                </option>
                              ))}
                            </select>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {parsed && entries.length === 0 && raw.trim() !== '' && (
            <div className="rounded-lg border border-dashed px-3 py-2 text-[11px] text-muted-foreground">
              {t('settings.words.envEmpty')}
            </div>
          )}

          {parsed && parsed.skipped.length > 0 && (
            <div className="rounded-lg border bg-muted/30">
              <button
                type="button"
                className="flex w-full items-center justify-between px-3 py-1.5 text-[11px] text-muted-foreground hover:text-foreground"
                onClick={() => setShowSkipped((v) => !v)}
              >
                <span>{tf('settings.words.envSkippedTitle', { n: parsed.skipped.length })}</span>
                <ChevronRight
                  className={cn('h-3 w-3 transition-transform', showSkipped && 'rotate-90')}
                />
              </button>
              {showSkipped && (
                <ul className="max-h-28 space-y-0.5 overflow-auto border-t border-border/60 px-3 py-1.5">
                  {parsed.skipped.map((s, i) => (
                    <li key={`${s.line}:${i}`} className="text-[10px] text-muted-foreground">
                      {tf('settings.words.envLine', { n: s.line })} · {s.reason}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        <DialogFooter className="items-center gap-2 sm:justify-between">
          <span className="text-[11px] text-muted-foreground">
            {needCat > 0 ? tf('settings.words.envNeedCat', { n: needCat }) : ''}
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              className="h-8 text-xs"
              onClick={() => onOpenChange(false)}
            >
              {t('common.cancel')}
            </Button>
            <Button size="sm" className="h-8 text-xs" disabled={readyCount === 0} onClick={doImport}>
              {tf('settings.words.envConfirm', { n: readyCount })}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
