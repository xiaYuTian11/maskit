/**
 * 本地试验台：输入一段文本 → 就地看脱敏结果与还原往返，**不出网、不留痕**。
 *
 * 为什么它必须在接入页（而不是只留在高级选项）：原先唯一的「真实脱敏测试」要求先
 * 填上游 key 并真的发一条请求——新人想确认"这东西到底会把我什么内容打码"，第一道
 * 门就是去要 key，等于把体验门槛架在理解之前。试验台不要 key、不碰上游，直接把
 * 「脱敏 ↔ 还原」这一对事实摆出来。
 *
 * 结果区刻意讲两件事：
 * 1. **唯一实体数 vs 出现次数**：同一个值出现两次只拿一个 token（用户曾质疑
 *    「脱敏几千、还原几十」，那是把会话累计当成单次命中）；
 * 2. **往返还原**：脱敏后的文本能在本机原样还原回来，这是「看到 token 不慌」的前提。
 */
import { useState } from 'react'
import { FlaskConical, Loader2, Play, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { toast } from '@/lib/toast'
import { useI18n } from '@/lib/i18n'
import { demoLab, type DemoLabResult } from '@/api/settings'

const MAX_CHARS = 4000

// 样例输入按**片段拼**，不写字面量：本机网关会把工具调用里的占位符字面量在落盘时
// 还原成真实值（AGENTS.md §3.9）——源码里于是出现一串真实号码/邮箱。拼接后源码文本
// 里没有完整号码，运行时拼出来的串仍会命中规则（否则演示就演示不出东西）。
const SAMPLE = '电话 ' + '1' + '3' + '0' + '0'.repeat(8)
  + '，邮箱 ' + 'zhangsan' + '@' + 'example.com'
  + '，key ' + 'sk' + '-' + 'demo' + '0'.repeat(12)
  + '，内网 http://192.168.' + '10.9' + ':8080'

export function LabCard() {
  const { t, tf } = useI18n()
  const [text, setText] = useState('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<DemoLabResult | null>(null)

  const run = async () => {
    if (running) return
    setRunning(true)
    try {
      const r = await demoLab(text)
      setResult(r)
      if (!r.ok) toast(r.hint || r.error || t('settings.lab.failed'), 'error')
    } catch (e) {
      const msg = String(e)
      // 503 busy 是设计内行为（同时只跑 2 个演示），说清楚而不是当成错误吓人
      toast(msg.includes('503') ? t('settings.lab.busy') : tf('settings.lab.failed', { e: msg }), 'error')
    } finally {
      setRunning(false)
    }
  }

  const tooLong = text.length > MAX_CHARS

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <FlaskConical className="h-4 w-4" />
          {t('settings.lab.title')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-[13px] leading-relaxed text-muted-foreground">{t('settings.lab.desc')}</p>
        <Textarea
          className="min-h-20 font-mono text-xs"
          placeholder={t('settings.lab.placeholder')}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" className="h-7 text-xs" onClick={run} disabled={running || tooLong}>
            {running ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : <Play className="mr-1 h-3 w-3" />}
            {t('settings.lab.run')}
          </Button>
          <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => { setText(SAMPLE); setResult(null) }}>
            {t('settings.lab.fillSample')}
          </Button>
          <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => { setText(''); setResult(null) }}>
            <RotateCcw className="mr-1 h-3 w-3" />
            {t('settings.lab.clear')}
          </Button>
          <span className={tooLong ? 'text-[11px] text-red-600 dark:text-red-400' : 'text-[11px] text-muted-foreground'}>
            {tf('settings.lab.counter', { n: text.length, max: MAX_CHARS })}
          </span>
        </div>

        {result?.ok && (
          <div className="space-y-3 rounded-lg border bg-muted/30 p-3 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="text-[10px]">
                {tf('settings.lab.unique', { n: result.count ?? 0 })}
              </Badge>
              <Badge variant="outline" className="text-[10px]">
                {tf('settings.lab.occurrences', { n: result.occurrences ?? 0 })}
              </Badge>
              <Badge
                variant="outline"
                className={result.roundtrip_ok
                  ? 'border-emerald-500/40 text-[10px] text-emerald-600 dark:text-emerald-400'
                  : 'border-red-500/40 text-[10px] text-red-600 dark:text-red-400'}
              >
                {result.roundtrip_ok ? t('settings.lab.roundtripOk') : t('settings.lab.roundtripBad')}
              </Badge>
              <span className="text-[10px] text-muted-foreground">
                {tf('settings.lab.timing', { mask: result.mask_ms ?? 0, restore: result.restore_ms ?? 0 })}
              </span>
            </div>

            <div>
              <div className="mb-1 text-[11px] text-muted-foreground">{t('settings.lab.masked')}</div>
              <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px]">{result.masked}</pre>
            </div>

            {result.restored !== undefined && (
              <div>
                <div className="mb-1 text-[11px] text-muted-foreground">{t('settings.lab.restored')}</div>
                <pre className="max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-muted-foreground">{result.restored}</pre>
              </div>
            )}

            {(result.items?.length ?? 0) > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[11px]">
                  <thead className="text-muted-foreground">
                    <tr>
                      <th className="py-1 pr-2 font-normal">{t('settings.lab.colToken')}</th>
                      <th className="py-1 pr-2 font-normal">{t('settings.lab.colLabel')}</th>
                      <th className="py-1 pr-2 font-normal">{t('settings.lab.colLen')}</th>
                      <th className="py-1 pr-2 font-normal">{t('settings.lab.colCount')}</th>
                      <th className="py-1 font-normal">{t('settings.lab.colSource')}</th>
                    </tr>
                  </thead>
                  <tbody className="font-mono">
                    {result.items!.map((it) => (
                      <tr key={it.token} className="border-t border-border/50">
                        <td className="py-1 pr-2 break-all">{it.token}</td>
                        <td className="py-1 pr-2">{it.label}</td>
                        <td className="py-1 pr-2">{it.original_len}</td>
                        <td className="py-1 pr-2">{it.occurrences}</td>
                        <td className="py-1">
                          {it.reused ? t('settings.lab.reused') : t('settings.lab.fresh')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {result.unresolved ? (
              <p className="text-red-600 dark:text-red-400">
                {tf('settings.lab.unresolved', { n: result.unresolved })}
              </p>
            ) : null}
          </div>
        )}

        <p className="text-[11px] leading-snug text-muted-foreground/80">{t('settings.lab.hint')}</p>
      </CardContent>
    </Card>
  )
}
