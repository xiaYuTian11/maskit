/**
 * 敏感词打码工具（Stats 排行榜 / Dashboard 脱敏明细共用）
 *
 * 凭据类标签：永远只显示打码（安全红线，与引擎口径一致：凭据原文不落库）。
 * 集合的唯一定义源在 `credential-labels.ts` —— 以前这里自己写了一份 5 元素的
 * 集合，少了 CONNSTR / PRIVATE_KEY，导致这两类词能被「显示明文」开关展示。
 */
export { CRED_LABELS, isCredentialLabel } from './credential-labels.ts'

/** 打码显示：超长串保留首尾，中间打星（明文切换仅在非凭据词上生效）。
 *
 * `cred` 为真时原样返回：凭据类落库的已经是安全预览（`<CONNSTR 4 位>`、
 * `<PEM 私钥 1024 字节>`、`sk-…3456`），再打一遍会变成 `<CO******* 位>` 这种畸形显示。
 * 判据必须是调用方给的 `cred`，不能只看字符串形状 —— 非凭据词（用户自定义敏感词）
 * 也可能长成 `<内部系统>` 或含 `…`，那时原样返回等于在「显示明文」关闭时泄露明文。
 */
export function maskWord(w: string, cred = false): string {
  if (!w) return ''
  if (cred && ((w.startsWith('<') && w.endsWith('>')) || w.includes('…'))) return w
  if (w.length <= 2) return '**'
  if (w.length <= 6) return w[0] + '*'.repeat(w.length - 2) + w[w.length - 1]
  const keep = Math.min(3, Math.floor(w.length / 4))
  return w.slice(0, keep) + '*'.repeat(Math.min(12, w.length - keep * 2)) + w.slice(-keep)
}
