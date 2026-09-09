#!/usr/bin/env node
/**
 * i18n 字典对齐检查（CI frontend job）。
 *
 * 规则：
 *  1. zh / en 两组 key 必须完全一致——缺一侧就会在对应语言下显示裸 key；
 *  2. 源码里 t('x') / tf('x') / tt('x') / ttf('x') / labelKey: 'x' 引用的 key 必须存在于字典。
 *
 * 用法：node scripts/check-i18n.mjs   （在仓库任意目录执行均可；退出码 0 通过 / 1 失败）
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SRC = join(ROOT, 'frontend', 'src')
const DICT = join(SRC, 'lib', 'i18n.tsx')

const src = readFileSync(DICT, 'utf-8')
const zhStart = src.indexOf('const zh: Record')
const enStart = src.indexOf('const en: Record')
const dictEnd = src.indexOf('const DICTS')
if (zhStart < 0 || enStart < 0 || dictEnd < 0) {
  console.error('check-i18n: cannot locate zh/en dictionaries in', DICT)
  process.exit(1)
}
// 一行可能写多个键（`'a': 'x',  'b': 'y',`），所以按「行首或逗号之后」匹配
const keysOf = (seg) => new Set([...seg.matchAll(/(?:^|,)\s*'([^']+)':/gm)].map((m) => m[1]))
const zh = keysOf(src.slice(zhStart, enStart))
const en = keysOf(src.slice(enStart, dictEnd))

const walk = (dir, out = []) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (/\.(tsx?|mts)$/.test(name) && p !== DICT) out.push(p)
  }
  return out
}
const used = new Set()
for (const f of walk(SRC)) {
  const s = readFileSync(f, 'utf-8')
  for (const m of s.matchAll(/\b(?:t|tf|tt|ttf)\(\s*'([^']+)'/g)) used.add(m[1])
  for (const m of s.matchAll(/labelKey:\s*'([^']+)'/g)) used.add(m[1])
}
// 动态拼接的前缀（如 t('nav.' + key)）不在静态检查范围内
used.delete('nav.')

let failed = false
const report = (title, items) => {
  if (items.length === 0) return
  failed = true
  console.error(`\n${title} (${items.length}):`)
  for (const k of items.sort()) console.error('  ' + k)
}
report('keys only in zh', [...zh].filter((k) => !en.has(k)))
report('keys only in en', [...en].filter((k) => !zh.has(k)))
report('keys used in source but missing from dictionary', [...used].filter((k) => !zh.has(k) && !en.has(k)))

if (failed) process.exit(1)
console.log(`check-i18n: OK (zh ${zh.size} keys, en ${en.size} keys, ${used.size} referenced)`)
