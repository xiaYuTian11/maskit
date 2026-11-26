#!/usr/bin/env node
/*
 * 浏览器扩展（extension/）静态门禁与隔离行为回归。
 *
 * **为什么需要**：扩展侧此前**没有任何自动化门禁**——单测（python）碰不到它，
 * `e2e_ext_bridge.py` 要真浏览器且不进 verify-all（SPEC §6.2 定为可选）。于是
 * extension/ 是唯一"改错了当场看不出来"的地方，而它恰恰是最脆的：一个 i18n 键拼错，
 * 页面上就是一行空白文案；`shared.js` 忘了在 HTML 里引，整个设置页 ReferenceError 全白；
 * `registerContentScripts` 写回蛇形 `run_at`，动态站点**静默失效**（见 background.js 注释）。
 * 这些都不是理论风险：前两个已经在本轮开发中差点踩到，后一个实测踩过。
 *
 * 检查项（全部零依赖、纯静态 + 纯函数用例）：
 *   1. 每个 .js 能被解析（语法错误当场拦住）；
 *   2. manifest.json 合法、必需字段齐全、引用的文件都存在；
 *   3. HTML 的 `<script src>` **顺序**正确（shared.js 必须在逻辑脚本之前）且无内联脚本
 *      （MV3 默认 CSP 会禁掉内联，写了就是运行时不执行）；
 *   4. i18n：zh/en 键集**必须完全一致**，且 HTML 里每个 data-i18n 键都能查到译文；
 *   5. shared.js 的纯函数行为（match pattern / 域名校验 / 站点覆盖）；
 *   6. 安全红线：不得出现 `chrome.storage.sync`、不得出现非 127.0.0.1/localhost 的字面 URL；
 *   7. `syncDynamicScripts` 必须用驼峰 `runAt`（蛇形 `run_at` 会让动态注册 100% 静默失效）；
 *   8. STATIC_SITES 与 manifest 的静态 content_scripts 必须对得上；
 *   9. SW 必须 `importScripts('shared.js')`（否则 MASKIT_SHARED 未定义，扩展加载即死）；
 *  10. JS 里 `$('id')` / `getElementById('id')` 引用的 id 必须在对应 HTML 里存在
 *      （缺失会让初始化在绑定按钮事件前抛错 —— 「刷新 / 设置」全成死键，见 §3b）；
 *  11. 文本 mask 的原函数行为：超时预算、分档边界、有限重试与用户阻断选择。
 *
 * 用法：`node scripts/check-extension.mjs`（失败退出码 1）
 */
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import url from 'node:url'

const ROOT = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), '..')
const EXT = path.join(ROOT, 'extension')

const errors = []
const notes = []
const fail = (msg) => errors.push(msg)

function read(name) {
  const p = path.join(EXT, name)
  if (!fs.existsSync(p)) {
    fail(`缺少文件：extension/${name}`)
    return ''
  }
  return fs.readFileSync(p, 'utf8')
}

// ── 1. 语法 ──────────────────────────────────────────────────────────────────
const JS_FILES = ['shared.js', 'background.js', 'bridge-main.js', 'bridge-isolated.js',
  'options.js', 'popup.js']
const sources = {}
for (const name of JS_FILES) {
  const code = read(name)
  sources[name] = code
  if (!code) continue
  try {
    new vm.Script(code, { filename: `extension/${name}` })
  } catch (e) {
    fail(`extension/${name} 语法错误：${e.message}`)
  }
}

// ── 2. manifest ─────────────────────────────────────────────────────────────
let manifest = null
try {
  manifest = JSON.parse(read('manifest.json') || '{}')
} catch (e) {
  fail(`manifest.json 不是合法 JSON：${e.message}`)
}
if (manifest) {
  if (manifest.manifest_version !== 3) fail('manifest_version 必须是 3（MV3）')
  for (const key of ['name', 'version', 'background', 'action']) {
    if (!(key in manifest)) fail(`manifest.json 缺少必需字段 ${key}`)
  }
  // `default_locale` 只有配了 _locales/ 目录才能写：只声明字段会让扩展直接加载失败
  if ('default_locale' in manifest && !fs.existsSync(path.join(EXT, '_locales'))) {
    fail('manifest.json 声明了 default_locale 但没有 _locales/ 目录 —— 扩展会加载失败')
  }
  const referenced = new Set()
  const bgCfg = manifest.background || {}
  const sw = String(bgCfg.service_worker || '').trim()
  if (sw) referenced.add(sw)
  // 跨浏览器双键：Chromium 走 service_worker，Firefox MV3 走 event page（scripts）。
  // Firefox 不支持 service_worker；只写单键在 Firefox 下 background 完全缺失 → 扩展死。
  if (!sw) fail('manifest.json background 缺少 service_worker（Chromium MV3 必需）')
  if (!Array.isArray(bgCfg.scripts) || !bgCfg.scripts.length) {
    fail('manifest.json background 缺少 scripts 数组（Firefox MV3 是 event page，只写 service_worker 时背景完全缺失）')
  }
  for (const s of bgCfg.scripts || []) referenced.add(s)
  for (const cs of manifest.content_scripts || []) {
    for (const f of cs.js || []) referenced.add(f)
  }
  for (const page of [manifest.options_page, (manifest.action || {}).default_popup]) {
    if (page) referenced.add(page)
  }
  for (const f of referenced) {
    if (!fs.existsSync(path.join(EXT, f))) fail(`manifest.json 引用了不存在的文件：extension/${f}`)
  }
  // content_scripts 在 manifest 里用蛇形 run_at（与 chrome.scripting 的 API 不同名，
  // 这正是 background.js 那个坑的来源），这里只做"字段确实存在"的存在性检查
  for (const cs of manifest.content_scripts || []) {
    if (!cs.run_at) fail('manifest content_scripts 缺少 run_at（manifest 侧是蛇形，别改）')
    if (!Array.isArray(cs.matches) || !cs.matches.length) fail('manifest content_scripts 缺少 matches')
  }
}

// ── 3. HTML：脚本顺序 + 内联脚本 ─────────────────────────────────────────────
const PAGES = [
  { html: 'options.html', logic: 'options.js' },
  { html: 'popup.html', logic: 'popup.js' },
]
for (const { html, logic } of PAGES) {
  const src = read(html)
  if (!src) continue
  const tags = [...src.matchAll(/<script\b([^>]*)>/gi)].map((m) => m[1])
  for (const attrs of tags) {
    if (!/\bsrc\s*=/i.test(attrs)) {
      fail(`extension/${html} 有内联 <script>：MV3 默认 CSP 会拒绝执行（页面上就是死的）`)
    }
  }
  const order = tags.map((a) => (a.match(/src\s*=\s*"([^"]+)"/i) || [])[1]).filter(Boolean)
  const iShared = order.indexOf('shared.js')
  const iLogic = order.indexOf(logic)
  if (iShared < 0) {
    fail(`extension/${html} 没有引入 shared.js —— 逻辑脚本会因 MASKIT_SHARED 未定义而整页报错`)
  } else if (iLogic < 0) {
    fail(`extension/${html} 没有引入 ${logic}`)
  } else if (iShared > iLogic) {
    fail(`extension/${html} 里 shared.js 必须排在 ${logic} **之前**（否则 const 解构拿到 undefined）`)
  }
  for (const f of order) {
    if (!fs.existsSync(path.join(EXT, f))) fail(`extension/${html} 引用了不存在的脚本：${f}`)
  }
}

// ── 3b. JS 引用的 DOM id 必须在对应 HTML 里存在 ──────────────────────────────
// 补一次真实事故（2026-09-16）：popup.html 的标题只写了 `data-i18n="recentTitle"`
// 而漏了 `id="recentTitle"`，于是 popup.js `$('recentTitle').textContent = …` 必抛
// TypeError。后果**不是**"少一行文案"，而是 init() 被掐断在「绑定按钮事件」之前 ——
// 「刷新 / 设置」一起变死键，界面却照常显示"尚未检测"，用户只能得出"点了没反应"。
// 这类错误静态可判，而 §4 的 i18n 检查看不见它（i18n 键存在、DOM 也在，只是 id 没了）。
// 只认字面量参数；`$('row-' + i)` 这类动态拼接天然跳过（不误报）。
const ID_USE_RE = /\$\('([A-Za-z0-9_-]+)'\)|getElementById\(['"]([A-Za-z0-9_-]+)['"]\)/g
for (const { html, logic } of PAGES) {
  const code = sources[logic]
  const page = read(html)
  if (!code || !page) continue
  const wantIds = new Set()
  for (const m of code.matchAll(ID_USE_RE)) wantIds.add(m[1] || m[2])
  const haveIds = new Set([...page.matchAll(/\bid="([A-Za-z0-9_-]+)"/g)].map((m) => m[1]))
  const miss = [...wantIds].filter((id) => !haveIds.has(id))
  if (miss.length) {
    fail(`extension/${logic} 引用了 ${html} 里不存在的 id：${miss.join(', ')}` +
      '（运行时抛 TypeError，且会在绑定按钮事件前中断整个初始化，表现为"按钮点了没反应"）')
  }
}

// ── 4. i18n 字典 ────────────────────────────────────────────────────────────
/** 从 JS 源码里抠出 `const <name> = {…}` 的平衡字面量并求值（比正则可靠）。 */
function extractObjectLiteral(src, declName) {
  const at = src.indexOf(`const ${declName} = `)
  if (at < 0) throw new Error(`找不到 const ${declName} = `)
  let i = src.indexOf('{', at)
  if (i < 0) throw new Error(`${declName} 后面不是对象字面量`)
  const start = i
  let depth = 0
  let quote = ''
  for (; i < src.length; i++) {
    const ch = src[i]
    if (quote) {
      if (ch === '\\') { i++; continue }
      if (ch === quote) quote = ''
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') { quote = ch; continue }
    if (ch === '{' || ch === '[') depth++
    else if (ch === '}' || ch === ']') {
      depth--
      if (depth === 0) return src.slice(start, i + 1)
    }
  }
  throw new Error(`${declName} 的对象字面量没有闭合`)
}

for (const { html, logic } of PAGES) {
  const src = sources[logic]
  if (!src) continue
  let dict
  try {
    dict = new Function(`return (${extractObjectLiteral(src, 'I18N')})`)()
  } catch (e) {
    fail(`extension/${logic} 的 I18N 无法解析：${e.message}`)
    continue
  }
  const zhKeys = Object.keys(dict.zh || {})
  const enKeys = Object.keys(dict.en || {})
  if (!zhKeys.length || !enKeys.length) {
    fail(`extension/${logic} 的 I18N 缺少 zh 或 en 分支`)
    continue
  }
  const onlyZh = zhKeys.filter((k) => !enKeys.includes(k))
  const onlyEn = enKeys.filter((k) => !zhKeys.includes(k))
  if (onlyZh.length) fail(`extension/${logic} 的 I18N：en 缺 ${onlyZh.join(', ')}`)
  if (onlyEn.length) fail(`extension/${logic} 的 I18N：zh 缺 ${onlyEn.join(', ')}`)

  const htmlSrc = read(html)
  const used = [...htmlSrc.matchAll(/data-i18n(?:-ph)?="([^"]+)"/g)].map((m) => m[1])
  const missing = [...new Set(used)].filter((k) => !zhKeys.includes(k) || !enKeys.includes(k))
  if (missing.length) {
    fail(`extension/${html} 用了字典里没有的 i18n 键：${missing.join(', ')}` +
      '（页面上会渲染成键名或空串）')
  }
  notes.push(`${logic}: i18n ${zhKeys.length} 键 × 2 语言，HTML 用到 ${new Set(used).size} 个`)
}

// ── 5. shared.js 纯函数行为 ─────────────────────────────────────────────────
let SHARED = null
try {
  const ctx = { self: {} }
  vm.createContext(ctx)
  vm.runInContext(sources['shared.js'] || '', ctx, { filename: 'extension/shared.js' })
  SHARED = ctx.self.MASKIT_SHARED
} catch (e) {
  fail(`shared.js 无法在沙箱里求值：${e.message}`)
}
if (SHARED) {
  const cases = [
    // [域名, 期望的 match pattern] —— localhost / IPv4 / IPv6 只能用 http://
    // （manifest 只预授权 http://，写成 *:// 会被 Chrome 拒绝，动态注册静默失效）
    ['chat.deepseek.com', '*://*.chat.deepseek.com/*'],
    ['127.0.0.1', 'http://127.0.0.1/*'],
    ['localhost', 'http://localhost/*'],
    ['[::1]', 'http://[::1]/*'],
    ['ChatGPT.com', '*://*.chatgpt.com/*'],
    ['', ''],
  ]
  for (const [input, want] of cases) {
    const got = SHARED.siteMatchPattern(input)
    if (got !== want) fail(`siteMatchPattern(${JSON.stringify(input)}) = ${JSON.stringify(got)}，期望 ${JSON.stringify(want)}`)
  }
  // 域名校验：只允许 [a-z0-9.*-]，首尾不允许点
  for (const bad of ['', '  ', 'a b.com', 'http://x.com', '.a.com', 'a.com.', 'a/b']) {
    if (SHARED.normalizeDomain(bad) !== '') fail(`normalizeDomain(${JSON.stringify(bad)}) 应为空串`)
  }
  for (const [good, want] of [['ChatGPT.com', 'chatgpt.com'], ['a.b-c.d', 'a.b-c.d'], ['127.0.0.1', '127.0.0.1']]) {
    if (SHARED.normalizeDomain(good) !== want) fail(`normalizeDomain(${JSON.stringify(good)}) 应为 ${want}`)
  }
  // 站点覆盖：必须支持子域，但不能跨域误match（"notchatgpt.com" 不属于 "chatgpt.com"）
  const sites = ['chatgpt.com', 'claude.ai']
  for (const [host, want] of [['chatgpt.com', 'chatgpt.com'], ['chat.openai.chatgpt.com', 'chatgpt.com'],
    ['notchatgpt.com', ''], ['claude.ai', 'claude.ai'], ['evil.com', '']]) {
    const got = SHARED.siteCovers(host, sites)
    if (got !== want) fail(`siteCovers(${host}) = ${JSON.stringify(got)}，期望 ${JSON.stringify(want)}`)
  }
  // STATIC_SITES 必须与 manifest 的静态注册对得上（否则 popup 说已启用、实际没注入）
  if (manifest) {
    const matched = (manifest.content_scripts || []).flatMap((cs) => cs.matches || [])
    for (const site of SHARED.STATIC_SITES) {
      if (!matched.some((m) => m.includes(site))) {
        fail(`STATIC_SITES 里的 ${site} 没出现在 manifest content_scripts.matches —— 静态注册缺失`)
      }
    }
    for (const m of matched) {
      const dom = m.replace(/^\*?:\/\/(\*\.)?/, '').replace(/\/.*$/, '')
      if (!SHARED.STATIC_SITES.includes(dom)) {
        fail(`manifest content_scripts.matches 里的 ${m} 不在 STATIC_SITES 里 —— 两处清单漂移`)
      }
    }
  }
}

// ── 5b. 推荐站点清单（PRESET_SITES） ────────────────────────────────────────
// 这份清单是**用户唯一会看到**的站点来源（设置页 chip + 一键添加），写坏的后果很直接：
//   - 域名不合法 → normalizeDomain 返回 '' → 点 chip 弹出「域名格式不合法」，永远加不上；
//   - 重复域名 → 一键添加时 `permissions.request` 收到重复 origin，用户看到同一个站两次；
//   - `verified` 与 `unsupportedReason` 不一致 → 未实测的站不打 ⚠，用户以为能脱敏，
//     实际静默裸奔（(B) 类直通，界面上完全看不出来）。
// 这些都是"改的人当场看不出来、用户隔几天才发现"的类型，所以必须静态兜住。
if (SHARED) {
  const presets = SHARED.PRESET_SITES
  if (!Array.isArray(presets) || !presets.length) {
    fail('shared.js 的 PRESET_SITES 缺失或为空 —— 设置页的「推荐站点」会是空的')
  } else {
    const seen = new Set()
    for (const p of presets) {
      const d = p && p.domain
      if (typeof d !== 'string' || !d) { fail(`PRESET_SITES 里有缺 domain 的条目`); continue }
      if (SHARED.normalizeDomain(d) !== d) {
        fail(`PRESET_SITES 域名不合法：${d}（normalizeDomain 归一化后应原样返回，只允许小写字母/数字/.-*）`)
      }
      if (seen.has(d)) fail(`PRESET_SITES 域名重复：${d}（一键添加会重复申请同一个 origin）`)
      seen.add(d)
      if (!p.zh || !p.en) fail(`PRESET_SITES 的 ${d} 缺少 zh/en 名称（设置页 chip 上要显示）`)
      if (p.verified !== true && p.verified !== false) {
        fail(`PRESET_SITES 的 ${d} 的 verified 必须是布尔值（true=路径实测命中，false=未实测）`)
        continue
      }
      const reason = SHARED.unsupportedReason(d, '')
      if (!p.verified && reason !== 'paths') {
        fail(`PRESET_SITES 的 ${d} 标了未实测，但 unsupportedReason 返回 ${JSON.stringify(reason)} —— 不会打 ⚠`)
      }
      if (p.verified && reason) {
        fail(`PRESET_SITES 的 ${d} 标了已实测，unsupportedReason 却返回 ${JSON.stringify(reason)} —— 会误打 ⚠`)
      }
    }
    // 静态注册站点必须在推荐清单里且标 verified：否则它既已在 enabledSites 默认项里，
    // 又会出现在"可添加"的 chip 上，用户点了得到一句「该站点已在列表中」。
    for (const s of SHARED.STATIC_SITES) {
      const hit = presets.find((x) => x.domain === s)
      if (!hit) fail(`STATIC_SITES 的 ${s} 不在 PRESET_SITES 里（设置页会把它显示成"可添加"）`)
      else if (hit.verified !== true) fail(`静态注册站点 ${s} 必须标 verified: true（它已在默认站点里）`)
    }
    notes.push(`shared.js: PRESET_SITES ${presets.length} 个推荐站点（${presets.filter((p) => p.verified).length} 个已实测）`)
  }
}

// ── 6/7/9. 源码红线（逐文件扫描） ───────────────────────────────────────────
// 先把注释剥掉再扫：这几个文件里**到处**是"不要用 storage.sync（那是外传）"、
// "http://127.0.0.1 而不是别的主机"这类说明性文字。拿原文扫必然全是误报，
// 而误报的门禁等于没有门禁——两次之后所有人都学会无视它。
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')      // /* 块注释 */
    .replace(/(^|[^:])\/\/.*$/gm, '$1')    // // 行注释（避开 "http://"）
}
for (const name of JS_FILES) {
  const src = sources[name]
  if (!src) continue
  const code = stripComments(src)
  if (/chrome\.storage\.sync/.test(code)) {
    fail(`extension/${name} 使用了 chrome.storage.sync —— 会把数据同步到账号（外传，红线）`)
  }
  // 只允许 127.0.0.1 / localhost 的字面 URL。模板插值（`http://${d}/*`）与变量拼接
  // 不是字面量，跳过——它们由 §5 的纯函数用例单独管（siteMatchPattern）。
  for (const m of code.matchAll(/https?:\/\/[^\s'"`)]+/g)) {
    const host = (m[0].match(/^https?:\/\/([^/:]+)/) || [])[1] || ''
    if (host.includes('$')) continue
    if (!['127.0.0.1', 'localhost'].includes(host)) {
      fail(`extension/${name} 出现非本机字面 URL：${m[0]}（扩展只允许访问 127.0.0.1 / localhost）`)
    }
  }
}
// 驼峰 runAt：蛇形会让 registerContentScripts 抛错 → 被 catch 收进 failures → 静默失效
const bg = sources['background.js'] || ''
if (/registerContentScripts/.test(bg)) {
  const body = bg.slice(bg.indexOf('async function syncDynamicScripts'))
  if (/\brun_at\s*:/.test(body)) {
    fail('background.js 的 registerContentScripts 用了蛇形 run_at —— 必须用驼峰 runAt，' +
      '否则动态注册 100% 静默失效')
  }
  if (!/\brunAt\s*:/.test(body)) {
    fail('background.js 的 registerContentScripts 里没有 runAt 字段')
  }
}
if (!/importScripts\(\s*['"]shared\.js['"]\s*\)/.test(bg)) {
  fail("background.js 缺少 importScripts('shared.js') —— MASKIT_SHARED 未定义，扩展加载即死")
}
// importScripts 只存在于 Worker 环境（Chromium SW）；Firefox MV3 的 event page 没有
// 这个全局，无条件调用会 ReferenceError 让背景直接死。必须由 manifest 的
// background.scripts 先加载 shared.js，并用 typeof 守卫住这条分支。
const importScriptsAt = bg.indexOf("importScripts('shared.js')")
if (importScriptsAt >= 0) {
  const guard = bg.slice(Math.max(0, importScriptsAt - 200), importScriptsAt)
  if (!/typeof\s+importScripts\s*===?\s*['"]function['"]/.test(guard)) {
    fail('background.js 的 importScripts 必须用 `typeof importScripts === \'function\'` 守卫 —— '
      + 'Firefox MV3 背景是 event page，没有 importScripts 全局，无条件调用直接 ReferenceError')
  }
}
// onMessage 必须按 `sender.url` 的 scheme 判定「扩展自己的页面」，不能用 `!sender.tab`。
// 选项页是**真标签页**，sender.tab 有值（2026-09-16 实测）；用 !sender.tab 判会让 admin
// 分支永远进不去、函数末尾返回 undefined → 端口立刻关闭 → 页面侧恒报
// "The message port closed before a response was received"（选项页测试连接/占用/重注册
// 三处同时失灵，而 SW 侧一切正常，极难定位）。
if (/onMessage/.test(bg) && !/sender\.url[\s\S]{0,120}(?:chrome-extension:|moz-extension:)/.test(bg)) {
  fail('background.js 的 onMessage 没有按 sender.url 判定扩展页面 —— ' +
    '以标签页打开的选项页其 sender.tab 有值，用 !sender.tab 判会让 admin 消息全部超时')
}

// ── restore 请求必须带 content_type ─────────────────────────────────────────
// 这是**静默失败**类字段：漏了不报错，引擎只是退回旧的「整段文本还原」，
// 而被 SSE 事件边界切开的占位符（模型逐 token 输出时 `content:"{{EMAIL"` +
// `content:"_dsszcd}}"`）就永远拼不回来，页面露出裸 `{{...}}`。
// 真机往返才暴露过一次（2026-09-16），所以钉死在门禁里。
// 两处都要检查：MAIN world 的调用点，以及 SW 构造 body 时的白名单。
const mainSrc = sources['bridge-main.js'] || ''
const restoreSites = [...mainSrc.matchAll(/bridge\.call\(\s*'restore'/g)]
if (!restoreSites.length) {
  fail("bridge-main.js 里找不到 bridge.call('restore') 调用点 —— 还原链路缺失")
} else {
  for (const site of restoreSites) {
    if (!/content_type\s*:/.test(mainSrc.slice(site.index, site.index + 400))) {
      fail('bridge-main.js 的 restore 调用没带 content_type —— 引擎会退回整段文本还原，' +
        '被 SSE 事件边界切开的占位符将无法还原（页面露出裸 {{...}}）')
    }
  }
}
if (/async function handleRestore/.test(bg)) {
  const at = bg.indexOf('async function handleRestore')
  if (!/content_type\s*:/.test(bg.slice(at, at + 800))) {
    fail('background.js 的 handleRestore 白名单漏了 content_type —— ' +
      '字段在建 body 时被丢掉，还原退化成整段文本（静默失败）')
  }
}

// ── mask / mask_file 调用点必须判 blocking ───────────────────────────────────
// 写方向（明文 → 上游）的失败语义与读方向**相反**，绝不能靠「失败就直通」兜：
// 直通的代价是未脱敏原文出网。
//
// 实测漏过一次（2026-09-19）：maskMultipart 的文本分支有 `if (r && r.blocking)`，
// 而同函数的 OOXML 分支漏了 —— 引擎 413/503 返回 blocking:true 时 `r.ok` 假，
// 代码落到 `if (!replaced)`，**把未脱敏的原文档照原样打包上行**，popup 还按
// 「直通」口径提示。附件是用户主动上传的完整文档，漏脱敏后果比文本链路严重。
//
// restore **故意不检查**：还原失败时 `r.ok` 假 → 透传原文（仍是占位符形态），
// 用户看到 `{{PHONE_x}}` 而不是明文 —— 降级方向安全。别把它也加进来，
// 那只会让页面在引擎抖动时整块报错。
const maskSites = [...mainSrc.matchAll(/bridge\.call\(\s*'(mask|mask_file)'/g)]
if (!maskSites.length) {
  fail("bridge-main.js 里找不到 bridge.call('mask'/'mask_file') 调用点 —— 写方向链路缺失")
} else {
  for (const site of maskSites) {
    if (!/\bblocking\b/.test(mainSrc.slice(site.index, site.index + 600))) {
      fail(`bridge-main.js 的 ${site[1]} 调用点没判 blocking —— 引擎 413/503 时会把` +
        '未脱敏原文（或原文档）直接放行出网，违背 fail-closed 红线')
    }
  }
}

// `callMask()` 是 mask 的封装（6s 超时 + 一次重试，定义见 bridge-main.js）。
// 封装内部已判 blocking，但**调用点**仍必须各自判 —— 否则调用点会把一个非 ok 的
// 结果当成成功继续往下走。这里把封装调用点一并纳入扫描，避免新增一层抽象之后
// 把原来的红线检查架空。
const callMaskSites = [...mainSrc.matchAll(/\bcallMask\(/g)]
for (const site of callMaskSites) {
  if (!/\bblocking\b/.test(mainSrc.slice(site.index, site.index + 600))) {
    fail('bridge-main.js 的 callMask() 调用点没判 blocking —— 引擎 413/503 时会把' +
      '未脱敏原文直接放行出网，违背 fail-closed 红线')
  }
}

// ── 响应还原判据不得用「URL 是否属上传域」 ───────────────────────────────
// `STORAGE_OR_UPLOAD_HOSTS` 里含 claude.ai / chatgpt.com / doubao.com / deepseek.com
// 四个**主域**（为了兜住路径不带 upload/files 关键字的附件端点，属有意为之的保守匹配），
// 于是 `isUploadOrStorageUrl(url)` 在这些站点上**恒为 true**。拿它的**否定形式**当还原
// 判据（曾经写成 `(m.sid && !isUploadOrStorageUrl(url)) ? wrapResponse(...) : res`），
// 结果是主站上走 FormData / Blob 分支的请求**永不还原**，页面永久停在裸 `{{...}}`。
// 唯一正确的判据是「body 是否真被改写」（`m.masked`）。
const badJudge = [...mainSrc.matchAll(/!\s*isUploadOrStorageUrl\s*\(/g)]
if (badJudge.length) {
  fail(`bridge-main.js 里有 ${badJudge.length} 处用 !isUploadOrStorageUrl(url) 作判据 —— ` +
    '该函数对四个主域恒为 true，会让主站的 FormData/Blob 请求永不还原；' +
    '还原判据必须是 m.masked（body 真被改写）')
}

// ── getWideMode 失败必须清缓存 ─────────────────────────────────────────────
// `wideModePromise` 是赋值即缓存。若失败（SW 冷启动时的 config 桥超时）也留在缓存里，
// 该标签页**整个生命周期**都会按精准模式跑 —— 表现为「有些站点完全不脱敏」，
// 且只有手动刷新页面才能恢复（真机上极易被误判成引擎坏了）。
// 因此缓存重置（`wideModePromise = null`）至少要有两处：初始化 + 失败回退。
const wmResets = [...mainSrc.matchAll(/wideModePromise\s*=\s*null/g)].length
if (wmResets < 2) {
  fail('bridge-main.js 的 getWideMode 失败时没有清缓存（wideModePromise = null）——' +
    'SW 冷启动首次 config 桥失败会让整页永久降级为精准模式，只能刷新页面才能恢复')
}

// ── 旧版 Office（.doc / .xls）不得被静默转换，也不得静默放行 ────────────────
// 背景：引擎对 .doc/.xls 的所谓「转换」是**有损重建** —— 用 decode('utf-16le') 从 OLE
// 二进制里捞可读字符串，再塞进手写的极简 OOXML 骨架。实测后果：图片/表格结构/样式/
// 公式/多 sheet 全丢，二进制碎片被当成正文段落捞进去（正文里出现整段乱码），且
// hits==0（文件毫无敏感信息）时**照样改写文件**，体积还可能膨胀（.xls 实测 +127%）。
// 所以默认关闭，改由扩展明确告知「这类格式做不到脱敏，请另存为新格式」。
// 两条红线都属「改的人当场看不出来、用户隔几天才发现」：
//   ① 引擎默认值必须保持 False —— 改回 True 会让所有用户的 .doc 上传在上游变成
//      另一个东西，而界面、日志、popup 上全都看不出来（hits 可能仍是 0）；
//   ② 扩展必须真的计数（legacyCount）并给出**专门**提示（attachTextLegacy）——
//      只报笼统的「附件不脱敏」会让用户以为自己操作错了，而不是格式不支持。
const enginePanelPath = path.join(ROOT, 'engine', 'panel.py')
if (!fs.existsSync(enginePanelPath)) {
  fail('找不到 engine/panel.py —— 旧版 Office 转换默认值无人把关')
} else {
  const enginePanel = fs.readFileSync(enginePanelPath, 'utf8')
  const onDefaults = [...enginePanel.matchAll(/ext_convert_legacy_office[^\n]*?\bTrue\b/g)]
  if (onDefaults.length) {
    fail(`engine/panel.py 有 ${onDefaults.length} 处 ext_convert_legacy_office 默认/回退值为 True —— ` +
      '该转换是有损重建（丢图片/表格/样式、碎片混入正文、无敏感词也改写文件），必须保持默认关闭')
  }
  // 默认表 / 完整默认配置 / 读配置回退 / 运行时状态 四处都要关，漏一处就会重新打开。
  const offDefaults = [...enginePanel.matchAll(/ext_convert_legacy_office[^\n]*?\bFalse\b/g)]
  if (offDefaults.length < 3) {
    fail(`engine/panel.py 只找到 ${offDefaults.length} 处 ext_convert_legacy_office=False —— ` +
      '默认表 / 完整默认配置 / 读配置回退 / 运行时状态四处都要关，漏一处就漏开关')
  }
}
if (!/const LEGACY_OFFICE_EXTS = new Set\(\[/.test(mainSrc)) {
  fail('bridge-main.js 缺少 LEGACY_OFFICE_EXTS —— 旧版 Office 原样上行时无法给出专门提示')
} else if (!/legacyCount/.test(mainSrc)) {
  fail('bridge-main.js 声明了 LEGACY_OFFICE_EXTS 却没有 legacyCount 计数 —— 提示永远不会触发')
}
if (!/legacyCount/.test(sources['background.js'] || '')) {
  fail('background.js 没有透传 legacyCount —— popup 读不到旧版 Office 告警计数')
}
if (!/attachTextLegacy/.test(sources['popup.js'] || '')) {
  fail('popup.js 缺少 attachTextLegacy 文案 —— 旧版 Office 未脱敏时用户只看到笼统的「附件不脱敏」')
}

// ── mask 请求必须带 sid（否则多轮对话的占位符永远还原不回来）───────────────
// 引擎的占位符映射表是**按 sid 隔离**的。此前 `/api/ext/mask` 调用压根不传 sid、
// `mask-file` 传的也基本是空串，于是每轮都新签一个 → 模型引用上一轮（或文档脱敏那次）
// 的占位符时，引擎在当前的表里查不到映射，只能原样吐回页面。
// 用户看到的是「部分没被还原」，事件库里是 restored 与 unresolved 同时有值
// （实测 2026-09-21：一次响应 restored=13 / unresolved=16，且相邻请求 sid 各不相同）。
// 这两条静态可判，而运行时只表现为「少还原了几个字」，极难定位。
const maskCallSites = [...bg.matchAll(/safeCall\(\s*'\/api\/ext\/mask'/g)]
for (const site of maskCallSites) {
  // 简写属性（`{ text, host, sid }`）没有冒号，所以必须同时认 `sid:` 与 `sid,` / `sid }`。
  if (!/sid\s*[:,}]/.test(bg.slice(site.index, site.index + 300))) {
    fail("background.js 的 /api/ext/mask 调用没带 sid —— 每轮新签 sid 会让多轮对话里" +
      '的占位符无法还原（实测 restored 与 unresolved 同时有值）')
  }
}
if (maskCallSites.length && !/async function findRecentSid/.test(bg)) {
  fail('background.js 缺少 findRecentSid —— sid 无法按 tab+host 复用，跨轮次占位符还原不回来')
}
if (/async function findRecentSid/.test(bg) && !/v\.host !== host/.test(bg)) {
  fail('background.js 的 findRecentSid 未按 host 区分 —— 同一标签页切换站点时会串用映射表')
}

// ── 打字探针（autocomplete）必须与主对话映射表隔离 ──────────────────────────
// ChatGPT 的补全接口会在用户点发送**之前**把输入框内容发出去。实测（2026-09-20）
// 送的是未上屏的拼音中间态：`{"input_text":"帮我整合y'xia"}` → NER 把 `y'xia` 判成 NAME，
// `{"input_text":"帮我整合y'x"}` → 把仅 3 字符的 `y'x` 判成 ORG。
// 碎片本身无害，但一旦写进主对话复用表，后续真实文本里出现同样的串就会被替换——跨轮污染。
if (!/function isTypingProbe\s*\(/.test(bg)) {
  fail('background.js 缺少 isTypingProbe —— 打字探针会污染主对话映射表（跳轮误替换）')
}
if (/function isTypingProbe\s*\(/.test(bg) && !/isTypingProbe\(text\)\s*\?\s*null/.test(bg)) {
  fail('打字探针没有隔离 sid —— 必须是 `isTypingProbe(text) ? null : ...`，否则映射仍会跨轮污染')
}
if (!/"num_completions"/.test(bg) || !/"input_text"/.test(bg)) {
  fail('isTypingProbe 的判据丢失 —— 必须按 body 字段判定（补全接口与正常对话同处' +
    ' /backend-api/ 前缀下，按 URL 根本区分不了）')
}
// 判据必须落在**顶层键**上：全文子串匹配的误伤面太大 —— Maskit 的用户就是开发者，
// 把含 `"input_text":` 的日志/JSON 贴进对话是日常，那轮真实对话会被判成探针、
// 不复用 sid，回复里的占位符再也还原不回来，而页面上看不出任何异常。
if (/function isTypingProbe\s*\(/.test(bg)) {
  const at = bg.indexOf('function isTypingProbe')
  const fnBody = bg.slice(at, at + 900)
  if (!/JSON\.parse/.test(fnBody)) {
    fail('isTypingProbe 没有按顶层键判定（缺 JSON.parse）—— 全文子串匹配会把' +
      '「用户贴进对话的含 input_text 的 JSON」误判成补全探针')
  }
  if (/return\s+\/[^\n]*\b(?:input_text|num_completions)\b/.test(fnBody)) {
    fail('isTypingProbe 退回成了全文正则匹配 —— 同上，误伤「把日志贴进对话」的日常场景')
  }
}

// ── XHR 路径必须与 fetch 路径同样处理 URLSearchParams ────────────────────
// fetch 侧早就显式处理了；XHR 少这一支时，用 `application/x-www-form-urlencoded`
// 提交对话的站点会**整站静默漏脱敏**（且原先连留痕都没有）。
if (!/const isUrlParams\s*=/.test(mainSrc) || !/isUrlParams && isUrlMaskable/.test(mainSrc)) {
  fail('bridge-main.js 的 XHR 路径没处理 URLSearchParams —— 表单编码提交对话时会静默漏脱敏')
}

// ── 无感知漏脱敏必须留痕 ───────────────────────────────────────────────────
// `isUrlMaskable && !isMaskableBody` = 我们判定该脱敏，却根本没读到内容。
// 必须在上报之后才放行，否则某站改用 x-protobuf / 二进制 JSON 时会整站静默漏脱敏、
// 页面上毫无异常、事件库里也没有任何线索。
if (!/const reportUnsupportedBody\s*=/.test(mainSrc)) {
  fail('bridge-main.js 缺少 reportUnsupportedBody —— 「该脱敏但 body 打不开」会无声漏掉')
}
if (/const reportUnsupportedBody\s*=/.test(mainSrc) &&
  !/isUrlMaskable\s*&&\s*!isMaskableBody\(resource\)\)\s*\{\s*reportUnsupportedBody\(/.test(mainSrc)) {
  fail('bridge-main.js 未在放行前上报不支持的 body —— 漏脱敏会无感知发生')
}
if (!/handleWarn\(/.test(bg) || !/'\/api\/ext\/warn'/.test(bg)) {
  fail('background.js 缺少 warn 通道 —— 漏脱敏事件进不了事件库')
}

// ── 协议握手：两边的版本号必须一致 ───────────────────────────────────────
// EXT_PROTOCOL_VERSION 是「/api/ext/* 契约版本」，引擎与扩展各存一份。它是**唯一**能
// 发现「客户端改了契约、而用户没重载扩展」的机制，而两边数字一旦漂移，就会**永远误报**
// （或者在真不兼容时反而不报）。所以这里必须交叉比对，不能各查各的存在性。
const sharedSrc = sources['shared.js'] || ''
const popupSrc = sources['popup.js'] || ''
if (!/EXT_PROTOCOL_VERSION/.test(sharedSrc)) {
  fail('shared.js 缺少 EXT_PROTOCOL_VERSION —— 扩展无法发现自己与客户端契约不兼容')
}
const panelPath = path.join(ROOT, 'engine', 'panel.py')
const panelPy = fs.existsSync(panelPath) ? fs.readFileSync(panelPath, 'utf8') : null
const mExt = sharedSrc.match(/EXT_PROTOCOL_VERSION\s*=\s*(\d+)/)
const mEng = panelPy && panelPy.match(/^EXT_PROTOCOL_VERSION\s*=\s*(\d+)/m)
if (mExt && !mEng) {
  fail('engine/panel.py 缺少模块级 EXT_PROTOCOL_VERSION —— 扩展拿到 undefined 会恒报不匹配，' +
    '变成全民误报')
}
if (mExt && mEng && mExt[1] !== mEng[1]) {
  fail(`协议版本不一致：shared.js=${mExt[1]} vs panel.py=${mEng[1]} —— ` +
    '两边必须同步（改契约时一起 +1），否则要么永远误报、要么真不兼容时反而不报')
}
if (!/protoMismatch/.test(bg) || !/applyProtoBadge/.test(bg)) {
  fail('background.js 未做协议握手 —— 契约不兼容时扩展会静默失效（页面无异常、无从归因）')
}
if (!/chrome\.action\.setBadgeText/.test(bg)) {
  fail('协议不匹配未打到图标角标 —— popup 只在点开时可见，最该被注意到的状态反而看不见')
}
if (!/renderProto\(/.test(popupSrc)) {
  fail('popup.js 没有 renderProto —— 协议不匹配时用户看不到任何提示')
}


// ── 文本打码：原函数隔离回归 ───────────────────────────────────────────────
// 只替换网络、存储和状态呈现依赖；不执行扩展生命周期或读取真实配置。
// 引擎延迟按虚拟时间计，避免每次门禁都等完整超时；不是浏览器端到端验证。
try {
  function constDecl(src, name) {
    const match = src.match(new RegExp(`\\bconst\\s+${name}\\s*=\\s*[^;\\n]+;`))
    if (!match) throw new Error(`找不到常量 ${name}`)
    return match[0]
  }
  function functionDecl(src, name) {
    const match = src.match(new RegExp(`^(?:async )?function ${name}\\b[\\s\\S]*?^}`, 'm'))
    if (!match) throw new Error(`找不到函数 ${name}`)
    return match[0]
  }
  const pageConstants = ['MASK_TIMEOUT_MS', 'MASK_TIMEOUT_MS_LARGE', 'MASK_LARGE_CHARS', 'SW_MARGIN_MS']
  const workerConstants = ['CALL_TIMEOUT_MS', 'CALL_TIMEOUT_MS_MAX', 'DOWN_WINDOW_MS', 'PING_TTL_MS',
    'SID_TTL_MS', 'PRUNE_INTERVAL_MS', 'BLOCK_ON_DOWN_KEY', 'AUTH_HOLD_MS', 'AUTH_PROBE_MS']
  const workerFunctions = ['safeCall', 'handleMask', 'isBlocking', 'isTypingProbe', 'isBlockOnDown',
    'restoreBlockWhenDownOnce', 'findRecentSid', 'rememberSid', 'pruneSids']
  const fixtureCode = [
    ...pageConstants.map((name) => constDecl(mainSrc, name)),
    ...workerConstants.map((name) => constDecl(bg, name)),
    ...workerFunctions.map((name) => functionDecl(bg, name)),
    constDecl(mainSrc, 'isLargeText'),
    `const maskOnce = (text) => ${extractObjectLiteral(mainSrc, 'maskOnce')};`,
    `const callMask = async (text) => ${extractObjectLiteral(mainSrc, 'callMask')};`,
    `let downUntil = 0, authHoldUntil = 0, authProbeAt = 0, authHoldErr = '';
     let blockRestorePromise = null, cacheFromPing = false;
     let cache = { at: Date.now(), blockWhenDown: false };
     globalThis.maskTiming = { callMask, handleMask, isLargeText,
       downUntil: () => downUntil, defaultMs: CALL_TIMEOUT_MS, maxMs: CALL_TIMEOUT_MS_MAX };`,
  ].join('\n')

  function fixture({ delayMs = 0, bridgeResults, engineResult, blockWhenDown } = {}) {
    const pageCalls = [], engineCalls = [], statuses = []
    const epochMs = 1_800_000_000_000
    let elapsedMs = 0
    const storage = { 'maskit:pruneAt': epochMs }
    if (typeof blockWhenDown === 'boolean') storage['maskit:blockWhenDown'] = blockWhenDown
    const ctx = {
      Date: { now: () => epochMs + elapsedMs },
      chrome: { storage: { session: {
        async get(key) { return key == null ? { ...storage } : { [key]: storage[key] } },
        async set(values) { Object.assign(storage, values) },
        async remove(keys) { for (const key of keys) delete storage[key] },
      } } },
      getConfig: async () => ({ enabled: true, enabledSites: ['chatgpt.com'] }),
      siteCovers: SHARED.siteCovers,
      setStatus: async (...args) => { statuses.push(args) },
      pushRecent: async () => {},
      refreshPing: async () => { throw new Error('测试不应触发真实 ping') },
      async callPanel(requestPath, body, method, timeoutMs) {
        engineCalls.push({ requestPath, body, method, timeoutMs })
        elapsedMs += Math.min(delayMs, timeoutMs)
        if (delayMs > timeoutMs) {
          const error = new Error('synthetic request aborted')
          error.name = 'AbortError'
          throw error
        }
        return engineResult || { http: 200, data: { ok: true, sid: 'ext:unit-test' } }
      },
      bridge: { async call(action, payload, pageMs) {
        pageCalls.push({ action, payload, pageMs })
        if (bridgeResults) {
          const index = pageCalls.length - 1
          assert.ok(index < bridgeResults.length, '发生了超出约定次数的桥重试')
          return bridgeResults[index]
        }
        return ctx.maskTiming.handleMask(payload, 1, 'chatgpt.com')
      } },
    }
    vm.runInNewContext(fixtureCode, ctx, { filename: 'mask-timeout-fixture', timeout: 1000 })
    return { api: ctx.maskTiming, pageCalls, engineCalls, statuses, elapsedMs: () => elapsedMs }
  }
  let passed = 0, total = 0
  async function check(name, fn) {
    total++
    try { await fn(); passed++ } catch (e) { fail(`文本 mask / ${name}：${e.message}`) }
  }
  const shortText = JSON.stringify({ message: 'short synthetic input' })
  await check('4s 短消息保留 15s 引擎预算', async () => {
    const f = fixture({ delayMs: 4000 })
    assert.equal((await f.api.callMask(shortText)).ok, true)
    assert.equal(f.elapsedMs(), 4000)
    assert.equal(f.pageCalls.length, 1)
    assert.equal(f.engineCalls.length, 1)
    assert.equal(f.engineCalls[0].requestPath, '/api/ext/mask')
    assert.equal(f.engineCalls[0].body.text, shortText)
    assert.equal(f.engineCalls[0].timeoutMs, f.api.defaultMs)
    assert.equal(f.pageCalls[0].pageMs, 18000)
  })
  for (const [length, pageMs, innerMs] of [[4095, 18000, 15000], [4096, 18000, 15000], [4097, 30000, 27000]]) {
    await check(`${length} 字符分档与外 > 内`, async () => {
      const f = fixture()
      const text = 'x'.repeat(length)
      assert.equal(f.api.isLargeText(text), length > 4096)
      assert.equal((await f.api.callMask(text)).ok, true)
      assert.equal(f.pageCalls[0].pageMs, pageMs)
      assert.equal(f.engineCalls[0].timeoutMs, innerMs)
      assert.ok(pageMs > innerMs)
      assert.equal(pageMs - innerMs, 3000)
    })
  }
  const success = { ok: true, sid: 'ext:unit-test' }
  await check('小文本 null 后只重试一次', async () => {
    const f = fixture({ bridgeResults: [null, success] })
    assert.equal(await f.api.callMask(shortText), success)
    assert.equal(f.pageCalls.length, 2)
  })
  await check('小文本两次 null 后停止', async () => {
    const f = fixture({ bridgeResults: [null, null] })
    assert.equal(await f.api.callMask(shortText), null)
    assert.equal(f.pageCalls.length, 2)
  })
  for (const response of [success, { ok: false, passthrough: true, error: 'engine_timeout' },
    { ok: false, blocking: true, error: 'synthetic_rejection' }]) {
    await check(`明确响应不重试 (${response.error || 'success'})`, async () => {
      const f = fixture({ bridgeResults: [response] })
      assert.equal(await f.api.callMask(shortText), response)
      assert.equal(f.pageCalls.length, 1)
    })
  }
  await check('大文本 null 不重试', async () => {
    const f = fixture({ bridgeResults: [null] })
    assert.equal(await f.api.callMask('x'.repeat(4097)), null)
    assert.equal(f.pageCalls.length, 1)
  })
  await check('引擎明确拒绝保持阻断，不重试', async () => {
    const f = fixture({ engineResult: { http: 503, data: { blocking: true, error: 'synthetic_rejection' } },
      blockWhenDown: false })
    const result = await f.api.callMask(shortText)
    assert.equal(result.ok, false)
    assert.equal(result.blocking, true)
    assert.equal(result.error, 'synthetic_rejection')
    assert.equal(f.pageCalls.length, 1)
    assert.equal(f.engineCalls.length, 1)
  })
  for (const choice of [false, true, undefined]) {
    await check(`引擎超时保持用户选择 (${String(choice)}) 且不全局熔断`, async () => {
      const f = fixture({ delayMs: 20000, blockWhenDown: choice })
      const result = await f.api.callMask(shortText)
      assert.equal(result.ok, false)
      assert.equal(result.error, 'engine_timeout')
      if (choice === true) assert.equal(result.blocking, true)
      else assert.equal(result.passthrough, true)
      assert.equal(f.api.downUntil(), 0)
      assert.equal(f.pageCalls.length, 1)
      assert.equal(f.engineCalls.length, 1)
      assert.ok(f.statuses.some((entry) => entry[1] === 'engine_timeout'))
    })
  }
  await check('超上限预算仍钳到 60s', async () => {
    const f = fixture()
    assert.equal((await f.api.handleMask({ text: shortText, timeoutMs: f.api.maxMs + 1000 }, 1, 'chatgpt.com')).ok, true)
    assert.equal(f.engineCalls[0].timeoutMs, 60000)
  })
  await check('已有 1s 下界不变', async () => {
    const f = fixture()
    await f.api.handleMask({ text: shortText, timeoutMs: 1000 }, 1, 'chatgpt.com')
    assert.equal(f.engineCalls[0].timeoutMs, 1000)
  })
  for (const requested of [undefined, 0, 999, -1, 'invalid', NaN, Infinity]) {
    await check(`无效预算回退默认 (${String(requested)})`, async () => {
      const f = fixture()
      await f.api.handleMask({ text: shortText, timeoutMs: requested }, 1, 'chatgpt.com')
      assert.equal(f.engineCalls[0].timeoutMs, f.api.defaultMs)
    })
  }
  await check('文件图片原有两层预算不变', () => {
    const ctx = vm.runInNewContext(`${constDecl(mainSrc, 'HEAVY_CALL_TIMEOUT_MS')};
      ({ pageMs: HEAVY_CALL_TIMEOUT_MS })`, {}, { timeout: 1000 })
    const sw = vm.runInNewContext(`${constDecl(bg, 'HEAVY_CALL_TIMEOUT_MS')};
      ({ innerMs: HEAVY_CALL_TIMEOUT_MS })`, {}, { timeout: 1000 })
    assert.equal(ctx.pageMs, 180000)
    assert.equal(sw.innerMs, 150000)
    assert.ok(ctx.pageMs > sw.innerMs)
  })
  notes.push(`文本 mask 原函数隔离回归：${passed}/${total}（延迟/网络/存储为模拟）`)
} catch (e) {
  fail(`文本 mask 隔离回归无法执行：${e.message}`)
}

// ── 结论 ────────────────────────────────────────────────────────────────────
for (const n of notes) console.log(`check-extension:      ${n}`)
if (errors.length) {
  for (const e of errors) console.log(`check-extension: FAIL ${e}`)
  console.log(`check-extension: FAIL（${errors.length} 项）`)
  process.exit(1)
}
console.log('check-extension: OK')
