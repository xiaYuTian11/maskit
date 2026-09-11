/**
 * `.env` 解析与智能分类（词库「从 .env 导入」用）。
 *
 * 全部是纯函数、无副作用、不碰 DOM 与网络：解析规则与分类启发式只依赖入参。
 * 前端没有单测框架，所以这里的规则改动后要用 Node 脚本直接跑边界用例验证
 * （见文件末尾的规则说明；不要只靠 UI 手点一遍）。
 */

/**
 * 凭据标签集合。**必须与引擎 `transparent.CREDENTIAL_LABELS` 保持一致。**
 *
 * 为什么这是硬约束而不是「建议」：词库的分类名会原样成为占位符的 label，
 * 引擎按 `label in CREDENTIAL_LABELS` 决定事件库写不写原文 —— 非凭据类写
 * `items[].original` 明文，凭据类只写 digest + preview。把密钥导进一个不在
 * 这个集合里的分类（例如 `PASSWORD` / `APP_SECRET`），等于把密钥明文写进本地
 * SQLite，与「凭据永不落库」的红线直接冲突。所以下面的 SECRET_HINTS 只允许
 * 映射到这里的标签，UI 也据此限制凭据行的可选分类。
 */
export const CREDENTIAL_LABELS = [
  'API_KEY',
  'TOKEN',
  'SECRET',
  'ACCESS_KEY',
  'JWT',
  'CONNSTR',
  'PRIVATE_KEY',
] as const

export type CredentialLabel = (typeof CREDENTIAL_LABELS)[number]

/** 与 `panel.py` 的 `MAX_WORD_LEN` 一致：后端对超长词是**静默丢弃**（只回一条 warning），
 *  所以前端必须先拦下并明确告诉用户，否则用户会以为已经导入成功。 */
export const MAX_WORD_LEN = 200

/** 与 `panel.py` 的 `MAX_ITEMS`（单分类词数上限）一致。 */
export const MAX_ITEMS = 500

/**
 * 过短的值一律不导入。
 *
 * 自定义词是**无边界子串匹配**（只有单字词或显式整词开关才加边界），
 * 实测加 `a1` 会把 `data1` 变成 `dat{{TERM_x}}` —— 把上游 prompt 改坏且极难排查。
 * 批量导入场景下这个错误的代价太大，所以默认拦掉，用户真需要就手工逐条加。
 */
const MIN_WORD_LEN = 3

/** 变量名合法形态（与 dotenv 主流实现一致；比后端 LABEL_RE 更严，避免产出奇怪的分类名）。 */
const KEY_RX = /^[A-Za-z_][A-Za-z0-9_.]*$/

/** 键名以这些后缀结尾时值几乎不会是凭据（是路径/文件名），先排除再走凭据启发式。 */
const NON_SECRET_RX = /(_PATH|_FILE|_DIR|_FOLDER|_HOME|_BIN|_COMMAND|_CMD)$/i

/**
 * 按变量名判定凭据。**顺序即优先级**，顺序是有讲究的：
 * - `PRIVATE_KEY` 必须在通用 KEY 之前，否则 `AWS_PRIVATE_KEY` 会被判成 API_KEY；
 * - `ACCESS_KEY` 排在 `API_KEY` 前：`AWS_SECRET_ACCESS_KEY` 是访问密钥，贴 ACCESS_KEY 更准；
 * - 通用的 `SECRET` / `PASSWORD` 放最后兜底。
 */
const SECRET_HINTS: { re: RegExp; label: CredentialLabel }[] = [
  { re: /PRIVATE[_-]?KEY/i, label: 'PRIVATE_KEY' },
  { re: /(DATABASE[_-]?URL|DB[_-]?URL|DSN|CONNECTION[_-]?STRING|CONN[_-]?STR)/i, label: 'CONNSTR' },
  { re: /(ACCESS[_-]?KEY|AK[_-]?ID)/i, label: 'ACCESS_KEY' },
  { re: /(API[_-]?KEY|APIKEY|APP[_-]?KEY|CLIENT[_-]?ID)/i, label: 'API_KEY' },
  { re: /JWT/i, label: 'JWT' },
  { re: /TOKEN/i, label: 'TOKEN' },
  { re: /(PASSWORD|PASSWD|PWD|SECRET|PASSPHRASE|CREDENTIAL)/i, label: 'SECRET' },
]

/**
 * 按「值形态」判定凭据：变量名不露线索时（`FOO=sk-live-…`）的最后一道网。
 *
 * 只收形态无歧义的几种。误判的代价只是多勾一行（用户取消勾选即可），
 * 漏判的代价是密钥没被脱敏，所以宁可略宽。前缀表与引擎
 * `DEFAULT_SECRET_PREFIXES`（`sk-` / `ah-`）对齐，并要求前缀后至少 8 位。
 */
const VALUE_HINTS: { re: RegExp; label: CredentialLabel }[] = [
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, label: 'PRIVATE_KEY' },
  { re: /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./, label: 'JWT' },
  { re: /^(sk-|ah-)[A-Za-z0-9_-]{8,}/, label: 'API_KEY' },
]

export interface EnvEntry {
  /** 变量名（原样） */
  key: string
  /** 变量值（原文；只存在于内存，用于生成预览与最终导入） */
  value: string
  /** 1-based 行号，便于用户回 .env 核对 */
  line: number
  /** 启发式判定为凭据 —— 决定默认勾选与可选的分类范围 */
  secret: boolean
  /** 建议的目标分类；非凭据条目为空串（由用户选） */
  label: string
}

export interface EnvParseResult {
  entries: EnvEntry[]
  /** 没有进入待导入列表的行：解析失败 / 空值 / 过短 / 过长 / 重复定义。行号 + 原因。 */
  skipped: { line: number; reason: string }[]
}

/** 值预览：凭据只露首尾各 2 位，其余打码；非凭据保留可辨识的少量上下文。 */
export function previewValue(value: string, secret: boolean): string {
  const v = String(value ?? '')
  if (!v) return ''
  if (secret) {
    if (v.length <= 6) return '•'.repeat(v.length)
    return `${v.slice(0, 2)}${'•'.repeat(Math.min(v.length - 4, 16))}${v.slice(-2)}`
  }
  return v.length <= 28 ? v : `${v.slice(0, 25)}…`
}

/**
 * 按变量名（必要时辅以值形态）给出凭据判定与建议分类。
 *
 * `secret` 为 true 时，UI 必须把目标分类限制在 `CREDENTIAL_LABELS` 内 —— 见文件头注释。
 */
export function classifyEnvKey(key: string, value = ''): { secret: boolean; label: string } {
  const k = String(key ?? '')
  if (NON_SECRET_RX.test(k)) return { secret: false, label: '' }
  for (const h of SECRET_HINTS) if (h.re.test(k)) return { secret: true, label: h.label }
  const v = String(value ?? '')
  for (const h of VALUE_HINTS) if (h.re.test(v)) return { secret: true, label: h.label }
  return { secret: false, label: '' }
}

/** 解析 `=` 之后的原始文本。引号未闭合等形态问题在这里拦下。 */
function parseValue(raw: string): { value: string } | { error: string } {
  let i = 0
  while (i < raw.length && (raw[i] === ' ' || raw[i] === '\t')) i++
  if (i >= raw.length) return { value: '' }
  const quote = raw[i]
  if (quote === '"' || quote === "'") {
    i++
    const out: string[] = []
    let closed = false
    while (i < raw.length) {
      const c = raw[i]
      // 单引号内一切字面（与 dotenv 一致）；双引号内处理常见转义
      if (c === '\\' && quote === '"') {
        const n = raw[i + 1]
        if (n === undefined) return { error: '转义符 \\ 后缺少字符' }
        if (n === 'n') {
          out.push('\n')
          i += 2
          continue
        }
        if (n === 'r') {
          out.push('\r')
          i += 2
          continue
        }
        if (n === 't') {
          out.push('\t')
          i += 2
          continue
        }
        if (n === '"' || n === '\\' || n === '$') {
          out.push(n)
          i += 2
          continue
        }
        // 未识别的转义原样保留（不吞字符，免得把 `C:\path` 改坏）
        out.push(c, n)
        i += 2
        continue
      }
      if (c === quote) {
        closed = true
        i++
        break
      }
      out.push(c)
      i++
    }
    if (!closed) return { error: `${quote === '"' ? '双' : '单'}引号未闭合` }
    return { value: out.join('') }
  }
  // 未加引号：到行尾；`#` 起注释，但只在「值首」或「前面是空白」时才算注释
  // （与 dotenv 约定一致，这样 `PASS=a#b` 不会被截成 `a`）
  let end = raw.length
  for (let j = i; j < raw.length; j++) {
    if (raw[j] === '#' && (j === i || raw[j - 1] === ' ' || raw[j - 1] === '\t')) {
      end = j
      break
    }
  }
  return { value: raw.slice(i, end).trim() }
}

/**
 * 解析 .env 文本。
 *
 * 支持：空行 / `#` 整行注释 / `export ` 前缀 / `KEY=VALUE` / 单双引号 /
 * 双引号内的 `\n \r \t \" \\ \$` 转义 / 未加引号值后的行内注释 / 重复 key（后者覆盖前者）。
 * 不支持多行值（引号跨行）—— 遇到未闭合引号会整行跳过并报原因，不做猜测。
 */
export function parseDotEnv(text: string): EnvParseResult {
  const entries: EnvEntry[] = []
  const skipped: { line: number; reason: string }[] = []
  const lineOf = new Map<string, number>()
  const lines = String(text ?? '').split(/\r\n|\r|\n/)
  for (let n = 0; n < lines.length; n++) {
    const lineNo = n + 1
    // 首行可能带 UTF-8 BOM，剥掉，否则变量名第一个字符就不合法
    const line = n === 0 ? lines[n].replace(/^\uFEFF/, '') : lines[n]
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const body = trimmed.replace(/^export\s+/i, '')
    const eq = body.indexOf('=')
    if (eq < 0) {
      skipped.push({ line: lineNo, reason: '缺少 `=`，不是 KEY=VALUE 形态' })
      continue
    }
    const key = body.slice(0, eq).trim()
    if (!KEY_RX.test(key)) {
      skipped.push({ line: lineNo, reason: `变量名不合法：${key || '(空)'}` })
      continue
    }
    const parsed = parseValue(body.slice(eq + 1))
    if ('error' in parsed) {
      skipped.push({ line: lineNo, reason: parsed.error })
      continue
    }
    const value = parsed.value
    if (!value) {
      skipped.push({ line: lineNo, reason: '值为空，没有可脱敏的内容' })
      continue
    }
    if (value.length > MAX_WORD_LEN) {
      skipped.push({ line: lineNo, reason: `值长 ${value.length} 字符，超过上限 ${MAX_WORD_LEN}（后端会静默丢弃）` })
      continue
    }
    if (value.length < MIN_WORD_LEN) {
      skipped.push({ line: lineNo, reason: `值过短（${value.length} 字符），无边界匹配会误伤代码` })
      continue
    }
    const prev = lineOf.get(key)
    if (prev !== undefined) {
      // dotenv 语义：后出现的覆盖先出现的。把先前那条从待导入列表里摘掉并留痕，
      // 免得用户以为两个值都会进词库。
      skipped.push({ line: prev, reason: `重复定义，采用第 ${lineNo} 行的值` })
      const idx = entries.findIndex((e) => e.key === key)
      if (idx >= 0) entries.splice(idx, 1)
    }
    lineOf.set(key, lineNo)
    const cls = classifyEnvKey(key, value)
    entries.push({ key, value, line: lineNo, secret: cls.secret, label: cls.label })
  }
  return { entries, skipped }
}

export interface MergeResult {
  next: Record<string, string[]>
  /** 实际新增的词数 */
  added: number
  /** 因已存在而跳过的词数 */
  dup: number
  /** 因超过单分类上限（MAX_ITEMS）而未加入的词数 */
  overflow: number
}

/**
 * 把勾选的条目合入词库。
 *
 * 注意后端 `POST /api/config` 是**顶层浅合并**：`sensitive` 一旦出现在请求体里
 * 就会整体替换，所以必须带上完整的分类映射（本函数从 existing 全量复制后再追加）。
 */
export function mergeEntries(
  existing: Record<string, string[]>,
  picked: { value: string; label: string }[],
): MergeResult {
  const next: Record<string, string[]> = {}
  for (const [cat, list] of Object.entries(existing ?? {})) next[cat] = [...(list ?? [])]
  let added = 0
  let dup = 0
  let overflow = 0
  for (const p of picked) {
    const cat = String(p.label || '').trim()
    const val = String(p.value || '')
    if (!cat || !val) continue
    const list = next[cat] ?? (next[cat] = [])
    if (list.includes(val)) {
      dup++
      continue
    }
    if (list.length >= MAX_ITEMS) {
      overflow++
      continue
    }
    list.push(val)
    added++
  }
  return { next, added, dup, overflow }
}
