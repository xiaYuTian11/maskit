#!/usr/bin/env node
/**
 * .env 导入解析器的边界用例（按需运行，**尚未接进 CI**）。
 *
 * 为什么要留这个脚本：解析器直接决定「哪些值会被当成密钥导入、导进哪个分类」，
 * 而分类名会原样成为占位符 label、决定事件库写不写原文（见 lib/env-import.ts 头注释）。
 * 规则改错是静默的，光靠 UI 手点一遍抓不到边界。
 *
 * 运行前提：Node >= 22.6（用到 --experimental-strip-types 直接跑 .ts 源码）。
 * CI 目前锁 Node 20，跑不了，所以没有接进 frontend job —— 接进去要先升
 * CI 的 node-version 或引入构建步骤，属于 CI 契约变更，另行确认。
 *
 * 用法：node --experimental-strip-types scripts/check-env-import.mjs
 *       （在仓库任意目录执行均可；退出码 0 通过 / 1 失败）
 */
import assert from 'node:assert/strict'
import { parseDotEnv, classifyEnvKey, mergeEntries, previewValue, MAX_WORD_LEN } from '../frontend/src/lib/env-import.ts'

let pass = 0
const cases = []
function t(name, fn) { cases.push([name, fn]) }

// ---------- 解析 ----------
t('基础 KEY=VALUE', () => {
  const r = parseDotEnv('A=aaa\nB=bbb\n')
  assert.deepEqual(r.entries.map((e) => e.key), ['A', 'B'])
  assert.equal(r.entries[1].line, 2)
})

t('空行与整行注释跳过', () => {
  const r = parseDotEnv('\n# 注释\n   \nA=abc\n#尾注释\n')
  assert.equal(r.entries.length, 1)
  assert.equal(r.skipped.length, 0)
})

t('export 前缀', () => {
  const r = parseDotEnv('export OPENAI_API_KEY=sk-abcdefghijklmnop\n')
  assert.equal(r.entries[0].key, 'OPENAI_API_KEY')
  assert.equal(r.entries[0].secret, true)
  assert.equal(r.entries[0].label, 'API_KEY')
})

t('双引号 + 转义', () => {
  const r = parseDotEnv('A="line1\\nline2\\t\\"q\\"\\\\end"\n')
  assert.equal(r.entries[0].value, 'line1\nline2\t"q"\\end')
})

t('双引号内 # 不是注释', () => {
  const r = parseDotEnv('A="p#ss word"\n')
  assert.equal(r.entries[0].value, 'p#ss word')
})

t('单引号内字面（不处理转义）', () => {
  const r = parseDotEnv("A='a\\nb'\n")
  assert.equal(r.entries[0].value, 'a\\nb')
})

t('未加引号的行内注释（# 前有空白才截断）', () => {
  const r = parseDotEnv('A=secretvalue # 说明\nB=has#hash\n')
  assert.equal(r.entries[0].value, 'secretvalue')
  assert.equal(r.entries[1].value, 'has#hash')
})

t('未闭合引号整行跳过', () => {
  const r = parseDotEnv('A="unterminated\n')
  assert.equal(r.entries.length, 0)
  assert.match(r.skipped[0].reason, /引号未闭合/)
})

t('缺 = 与非法变量名', () => {
  const r = parseDotEnv('JUSTTEXT\n1BAD=value\n')
  assert.equal(r.entries.length, 0)
  assert.equal(r.skipped.length, 2)
  assert.match(r.skipped[0].reason, /缺少/)
  assert.match(r.skipped[1].reason, /变量名不合法/)
})

t('BOM 剥除', () => {
  const r = parseDotEnv('\uFEFFA=abcdef\n')
  assert.equal(r.entries.length, 1)
  assert.equal(r.entries[0].key, 'A')
})

t('重复 key：后者覆盖，前者记为跳过', () => {
  const r = parseDotEnv('A=firstval\nA=secondval\n')
  assert.equal(r.entries.length, 1)
  assert.equal(r.entries[0].value, 'secondval')
  assert.equal(r.entries[0].line, 2)
  assert.match(r.skipped[0].reason, /重复定义/)
  assert.equal(r.skipped[0].line, 1)
})

t('空值跳过', () => {
  const r = parseDotEnv('A=\nB="  "\n')
  assert.equal(r.entries.length, 0)
  assert.equal(r.skipped.length, 2)
})

t('过短值跳过（<3 字符）', () => {
  const r = parseDotEnv('DEBUG=1\nOK=ab\nGOOD=abc\n')
  assert.deepEqual(r.entries.map((e) => e.key), ['GOOD'])
  assert.equal(r.skipped.length, 2)
  assert.match(r.skipped[0].reason, /过短/)
})

t('超长值跳过（>200 字符）', () => {
  const long = 'x'.repeat(MAX_WORD_LEN + 1)
  const r = parseDotEnv(`A=${long}\nB=${'y'.repeat(MAX_WORD_LEN)}\n`)
  assert.deepEqual(r.entries.map((e) => e.key), ['B'])
  assert.match(r.skipped[0].reason, /超过上限/)
})

t('CRLF 与 \r 换行', () => {
  const r = parseDotEnv('A=aaaa\r\nB=bbbb\rC=cccc\n')
  assert.deepEqual(r.entries.map((e) => e.key), ['A', 'B', 'C'])
  assert.deepEqual(r.entries.map((e) => e.line), [1, 2, 3])
})

t('值里含 = 号', () => {
  const r = parseDotEnv('TOKEN=abc=def=ghi\n')
  assert.equal(r.entries[0].value, 'abc=def=ghi')
})

// ---------- 分类 ----------
t('键名启发式：各类凭据', () => {
  const want = {
    OPENAI_API_KEY: 'API_KEY',
    AWS_ACCESS_KEY_ID: 'ACCESS_KEY',
    AWS_SECRET_ACCESS_KEY: 'ACCESS_KEY',
    GITHUB_TOKEN: 'TOKEN',
    DB_PASSWORD: 'SECRET',
    MY_SECRET: 'SECRET',
    JWT_SIGNING: 'JWT',
    DATABASE_URL: 'CONNSTR',
    REDIS_DSN: 'CONNSTR',
    SSH_PRIVATE_KEY: 'PRIVATE_KEY',
  }
  for (const [k, label] of Object.entries(want)) {
    const c = classifyEnvKey(k, 'somevalue123')
    assert.equal(c.secret, true, `${k} 应判为凭据`)
    assert.equal(c.label, label, `${k} 分类应为 ${label}`)
  }
})

t('路径类键名不算凭据', () => {
  for (const k of ['SSH_KEY_PATH', 'PRIVATE_KEY_FILE', 'CERT_DIR', 'TOKEN_FILE']) {
    assert.equal(classifyEnvKey(k, '/home/u/.ssh/id_rsa').secret, false, `${k} 不应判为凭据`)
  }
})

t('普通键名不算凭据', () => {
  for (const k of ['COMPANY_NAME', 'DB_HOST', 'LOG_LEVEL', 'ADMIN_EMAIL']) {
    assert.equal(classifyEnvKey(k, 'some-normal-value').secret, false, `${k} 不应判为凭据`)
  }
})

t('值形态兜底：sk- 前缀 / JWT / PEM', () => {
  assert.deepEqual(classifyEnvKey('FOO', 'sk-liveabcdefgh1234'), { secret: true, label: 'API_KEY' })
  assert.deepEqual(classifyEnvKey('FOO', 'ah-abcdefgh1234'), { secret: true, label: 'API_KEY' })
  assert.equal(classifyEnvKey('FOO', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig').label, 'JWT')
  // PEM 头**运行时拼**，不写字面量：完整的 `-----BEGIN … PRIVATE KEY-----` 会触发
  // GitHub Secret Scanning 的形态，`scripts/audit-public-release.py` 会据此拦下公开发布
  // （该脚本的约定就是「测试应运行时构造伪造值，而不是把完整 key 形态写进公开历史」）。
  // 这条用例验的是值形态兜底，不能删，所以只把拼装挪到运行时。
  const pemHead = ['-----BEGIN', 'RSA', 'PRIVATE KEY-----'].join(' ')
  assert.equal(classifyEnvKey('FOO', pemHead).label, 'PRIVATE_KEY')
  // 短前缀值不误判（前缀后必须 ≥8 位）
  assert.equal(classifyEnvKey('FOO', 'sk-demo').secret, false)
})

t('分类目标只落在 CREDENTIAL_LABELS 内', () => {
  const keys = ['A_API_KEY', 'A_TOKEN', 'A_PASSWORD', 'A_SECRET', 'A_ACCESS_KEY', 'A_JWT', 'A_DATABASE_URL', 'A_PRIVATE_KEY']
  const allowed = new Set(['API_KEY', 'TOKEN', 'SECRET', 'ACCESS_KEY', 'JWT', 'CONNSTR', 'PRIVATE_KEY'])
  for (const k of keys) {
    const c = classifyEnvKey(k, 'somevalue123')
    assert.ok(allowed.has(c.label), `${k} 给出的 ${c.label} 不在凭据标签集合内`)
  }
})

// ---------- 预览 ----------
t('凭据预览不泄露主体', () => {
  const p = previewValue('sk-liveabcdefghijklmnop', true)
  assert.ok(!p.includes('liveabc'), `预览泄露了值主体：${p}`)
  assert.ok(p.startsWith('sk') && p.endsWith('op'))
  assert.equal(previewValue('abc', true), '•••')
})

t('非凭据预览保留上下文', () => {
  assert.equal(previewValue('Acme', false), 'Acme')
  assert.ok(previewValue('x'.repeat(50), false).endsWith('…'))
})

// ---------- 合入 ----------
t('合入：去重 + 保留既有词顺序', () => {
  const r = mergeEntries({ SECRET: ['old1', 'old2'] }, [
    { value: 'old1', label: 'SECRET' },
    { value: 'new1', label: 'SECRET' },
    { value: 'new2', label: 'API_KEY' },
  ])
  assert.deepEqual(r.next.SECRET, ['old1', 'old2', 'new1'])
  assert.deepEqual(r.next.API_KEY, ['new2'])
  assert.equal(r.added, 2)
  assert.equal(r.dup, 1)
})

t('合入：不修改入参', () => {
  const existing = { SECRET: ['old1'] }
  mergeEntries(existing, [{ value: 'new1', label: 'SECRET' }])
  assert.deepEqual(existing.SECRET, ['old1'])
})

t('合入：单分类上限', () => {
  const full = { SECRET: Array.from({ length: 500 }, (_, i) => `w${i}`) }
  const r = mergeEntries(full, [{ value: 'overflow', label: 'SECRET' }])
  assert.equal(r.overflow, 1)
  assert.equal(r.added, 0)
  assert.equal(r.next.SECRET.length, 500)
})

// ---------- 端到端样例 ----------
t('真实 .env 样例', () => {
  const sample = [
    '# ---- LLM ----',
    'export OPENAI_API_KEY="sk-proj-abcdefghijklmnopqrst"',
    'ANTHROPIC_API_KEY=ah-anthropic-key-1234567890',
    "DB_PASSWORD='p@ss#word'   # 生产库",
    'DATABASE_URL=postgres://user:secretpw@10.0.0.1:5432/app',
    'COMPANY_NAME=Acme 科技有限公司',
    'LOG_LEVEL=debug',
    'SSH_KEY_PATH=/home/deploy/.ssh/id_rsa',
    'DEBUG=1',
    '',
  ].join('\n')
  const r = parseDotEnv(sample)
  const byKey = Object.fromEntries(r.entries.map((e) => [e.key, e]))
  assert.equal(byKey.OPENAI_API_KEY.label, 'API_KEY')
  assert.equal(byKey.OPENAI_API_KEY.value, 'sk-proj-abcdefghijklmnopqrst')
  assert.equal(byKey.ANTHROPIC_API_KEY.label, 'API_KEY')
  assert.equal(byKey.DB_PASSWORD.value, 'p@ss#word')
  assert.equal(byKey.DB_PASSWORD.label, 'SECRET')
  assert.equal(byKey.DATABASE_URL.label, 'CONNSTR')
  assert.equal(byKey.COMPANY_NAME.secret, false)
  assert.equal(byKey.LOG_LEVEL.secret, false)
  assert.equal(byKey.SSH_KEY_PATH.secret, false)
  assert.ok(!r.entries.some((e) => e.key === 'DEBUG'), 'DEBUG=1 过短应被跳过')
  const secrets = r.entries.filter((e) => e.secret).map((e) => e.key)
  assert.deepEqual(secrets, ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'DB_PASSWORD', 'DATABASE_URL'])
})

let failed = 0
for (const [name, fn] of cases) {
  try {
    fn()
    pass++
  } catch (e) {
    failed++
    console.error(`FAIL  ${name}\n      ${e.message}`)
  }
}
console.log(`\n${pass}/${cases.length} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
