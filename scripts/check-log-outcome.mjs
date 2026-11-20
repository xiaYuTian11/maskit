#!/usr/bin/env node
/**
 * 日志「结论」推导 + MASK/终态折叠的用例门禁（frontend/src/lib/log-outcome.ts、log-events.ts）。
 *
 * 为什么必须有：这两个模块决定**列表里一眼看到的是「成功还是失败」**，而它们的判据全部
 * 来自引擎已落库的字段组合（http_status / unresolved / degraded / decision / completeness /
 * 终态事件类型）。前端没有单测框架，所以固化成 Node 用例跑在 frontend job 里
 * （与 .env 导入解析器、复制工具用例同法）。
 *
 * 三条最值得钉住的不变量（都对应真实误判）：
 *  1. **折叠行的结论不能只看 `type`**：MASK+CANCEL 折成一行后 type 仍是 MASK，
 *     只看 type 会把「已取消」渲染成「进行中 / 成功」。
 *  2. **绝不吞日志**：同 sid 的第三条同类事件、无 sid 的事件必须独立成行。
 *  3. **显式筛选优先于「隐藏噪声」**：旧实现里在下拉选「用户取消」只会得到空列表，
 *     因为 CANCEL 本来就在噪声集合里、而噪声过滤先于筛选生效。
 *
 * 运行前提：Node >= 22.6（--experimental-strip-types 直接跑 .ts 源码）。
 * 用法：node --experimental-strip-types scripts/check-log-outcome.mjs
 *       （在仓库任意目录执行均可；退出码 0 通过 / 1 失败）
 */
import assert from 'node:assert/strict'
import {
  IN_FLIGHT_WINDOW_S,
  OUTCOME_ORDER,
  deriveOutcome,
  describeTerminal,
  outcomeFilterValue,
  outcomeFromFilter,
} from '../frontend/src/lib/log-outcome.ts'
import { FILTER_ALL, mergeMaskRestore } from '../frontend/src/lib/log-events.ts'

/** 固定时间轴：结论里的「进行中 / 未完成」靠 nowSec，写死才能稳定断言。 */
const NOW = 1_800_000_000

/** 造一条事件。只填判据需要的字段，其余留空。 */
const ev = (over) => ({
  seq: 1,
  ts: NOW - 10,
  type: 'MASK',
  sid: 's1',
  host: 'api.example',
  method: 'POST',
  path: '/v1/chat/completions',
  count: 0,
  restored: 0,
  ...over,
})

let pass = 0
const cases = []
function t(name, fn) {
  cases.push([name, fn])
}

// ---------------------------------------------------------------- deriveOutcome

t('成功：MASK 折进 RESTORE 且 HTTP 2xx', () => {
  assert.equal(deriveOutcome(ev({ terminal: 'RESTORE', http_status: 200 }), NOW), 'success')
})

// 2026-11-20 变更：这条原为「也算成功」。真机痛点：用户贴几万字代码做分析时，日志页满屏
// 绿色「成功」，但绝大多数是 0 命中（请求里压根没敏感词），无法区分「保护生效了」与
// 「这次没东西可保护」。现在 scanned_clean 单列为 clean，success 只留给真正命中并脱敏的请求。
t('无敏感词：只扫描未命中（decision=scanned_clean）不再混进成功', () => {
  assert.equal(deriveOutcome(ev({ terminal: 'RESTORE', http_status: 200, decision: 'scanned_clean' }), NOW), 'clean')
})

t('有告警：有未还原占位符（unresolved>0）', () => {
  assert.equal(deriveOutcome(ev({ terminal: 'RESTORE', http_status: 200, unresolved: 2 }), NOW), 'warn')
})

t('有告警：靠宽松兜底还原（degraded>0）', () => {
  assert.equal(deriveOutcome(ev({ terminal: 'RESTORE', http_status: 200, degraded: 1 }), NOW), 'warn')
})

t('有告警：检测不完整（completeness=partial）', () => {
  assert.equal(deriveOutcome(ev({ terminal: 'RESTORE', http_status: 200, completeness: 'partial' }), NOW), 'warn')
})

t('有告警：DNS 失败不算本机故障（不归红）', () => {
  assert.equal(deriveOutcome(ev({ type: 'DNS_ERROR', sid: '' }), NOW), 'warn')
})

t('失败：RESTORE 带 5xx', () => {
  assert.equal(deriveOutcome(ev({ terminal: 'RESTORE', http_status: 502 }), NOW), 'failed')
})

t('失败：decision=blocked（fail-closed 拦截）', () => {
  assert.equal(deriveOutcome(ev({ terminal: 'RESTORE', http_status: 200, decision: 'blocked' }), NOW), 'failed')
})

t('失败：独立 ERR / BLOCK', () => {
  assert.equal(deriveOutcome(ev({ type: 'ERR', sid: '' }), NOW), 'failed')
  assert.equal(deriveOutcome(ev({ type: 'BLOCK', sid: '' }), NOW), 'failed')
})

t('已取消：独立 CANCEL', () => {
  assert.equal(deriveOutcome(ev({ type: 'CANCEL', sid: '' }), NOW), 'canceled')
})

t('已取消：折叠行（type 仍是 MASK，必须看 terminal）', () => {
  // 这是最关键的一条：只看 type 会把它判成「进行中」甚至「成功」
  assert.equal(deriveOutcome(ev({ terminal: 'CANCEL' }), NOW), 'canceled')
})

t('失败：折叠行折进 ERR', () => {
  assert.equal(deriveOutcome(ev({ terminal: 'ERR' }), NOW), 'failed')
})

t('未处理：PASS / BYPASS / SKIP', () => {
  for (const type of ['PASS', 'BYPASS', 'SKIP']) {
    assert.equal(deriveOutcome(ev({ type, sid: '' }), NOW), 'passthrough', type)
  }
})

t('安全告警：SCAN_WARN 审计信号单独成类', () => {
  assert.equal(deriveOutcome(ev({ type: 'SCAN_WARN', sid: '' }), NOW), 'alert')
})

t('进行中：只有 MASK 且仍在窗口内', () => {
  assert.equal(deriveOutcome(ev({ ts: NOW - 5 }), NOW), 'pending')
})

t('未完成：只有 MASK 且超过窗口', () => {
  assert.equal(deriveOutcome(ev({ ts: NOW - IN_FLIGHT_WINDOW_S - 1 }), NOW), 'incomplete')
})

t('边界：正好等于窗口仍算进行中（<=）', () => {
  assert.equal(deriveOutcome(ev({ ts: NOW - IN_FLIGHT_WINDOW_S }), NOW), 'pending')
})

t('未完成：没有 ts 时不敢断言进行中', () => {
  assert.equal(deriveOutcome(ev({ ts: undefined }), NOW), 'incomplete')
})

t('明确直通（decision=passthrough）不判成「未处理」', () => {
  // 「直通未脱敏」由处理摘要列的 chip 表达；结论描述的是「这次请求跑完了没有」
  assert.equal(deriveOutcome(ev({ terminal: 'RESTORE', http_status: 200, decision: 'passthrough' }), NOW), 'success')
})

// ------------------------------------------------------------- describeTerminal

t('终态归因：上游静默带秒数 / 不带秒数', () => {
  assert.deepEqual(describeTerminal({ type: 'CANCEL', reason: 'upstream_idle', upstream_idle_s: 106.06 }), {
    key: 'logs.term.upstreamIdle',
    vars: { s: 106 },
  })
  assert.deepEqual(describeTerminal({ type: 'CANCEL', reason: 'upstream_idle' }), { key: 'logs.term.upstreamIdleNoSec' })
})

t('终态归因：客户端断开 / 客户端取消', () => {
  assert.deepEqual(describeTerminal({ type: 'CANCEL', reason: 'client_disconnected' }), { key: 'logs.term.clientDisconnected' })
  assert.deepEqual(describeTerminal({ type: 'CANCEL', reason: 'client_cancelled' }), { key: 'logs.term.clientCancelled' })
})

t('终态归因：reason 优先于 failure_owner', () => {
  assert.deepEqual(
    describeTerminal({ type: 'CANCEL', reason: 'client_disconnected', failure_owner: 'upstream' }),
    { key: 'logs.term.clientDisconnected' },
  )
})

t('终态归因：ERR 按 failure_owner 分类', () => {
  const want = {
    client: 'logs.term.clientDisconnected',
    dns: 'logs.term.dns',
    proxy: 'logs.term.proxy',
    engine: 'logs.term.engine',
    upstream: 'logs.term.upstream',
  }
  for (const [owner, key] of Object.entries(want)) {
    assert.deepEqual(describeTerminal({ type: 'ERR', failure_owner: owner }), { key }, owner)
  }
})

t('终态归因：没有归因时返回 null（状态列显示「—」）', () => {
  assert.equal(describeTerminal({ type: 'MASK' }), null)
  assert.equal(describeTerminal({ type: 'ERR', failure_owner: 'unknown-owner' }), null)
})

// ------------------------------------------------------------------ 筛选哨兵

t('结论筛选哨兵：往返一致，大小写不敏感，普通类型与未知结论都不认', () => {
  for (const key of OUTCOME_ORDER) {
    assert.equal(outcomeFromFilter(outcomeFilterValue(key)), key)
  }
  // URL 回填会把 ?type= 整体转大写（见 Logs 页），哨兵必须能接住
  assert.equal(outcomeFromFilter('OUTCOME:CANCELED'), 'canceled')
  assert.equal(outcomeFromFilter('outcome:success'), 'success')
  assert.equal(outcomeFromFilter('CANCEL'), null)
  assert.equal(outcomeFromFilter('OUTCOME:not-a-real-outcome'), null)
  assert.equal(outcomeFromFilter(FILTER_ALL), null)
  assert.equal(outcomeFromFilter('OUTCOME:'), null)
})

// ------------------------------------------------------------- mergeMaskRestore

t('折叠：MASK + RESTORE 合成一行，RESTORE 的终态字段覆盖', () => {
  const rows = mergeMaskRestore(
    [
      ev({ seq: 1, ts: NOW - 30, count: 12, upstream: 'ciyuan' }),
      ev({ seq: 2, ts: NOW - 20, type: 'RESTORE', restored: 9, http_status: 200, upstream_ms: 12_400 }),
    ],
    { nowSec: NOW },
  )
  assert.equal(rows.length, 1)
  assert.equal(rows[0].terminal, 'RESTORE')
  assert.equal(rows[0].type, 'MASK')
  assert.equal(rows[0].count, 12)
  assert.equal(rows[0].restored, 9)
  assert.equal(rows[0].http_status, 200)
  assert.equal(rows[0].upstream_ms, 12_400)
  // 时间锚取请求侧（MASK），不是响应侧
  assert.equal(rows[0].ts, NOW - 30)
  assert.equal(deriveOutcome(rows[0], NOW), 'success')
})

t('折叠：MASK + CANCEL 合成一行并带上归因', () => {
  const rows = mergeMaskRestore(
    [
      ev({ seq: 1, ts: NOW - 30, count: 12 }),
      ev({ seq: 2, ts: NOW - 5, type: 'CANCEL', reason: 'client_disconnected', failure_owner: 'client', error_type: 'Error' }),
    ],
    { nowSec: NOW },
  )
  assert.equal(rows.length, 1)
  assert.equal(rows[0].terminal, 'CANCEL')
  assert.equal(rows[0].reason, 'client_disconnected')
  assert.equal(rows[0].failure_owner, 'client')
  assert.equal(deriveOutcome(rows[0], NOW), 'canceled')
  assert.deepEqual(describeTerminal(rows[0]), { key: 'logs.term.clientDisconnected' })
})

t('折叠：MASK + ERR 合成一行，结论为失败', () => {
  const rows = mergeMaskRestore(
    [ev({ seq: 1 }), ev({ seq: 2, type: 'ERR', failure_owner: 'upstream', error_type: 'ReadTimeout' })],
    { nowSec: NOW },
  )
  assert.equal(rows.length, 1)
  assert.equal(rows[0].terminal, 'ERR')
  assert.equal(deriveOutcome(rows[0], NOW), 'failed')
})

t('绝不吞日志：同 sid 的第三条同类事件独立成行', () => {
  const rows = mergeMaskRestore(
    [
      ev({ seq: 1 }),
      ev({ seq: 2, type: 'RESTORE', restored: 3, http_status: 200 }),
      ev({ seq: 3, type: 'RESTORE', restored: 99, http_status: 200 }),
    ],
    { nowSec: NOW },
  )
  assert.equal(rows.length, 2)
  // 已折叠的那行不能被第三条覆盖
  const paired = rows.find((r) => r.terminal === 'RESTORE')
  assert.equal(paired.restored, 3)
  assert.ok(rows.some((r) => r.seq === 3))
})

t('绝不吞日志：没有 sid 的事件独立成行', () => {
  const rows = mergeMaskRestore(
    [ev({ seq: 1 }), ev({ seq: 2, type: 'SCAN_WARN', sid: '' }), ev({ seq: 3, type: 'DNS_ERROR', sid: '' })],
    { nowSec: NOW },
  )
  assert.equal(rows.length, 3)
})

t('排序：按 ts 最新在前', () => {
  const rows = mergeMaskRestore(
    [
      ev({ seq: 1, sid: 'a', ts: NOW - 100 }),
      ev({ seq: 2, sid: 'b', ts: NOW - 10 }),
      ev({ seq: 3, sid: 'c', ts: NOW - 50 }),
    ],
    { nowSec: NOW },
  )
  assert.deepEqual(rows.map((r) => r.sid), ['b', 'c', 'a'])
})

t('噪声：孤立 CANCEL 默认隐藏，已折叠的取消行照常显示', () => {
  const events = [
    ev({ seq: 1, sid: 'paired', count: 1 }),
    ev({ seq: 2, sid: 'paired', type: 'CANCEL', reason: 'client_disconnected' }),
    ev({ seq: 3, sid: 'orphan', type: 'CANCEL', reason: 'client_disconnected' }),
    ev({ seq: 4, sid: 'noise', type: 'SKIP' }),
  ]
  const hidden = mergeMaskRestore(events, { nowSec: NOW, hideNoise: true })
  // paired 折叠行留下（结论=已取消），orphan CANCEL 与 SKIP 被隐藏
  assert.equal(hidden.length, 1)
  assert.equal(hidden[0].terminal, 'CANCEL')
  assert.equal(deriveOutcome(hidden[0], NOW), 'canceled')

  const shown = mergeMaskRestore(events, { nowSec: NOW, hideNoise: false })
  assert.equal(shown.length, 3)
})

t('回归：显式选「用户取消」时不被「隐藏噪声」吞成空列表', () => {
  const events = [
    ev({ seq: 1, sid: 'x', count: 1 }),
    ev({ seq: 2, sid: 'x', type: 'CANCEL', reason: 'client_disconnected' }),
    ev({ seq: 3, sid: 'y', type: 'CANCEL', reason: 'client_disconnected' }),
  ]
  const rows = mergeMaskRestore(events, { nowSec: NOW, hideNoise: true, filterType: 'CANCEL' })
  // 只取 CANCEL 原始事件 → 没有 MASK 可折叠 → 两条独立行，且不被噪声开关吞掉
  assert.equal(rows.length, 2)
  assert.ok(rows.every((r) => r.type === 'CANCEL'))
})

t('回归：显式选「放行与透传」时不被「隐藏噪声」吞成空列表', () => {
  const rows = mergeMaskRestore([ev({ seq: 1, type: 'PASS', sid: '' }), ev({ seq: 2, type: 'SKIP', sid: '' })], {
    nowSec: NOW,
    hideNoise: true,
    filterType: 'PASS_COMBINED',
  })
  assert.equal(rows.length, 2)
})

t('按结论筛选：只留对应结论的行', () => {
  const events = [
    ev({ seq: 1, sid: 'ok', count: 3 }),
    ev({ seq: 2, sid: 'ok', type: 'RESTORE', restored: 3, http_status: 200 }),
    ev({ seq: 3, sid: 'gone', count: 5 }),
    ev({ seq: 4, sid: 'gone', type: 'CANCEL', reason: 'client_disconnected' }),
    ev({ seq: 5, sid: 'bad', count: 1 }),
    ev({ seq: 6, sid: 'bad', type: 'RESTORE', restored: 0, http_status: 502 }),
  ]
  const canceled = mergeMaskRestore(events, { nowSec: NOW, filterType: outcomeFilterValue('canceled') })
  assert.equal(canceled.length, 1)
  assert.equal(canceled[0].sid, 'gone')

  const failed = mergeMaskRestore(events, { nowSec: NOW, filterType: outcomeFilterValue('failed') })
  assert.equal(failed.length, 1)
  assert.equal(failed[0].sid, 'bad')

  const all = mergeMaskRestore(events, { nowSec: NOW, filterType: FILTER_ALL })
  assert.equal(all.length, 3)
})

t('折叠行的详情回源：优先 RESTORE，其次失败归因事件', () => {
  const withRestore = mergeMaskRestore(
    [ev({ seq: 11 }), ev({ seq: 22, type: 'RESTORE', http_status: 200 })],
    { nowSec: NOW },
  )
  assert.equal(withRestore[0]._detailSeq, 22)

  const withCancel = mergeMaskRestore(
    [ev({ seq: 11 }), ev({ seq: 33, type: 'CANCEL', reason: 'client_disconnected' })],
    { nowSec: NOW },
  )
  assert.equal(withCancel[0]._detailSeq, 33)
})

// ------------------------------------------------- G701 / G702 · 「无敏感词」结论
//
// `clean` 与 `success` 必须分开：前者是「扫描通过但一个敏感词都没命中」，后者是「真的命中并
// 脱敏了」。判据只能是引擎的处置结论 `decision=scanned_clean`，**不能**用 `count===0` ——
// count 是派生量，NER 截断时也可能是 0（那类请求 completeness=partial，应先被判 warn）。

t('G702 无敏感词：decision=scanned_clean 且全部正常 → clean', () => {
  const row = ev({ terminal: 'RESTORE', http_status: 200, decision: 'scanned_clean' })
  assert.equal(deriveOutcome(row, NOW), 'clean')
})

t('G702 判据不得是 count：count=0 但没有 decision → 仍是 success', () => {
  const row = ev({ terminal: 'RESTORE', http_status: 200, count: 0 })
  assert.equal(deriveOutcome(row, NOW), 'success')
})

t('G702 判据不得是 count：count=0 且 decision=masked → 仍是 success', () => {
  const row = ev({ terminal: 'RESTORE', http_status: 200, count: 0, decision: 'masked' })
  assert.equal(deriveOutcome(row, NOW), 'success')
})

t('G701 未还原优先：scanned_clean 但 unresolved>0 → warn', () => {
  const row = ev({ terminal: 'RESTORE', http_status: 200, decision: 'scanned_clean', unresolved: 2 })
  assert.equal(deriveOutcome(row, NOW), 'warn')
})

t('G701 兜底还原优先：scanned_clean 但 degraded>0 → warn', () => {
  const row = ev({ terminal: 'RESTORE', http_status: 200, decision: 'scanned_clean', degraded: 1 })
  assert.equal(deriveOutcome(row, NOW), 'warn')
})

t('G701 检测不完整优先：scanned_clean 但 completeness=partial → warn', () => {
  const row = ev({ terminal: 'RESTORE', http_status: 200, decision: 'scanned_clean', completeness: 'partial' })
  assert.equal(deriveOutcome(row, NOW), 'warn')
})

t('G701 HTTP 错误优先：scanned_clean 但 http_status=502 → failed', () => {
  const row = ev({ terminal: 'RESTORE', http_status: 502, decision: 'scanned_clean' })
  assert.equal(deriveOutcome(row, NOW), 'failed')
})

t('G704 clean 可筛出，且与 success 互不串', () => {
  const events = [
    ev({ seq: 1, sid: 'a', decision: 'masked', count: 3 }),
    ev({ seq: 2, sid: 'a', type: 'RESTORE', http_status: 200 }),
    ev({ seq: 3, sid: 'b', decision: 'scanned_clean', count: 0 }),
    ev({ seq: 4, sid: 'b', type: 'RESTORE', http_status: 200 }),
  ]
  const clean = mergeMaskRestore(events, { nowSec: NOW, filterType: outcomeFilterValue('clean') })
  assert.equal(clean.length, 1)
  assert.equal(clean[0].sid, 'b')

  const success = mergeMaskRestore(events, { nowSec: NOW, filterType: outcomeFilterValue('success') })
  assert.equal(success.length, 1)
  assert.equal(success[0].sid, 'a')
})

t('G704 大写回填：URL 整体 toUpperCase 后 OUTCOME:CLEAN 仍能解析', () => {
  assert.equal(outcomeFromFilter('OUTCOME:CLEAN'), 'clean')
})

let failed = 0
for (const [name, fn] of cases) {
  try {
    await fn()
    pass += 1
    console.log(`  ok   ${name}`)
  } catch (err) {
    failed += 1
    console.error(`  FAIL ${name}\n       ${err && err.message ? err.message : err}`)
  }
}
console.log(`check-log-outcome: ${pass}/${cases.length} passed`)
process.exit(failed ? 1 : 0)
