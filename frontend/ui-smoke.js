// LLM Shield 真实 UI 冒烟测试（CDP DOM 级，不依赖截图/窗口遮挡）
// 前置：壳以 WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222 启动
// 用法: node ui-smoke.js [ws-url]（缺省自动探测 http://127.0.0.1:9222/json/list）
async function detectWsUrl() {
  try {
    const res = await fetch('http://127.0.0.1:9222/json/list')
    const list = await res.json()
    const page = list.find((t) => t.type === 'page')
    if (page) return page.webSocketDebuggerUrl
  } catch { /* 忽略 */ }
  return null
}

let WS_URL = process.argv[2]
if (!WS_URL) {
  WS_URL = await detectWsUrl()
  if (!WS_URL) {
    console.error('无法探测 CDP target——壳是否以 --remote-debugging-port=9222 启动？')
    process.exit(1)
  }
}

const ws = new WebSocket(WS_URL)
let msgId = 0
const pending = new Map()

function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++msgId
    pending.set(id, { resolve, reject })
    ws.send(JSON.stringify({ id, method, params }))
  })
}

ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data)
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id)
    pending.delete(msg.id)
    if (msg.error) reject(new Error(msg.error.message))
    else resolve(msg.result)
  }
}

async function evalJs(expression) {
  const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  return r.result?.value
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function checkPage(name) {
  const info = await evalJs(`(() => {
    const body = document.body
    const text = body ? body.innerText.slice(0, 400) : 'NO BODY'
    const err = document.querySelector('[class*="red-500"]')?.innerText || ''
    return { text, err, hasReactRoot: !!document.getElementById('root')?.children.length }
  })()`)
  console.log(`\n===== ${name} =====`)
  console.log('hasReactRoot:', info.hasReactRoot)
  if (info.err) console.log('错误提示:', info.err.slice(0, 200))
  console.log('页面文本:', info.text.replace(/\n+/g, ' | ').slice(0, 300))
}

ws.onopen = async () => {
  try {
    // 启用 Runtime 事件（捕获 console 错误）
    await send('Runtime.enable')
    await send('Log.enable')

    // 收集页面错误
    let jsErrors = []
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data)
      if (msg.id && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id)
        pending.delete(msg.id)
        if (msg.error) reject(new Error(msg.error.message))
        else resolve(msg.result)
      } else if (msg.method === 'Runtime.exceptionThrown') {
        jsErrors.push(msg.params.exceptionDetails?.exception?.description || msg.params.exceptionDetails?.text || 'unknown')
      } else if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
        jsErrors.push(msg.params.entry.text)
      }
    }

    await sleep(3000) // 等应用加载

    // 1. 当前页面（控制台）
    await checkPage('控制台（初始）')

    // 2. 点击日志导航
    await evalJs(`(() => {
      const links = [...document.querySelectorAll('a')]
      const logs = links.find(a => a.getAttribute('href') === '#/logs')
      if (logs) { logs.click(); return 'clicked' }
      return 'NOT FOUND: ' + links.map(a => a.getAttribute('href')).join(',')
    })()`)
    await sleep(3000)
    await checkPage('拦截日志（点击后）')

    // 3. 日志页数据检查
    const logData = await evalJs(`(() => {
      const text = document.body.innerText
      return {
        hasTable: text.includes('类型') && text.includes('路径'),
        hasRows: /MASK|RESTORE|BLOCK|ERR|SCAN_WARN|PASS|BYPASS|SKIP|CANCEL|DNS_ERROR/.test(text),
        sample: text.slice(0, 300)
      }
    })()`)
    console.log('\n===== 日志页数据 =====')
    console.log('含表头:', logData.hasTable, '| 含事件类型行:', logData.hasRows)

    // 4. 其他导航
    for (const [name, href] of [['敏感词库', '#/words'], ['客户端管理', '#/clients'], ['探针审计', '#/audit'], ['高级设置', '#/settings']]) {
      await evalJs(`(() => {
        const links = [...document.querySelectorAll('a')]
        const el = links.find(a => a.getAttribute('href') === '${href}')
        if (el) { el.click(); return 'clicked' }
        return 'NOT FOUND'
      })()`)
      await sleep(2500)
      await checkPage(name)
    }

    console.log('\n===== JS 运行时错误 =====')
    console.log(jsErrors.length ? jsErrors.slice(0, 5) : '无（页面渲染正常）')

    process.exit(0)
  } catch (e) {
    console.error('测试失败:', e)
    process.exit(1)
  }
}
