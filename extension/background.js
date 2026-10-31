/* Data Maskit Browser Bridge — Service Worker
 *
 * 职责：**唯一**与本地引擎（panel，默认 http://127.0.0.1:5801）通信的一方。
 * token 只存在本文件的存储里，绝不进页面上下文、绝不进 postMessage。
 *
 * 安全红线（违反即返工）：
 *  1. 100% 本地：只向 127.0.0.1 / localhost 发请求，不接任何遥测、上报、云端日志；
 *  2. 不用 `chrome.storage.sync`（sync 会把数据同步到账号 = 外传）；
 *  3. 什么都不 `console.log(body)`：MV3 SW 会被回收，且等于把 PII 写进浏览器 profile；
 *  4. `chrome.storage.session` **只存元数据**：sid 签发表 {tabId,host,issuedAt} 与
 *     最近请求缓冲 {ts,host,path,action,count,status}。绝不存 body / 占位符 / 原文 /
 *     响应文本；
 *  5. sid 与 host 都由服务端签发 / SW 从 sender.tab 推导，payload 里的同名字段一律忽略。
 *
 * manifest 故意**不写** `default_locale`：它必须与 `_locales/` 目录同进同出，
 * 只声明字段不建目录会让扩展加载直接失败。UI 文案走文件内的中英对照表。
 */

'use strict';

// 扩展内共享常量与纯函数（STATIC_SITES / UNSUPPORTED_REASON / siteMatchPattern…
// 的唯一来源，见 shared.js 头部说明为何必须收敛成一份）。
// Chromium MV3 背景是 Service Worker：用 importScripts 同步引入；
// Firefox MV3 背景是 Event Page（无 importScripts 全局，直接调会 ReferenceError）：
// 由 manifest 的 background.scripts 数组先加载 shared.js 再执行本文件。
if (typeof importScripts === 'function') {
  importScripts('shared.js');
}
const { STATIC_SITES, siteMatchPattern, siteCovers, isLocalPanelUrl, EXT_PROTOCOL_VERSION } = self.MASKIT_SHARED;

const DEFAULTS = {
  token: '',
  panelUrl: 'http://127.0.0.1:5801',
  enabledSites: STATIC_SITES.slice(),
  enabled: true,
  /**
   * 拦截范围：`true` = 同站 POST 一律送引擎（广泛模式，实验性）；
   *           `false` = 只处理已知对话接口路径（精准模式，默认，无数据污染风险）。
   * 由 bridge-main.js 通过 `config` 消息在首次请求时取一次并缓存（刷新页面生效）。
   */
  wideMode: false,
};

/**
 * 引擎未安装 / 未启动时的引导入口。
 *
 * 为什么必须有：扩展**不能独立工作**——规则引擎、占位符复用表、还原都在本地程序里，
 * 扩展只是把页面请求转发过去。引擎不在时扩展「默默什么都不做」，页面完全正常但内容
 * 裸着发出去，用户根本不知道自己没被保护。这比报错糟糕得多，所以必须**明说**去哪装。
 */
// 从 manifest 的 `homepage_url` 推出来，**不在 JS 里写外域字面 URL** —— 扩展代码里出现
// 非本机主机一律被 `check-extension.mjs` 判失败（那条规则防的正是"扩展偷偷外发"）。
// 这个地址只会被渲染成给用户点开的 `<a href>`，扩展自己永不 fetch 它。
const MANIFEST_HOME = String((chrome.runtime.getManifest && chrome.runtime.getManifest() || {}).homepage_url || '').replace(/\/+$/, '');
const DOWNLOAD_URL = MANIFEST_HOME ? MANIFEST_HOME + '/releases/latest' : '';

/** sid 签发表条目存活上限：对齐引擎复用表 RECENT_TTL(24h)，留 1h 余量。 */
const SID_TTL_MS = 25 * 3600 * 1000;
const PRUNE_INTERVAL_MS = 3600 * 1000;

const RECENT_KEY = 'maskit:recent';
const RECENT_MAX = 50;
/** 最近请求缓冲**只允许**这些字段落库（违反即返工：不得存正文/占位符/原文）。 */
const RECENT_FIELDS = ['ts', 'host', 'path', 'action', 'count', 'status'];

const STATUS_KEY = 'maskit:status';
const UNMATCHED_KEY = 'maskit:unmatched';
const UNMATCHED_MAX = 40;
/** 本页「带文件上传的请求」标记：{tabId: {image, count, at}}。只存有没有、是什么类型。 */
const ATTACH_KEY = 'maskit:attach';

/**
 * 今日计数（**只有计数，绝无正文**）。popup 的「今日计数」需要按日归零，而
 * `/api/ext/ping` 的 `_EXT_STATS` 是 panel 进程启动以来的累计值（进程重启即清零），
 * 口径不同不能混用，所以扩展侧自己记一份日计数。
 * 放 session：跨 SW 回收存活、不落盘；浏览器重启即归零，故 popup 上标明口径。
 */
const DAILY_KEY = 'maskit:daily';

/** (B) 类连接失败后的直通期：期间不再发网络请求，popup 显示「已直通 Ns」。 */
const DOWN_WINDOW_MS = 60000;
const PING_TTL_MS = 60000;
const CALL_TIMEOUT_MS = 15000;

/**
 * 403「配置性拒绝」的退避策略（token 失效 / 面板关开关）。
 *
 * **为什么必须退避**：restore 是**每 SSE chunk 一次**调用。token 失效时每个 chunk 都
 * 会打到 panel → 引擎侧每次经 `_guard_reject` 写一行拒绝日志 → 800 行环形缓冲被一条
 * 回答冲干净，「运行日志」里崩溃现场的 Traceback 全没了（SPEC §5.4 的诊断能力归零）。
 * 实测一条几十 chunk 的回答就能把缓冲刷满，所以这不是理论风险。
 *
 * **为什么不复用 `downUntil`**：那个窗口的语义是「引擎没起来」，popup 显示黄标
 * 「引擎未运行，已直通 Ns」；而 token 失效是**用户配置错了**，必须持续红标
 * 「token 失效，请到设置更新」（SPEC §3.6）。合并成一个窗口等于把「你配置错了」
 * 说成「引擎没起来」，排查方向直接被带偏——这正是 SPEC 反复强调的不对称代价。
 *
 * **为什么不干脆"整段不发请求"**：那会让用户在修复后（改对 token / 打开面板开关）
 * 盲等最多一整段窗口，而等待期内页面流量是**静默未脱敏**的。所以退避期里保留
 * **低速探测**：进入退避后的**下一次调用立刻探测一次**（否则用户在面板重新打开开关
 * 或改对 token 后，第一个请求仍会直通、把明文发出去，最长静默一整个探测间隔 ——
 * 与本条自述的「命中即刻自愈、恢复几乎是即时的」自相矛盾，真机 e2e 长期红着），
 * 之后每 `AUTH_PROBE_MS` 一次。
 * 上限从"每 chunk 一次"降到"每 5s 一次"，日志不再被冲掉，恢复又是即时的。
 */
const AUTH_HOLD_MS = 60000;
const AUTH_PROBE_MS = 5000;

/**
 * R10：`chrome.storage.session` 配额**随 Chrome 版本变**——manifest 定的最低版本 111 上
 * 只有约 1MB（官方文档明示 "Before Chrome 112, the quota was approximately 1 MB"），
 * 112+ 才是约 10MB。所以按 1MB 做预算展示，并只往里放小对象（sid 签发表 + 50 条元数据），
 * 绝不把 session 当通用缓存（popup 里也不塞请求体）。
 */
const SESSION_QUOTA_HINT = 1024 * 1024;

// ── 内存缓存 ────────────────────────────────────────────────────────────────
// 丢了也没关系（可从 panel 重新问），所以放内存；**sid 签发表绝不放这里**：
// MV3 SW 空闲 ~30s 就被终止，内存 Map 必丢，推理模型思考几十秒不吐 chunk 是常态。
let cache = { alive: null, version: '', protocol: null, blockWhenDown: false, recordEvents: true, stats: null, at: 0 };
// cache 是否已经被一次**成功的 ping** 填充过。用来区分「用户的显式选择」与
// 「我们还没拿到过任何值」：前者要执行，后者才允许保守放行（见 restoreBlockWhenDownOnce）。
let cacheFromPing = false;
// 协议握手结果（引擎与扩展对 /api/ext/* 的契约是否一致）。
// 默认 true：在第一次 ping 成功之前我们无法确认契约一致，按「不确定就不承诺」处理。
// 注意它**不进 cache**：cache 会在 ping 失败时被写成 alive:false，而协议不匹配是
// 「引擎可达但契约不对」，两件事必须分开表达。
let protoMismatch = true;
let downUntil = 0;
// 403 配置性拒绝的退避状态（见 AUTH_HOLD_MS 注释）。与 downUntil 分开记：两者展示
// 语义不同（一个黄标「引擎未运行」、一个红标「token 失效/扩展已关闭」），但**都**
// 在 ping 成功时一起清除（自愈）。
let authHoldUntil = 0;
let authHoldErr = '';
// 退避期内下一次允许真实探测的时间：把"每 chunk 打一次 panel"降到"每 AUTH_PROBE_MS 一次"。
let authProbeAt = 0;
let lastStatus = { engine: 'unknown', detail: '', at: 0 };

// ── 配置 ────────────────────────────────────────────────────────────────────

async function getConfig() {
  const stored = await chrome.storage.local.get(Object.keys(DEFAULTS));
  return { ...DEFAULTS, ...stored };
}

async function getPanelUrl() {
  const cfg = await getConfig();
  const raw = String(cfg.panelUrl || '').replace(/\/+$/, '');
  // 令牌**绝不能**发往非本机地址（审计 M3）。
  //
  // 为什么 SW 必须自校验、不能只信 options 页：`panelUrl` 存在 `chrome.storage.local`
  // 里，任何写这个 key 的地方都绕过了保存按钮的校验——实测「测试连接」按钮就贴在地址框
  // 右侧，填个外域点一下就先 `set({panelUrl})` 再 ping，而 `callPanel` 会给这个地址带上
  // `X-Shield-Token`。等于「唯一持有令牌的组件（SW）不校验令牌去哪」。
  //
  // 非法地址**回落默认值而不是抛错**：抛异常会让 mask 链路整体失败 → 扩展按 (B) 直通，
  // 反而变成「静默未脱敏」。回落之后正确的失败模式是「打不通引擎 → 直通 + 黄标」，
  // 而不是「令牌被发到别人的服务器」。
  return isLocalPanelUrl(raw) ? raw : DEFAULTS.panelUrl;
}

// ── 状态与元数据缓冲（都只存元数据） ─────────────────────────────────────────

/**
 * 协议不匹配时在扩展图标上打角标。
 *
 * 为什么必须打到图标上：popup 只在用户主动点开时才看得到，而「契约不兼容」意味着
 * 脱敏语义可能已经不对了——这种状态下最不该依赖用户想起来去点开看。
 * 角标是唯一「不看也会注意到」的通道。
 */
async function applyProtoBadge(mismatch) {
  try {
    await chrome.action.setBadgeText({ text: mismatch ? '!' : '' });
    if (mismatch) await chrome.action.setBadgeBackgroundColor({ color: '#d97706' });
  } catch (e) {
    /* 角标写不进去不能影响主链路 */
  }
}

async function setStatus(engine, detail) {
  const next = { engine, detail: String(detail || '').slice(0, 80), at: Date.now() };
  // 幂等短路：`safeCall` 每 SSE chunk 都会走一遍状态设置，重复写 storage 是纯浪费
  // （一次回答几十上百次 `chrome.storage.session.set`）。状态没变就不落盘，只刷内存。
  const unchanged = lastStatus.engine === next.engine && lastStatus.detail === next.detail;
  lastStatus = next;
  if (unchanged) return;
  try {
    await chrome.storage.session.set({ [STATUS_KEY]: lastStatus });
  } catch (e) {
    /* 状态写不进去不能影响主链路 */
  }
}

async function readStatus() {
  try {
    const got = await chrome.storage.session.get(STATUS_KEY);
    return got[STATUS_KEY] || lastStatus;
  } catch (e) {
    return lastStatus;
  }
}

/**
 * 写「本页最近请求」环形缓冲。**只写元数据**，字段由 RECENT_FIELDS 白名单强制。
 * 目的：回答「到底生效没有」——(B) 类直通是**静默不脱敏**，不点开 popup 完全无感。
 * 失败静默：缓冲写不进去绝不能影响主链路。
 */
async function pushRecent(entry) {
  try {
    const meta = {};
    for (const k of RECENT_FIELDS) {
      if (entry[k] !== undefined) meta[k] = entry[k];
    }
    meta.ts = meta.ts || Date.now();
    await bumpDaily(meta.action);
    const got = await chrome.storage.session.get(RECENT_KEY);
    const list = Array.isArray(got[RECENT_KEY]) ? got[RECENT_KEY] : [];
    list.unshift(meta);
    await chrome.storage.session.set({ [RECENT_KEY]: list.slice(0, RECENT_MAX) });
  } catch (e) {
    /* 同上 */
  }
}

/** 本机日期（本地时区），用于日计数归零判定。 */
function todayKey() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

async function bumpDaily(action) {
  try {
    const day = todayKey();
    const got = await chrome.storage.session.get(DAILY_KEY);
    const prev = got[DAILY_KEY];
    const cur = prev && prev.day === day ? prev : { day, mask: 0, restore: 0, skip: 0 };
    const key = action === 'restore' ? 'restore' : action === 'mask' ? 'mask' : 'skip';
    cur[key] = (cur[key] || 0) + 1;
    await chrome.storage.session.set({ [DAILY_KEY]: cur });
  } catch (e) {
    /* 计数写不进去不影响主链路 */
  }
}

/** 记录「本页 POST 未命中路径白名单」的 path，popup 展示供用户反馈。 */
async function pushUnmatched(tabId, path) {
  try {
    if (!path) return;
    const got = await chrome.storage.session.get(UNMATCHED_KEY);
    const all = got[UNMATCHED_KEY] && typeof got[UNMATCHED_KEY] === 'object' ? got[UNMATCHED_KEY] : {};
    const list = Array.isArray(all[tabId]) ? all[tabId] : [];
    if (!list.includes(path)) list.push(path);
    all[tabId] = list.slice(-UNMATCHED_MAX);
    await chrome.storage.session.set({ [UNMATCHED_KEY]: all });
  } catch (e) {
    /* 同上 */
  }
}

/**
 * 记录「本页有请求带文件上传」。
 *
 * 只记**有没有 + 是不是图片**，绝不记文件名 / 内容 / 数量以外的任何东西。
 * 用途是让 popup 能明说「文件内容不会被脱敏」——静默放行是最坏的一种失败：
 * 用户以为上传的合同/截图也被打过码了，实际上原样进了对方服务器。
 */
async function pushAttachment(tabId, payload) {
  if (!tabId) return;
  try {
    const got = await chrome.storage.session.get(ATTACH_KEY);
    const all = got[ATTACH_KEY] && typeof got[ATTACH_KEY] === 'object' ? got[ATTACH_KEY] : {};
    const prev = all[tabId] || { image: false, count: 0, maskedCount: 0, at: 0 };
    all[tabId] = {
      image: !!prev.image || !!payload.image,
      count: Number(payload.count) || 0,
      maskedCount: Number(payload.maskedCount) || prev.maskedCount || 0,
      // 旧版 Office(.doc/.xls) 未脱敏计数：与 maskedCount 同样「一旦出现过就保留」，
      // 避免同一页面多次上传时，后一次的 payload 把前一次的告警抹掉。
      legacyCount: Number(payload.legacyCount) || prev.legacyCount || 0,
      at: Date.now(),
    };
    await chrome.storage.session.set({ [ATTACH_KEY]: all });
  } catch (e) {
    /* 同上 */
  }
}

// ── sid 签发表（chrome.storage.session：跨 SW 重启存活、不落盘） ───────────────

async function rememberSid(sid, tabId, host) {
  if (!sid) return;
  try {
    await chrome.storage.session.set({ [sid]: { tabId, host, issuedAt: Date.now() } });
    const got = await chrome.storage.session.get('maskit:pruneAt');
    const at = Number(got['maskit:pruneAt'] || 0);
    if (Date.now() - at > PRUNE_INTERVAL_MS) {
      await chrome.storage.session.set({ 'maskit:pruneAt': Date.now() });
      await pruneSids();
    }
  } catch (e) {
    /* 登记失败只影响还原，不影响打码 */
  }
}

/** 清理 issuedAt 超 25h 的签名条目（对齐引擎 RECENT_TTL 的滑动窗口）。 */
async function pruneSids() {
  try {
    const all = await chrome.storage.session.get(null);
    const now = Date.now();
    const stale = [];
    for (const [k, v] of Object.entries(all)) {
      if (!v || typeof v !== 'object' || typeof v.issuedAt !== 'number') continue;
      if (now - v.issuedAt > SID_TTL_MS) stale.push(k);
    }
    if (stale.length) await chrome.storage.session.remove(stale);
  } catch (e) {
    /* ignore */
  }
}

/** 还原前的 sid 校验：必须是本 tab 的、且未过期。storage.session 是异步 API。 */
async function validateSid(sid, tabId) {
  if (!sid) return false;
  try {
    const got = await chrome.storage.session.get(sid);
    const rec = got[sid];
    if (!rec || typeof rec !== 'object') return false;
    return rec.tabId === tabId && Date.now() - rec.issuedAt <= SID_TTL_MS;
  } catch (e) {
    return false;
  }
}

/**
 * 反查该 tab + host 最近签发的 sid，供**复用**引擎侧会话。
 *
 * **为什么必须复用**：引擎的占位符映射表是**按 sid 隔离**的。此前每个请求都新签一个
 * sid（`bridge-main.js` 里 `let sid = null` 且 `/api/ext/mask` 根本不传 sid），于是同一标签页
 * 多轮对话中，模型引用上一轮——或文档脱敏那次——的占位符时，引擎在「当前 sid」的表里
 * 找不到映射，只能把 `{{...}}` 原样吐回页面。事件库里就是 restored 与 unresolved
 * 同时有值（实测 2026-09-21：一次响应 restored=13 / unresolved=16，且相邻请求的 sid
 * 每次都不一样）。用户看到的就是「部分没被还原」。
 *
 * 复用后同一 tab + host 的对话共享一张映射表，跨轮次引用可正常还原；
 * **同一标签页内的重复打码也会因此走滑动窗口复用**（不再为同一个值重复造占位符）。
 * host 变了（切站点）或超 TTL 就自然重新签发。
 *
 * 任何异常一律返回空串 = 退回「新签一个 sid」的旧行为：
 * 最多是这一轮少还原几个占位符，不会影响打码本身。
 */
async function findRecentSid(tabId, host) {
  if (!tabId || !host) return '';
  try {
    const all = await chrome.storage.session.get(null);
    const now = Date.now();
    let best = '';
    let bestAt = -1;
    for (const [k, v] of Object.entries(all || {})) {
      // 只认引擎签发的 sid（`ext:` 前缀），跳过 maskit:* 等元数据键。
      if (!k.startsWith('ext:') || !v || typeof v !== 'object') continue;
      if (v.tabId !== tabId || v.host !== host) continue;
      const at = typeof v.issuedAt === 'number' ? v.issuedAt : 0;
      if (now - at > SID_TTL_MS) continue;
      if (at > bestAt) {
        bestAt = at;
        best = k;
      }
    }
    return best;
  } catch (e) {
    return '';
  }
}

// ── 与 panel 通信 ────────────────────────────────────────────────────────────

/**
 * 调本机 panel。
 *
 * ⚠️ **POST 会带 `Origin: chrome-extension://<扩展ID>`**（2026-09-15 真 Chrome 实测反转了
 * 「SW fetch 不带 Origin」的说法——按 Fetch 规范，非 GET/HEAD 一律附加 Origin，与是否拥有
 * host 权限无关；GET 才不带）。所以引擎侧 `api_guard` 必须为 `/api/ext/*` 放行扩展 scheme 的
 * Origin，否则**每个 mask/restore 都被 403 origin_rejected 打回，扩展按 (B) 直通 →
 * 全站静默未脱敏**（页面看起来完全正常，这是最危险的一种失败）。
 * X-Shield-Token 仍是唯一主防线。
 */
async function callPanel(path, body, method = 'POST', timeoutMs = CALL_TIMEOUT_MS) {
  const base = await getPanelUrl();
  const cfg = await getConfig();
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(base + path, {
      method,
      headers: { 'X-Shield-Token': String(cfg.token || ''), 'Content-Type': 'application/json' },
      body: method === 'GET' ? undefined : JSON.stringify(body || {}),
      signal: ctl.signal,
    });
    let data = null;
    try {
      data = await res.json();
    } catch (e) {
      data = null;      // 解析失败也算 (B)：由调用方的默认桶处理
    }
    return { http: res.status, data };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * (A)/(B) 判定——**白名单式，写死不许改**。
 *
 * 判 (A) 的**唯一**依据是响应里 `blocking === true`（mask 管线异常 503 / 超限 413 /
 * 参数错误 400）。**其余一切**（未枚举的 403、无 blocking 的 500、origin_rejected /
 * host_rejected、DNS/连接/超时错误、JSON 解析失败、未知字段）一律归 (B) 直通，并把
 * 原始 status/error 写进元数据缓冲供排查。
 *
 * 为什么必须这样写：漏归 (A) 只损失一次直通；(B) 误归 (A) 是「网页 AI 全站不可用」
 * 的灾难——两者代价不对称。`api_guard` 实际有四种拒绝路径，穷举天然会漏，所以靠
 * 默认桶兜底而不是靠识别。
 */
function isBlocking(data) {
  return !!(data && data.blocking === true);
}

// 「引擎不可用时阻断」是用户在面板里的**显式选择**，只存在引擎侧 config.json，
// 扩展只能靠 ping 拿到。而 `cache` 是 SW 内存变量（初值 false），SW 被回收后如果
// 引擎正好不可达，取值就回落成 false —— 恰恰在这个开关**唯一有意义**的场景里把用户
// 的选择静默丢掉。所以拿到过就落一份到 session storage，冷启动时回读。
// （用 session 而不是 local：它活过一个 SW 回收周期就够，不需要跨浏览器重启。）
const BLOCK_ON_DOWN_KEY = 'maskit:blockWhenDown';
let blockRestorePromise = null;

/**
 * SW 冷启动后把**曾经从引擎拿到过**的阻断开关读回来。
 *
 * 只回读「拿到过」的值：首次安装 / 从未 ping 通时仍然回落 false —— 不能因为拿不到
 * 开关就擅自把网页打断（否则会在引擎没装时就断送用户的网页 AI）。
 * 区别是「用户的显式选择」与「我们不知道」：前者必须执行，后者才可以保守放行。
 */
function restoreBlockWhenDownOnce() {
  if (!blockRestorePromise) {
    blockRestorePromise = chrome.storage.session
      .get(BLOCK_ON_DOWN_KEY)
      .then((s) => {
        const v = s && s[BLOCK_ON_DOWN_KEY];
        if (!cacheFromPing && typeof v === 'boolean') {
          cache = { ...cache, blockWhenDown: v };
        }
      })
      .catch(() => {});   // 读不到就按「不知道」处理，不影响主流程
  }
  return blockRestorePromise;
}

async function isBlockOnDown() {
  await restoreBlockWhenDownOnce();
  if (Date.now() - cache.at > PING_TTL_MS) {
    await refreshPing().catch(() => {});
  }
  // 未知时回落 false（直通）：宁可少拦一次，也不能因为拿不到开关就把网页打断。
  return cache.blockWhenDown === true;
}

async function refreshPing() {
  let r;
  try {
    r = await callPanel('/api/ext/ping', null, 'GET', 5000);
  } catch (e) {
    // 连接拒绝 / 超时 / DNS：引擎**真的连不上**。
    //
    // 这条分支以前是空的（异常抛给 handlePing 兜底），后果是：状态停在**上一次的
    // 值**不动。上一秒还好好的 → 引擎关掉 → status 仍是 `ok`、popup 仍绿标，
    // 而实际上所有流量都在裸奔。绿标 + 不脱敏是最糟的组合，必须在这里显式标红。
    await setStatus('down', 'engine_unreachable');
    cache = { ...cache, alive: false, at: Date.now() };
    return cache;
  }
  const data = r.data;
  if (r.http === 200 && data && data.ok) {
    cache = {
      alive: true, version: data.version || '',
      protocol: typeof data.ext_protocol === 'number' ? data.ext_protocol : null,
      blockWhenDown: data.block_when_down === true,
      recordEvents: data.record_events !== false,
      stats: data.stats || null, at: Date.now(),
    };
    cacheFromPing = true;
    // 落盘用户的选择：给 SW 冷启动留一条回读路径（见 restoreBlockWhenDownOnce）。
    // 写失败不影响本次 ping 结果（只损失一次冷启动后的回读）。
    try {
      await chrome.storage.session.set({ [BLOCK_ON_DOWN_KEY]: cache.blockWhenDown });
    } catch (e) { /* ignore */ }
    // ── 协议握手 ────────────────────────────────────────────────────
    // 比的是**协议版本**而不是产品版本（理由见 shared.js 的 EXT_PROTOCOL_VERSION 注释）。
    // 握手缺失的代价：客户端改了 /api/ext/* 契约而用户没重载扩展时，扩展会**静默失效**
    // ——页面毫无异常，用户只看到「怎么不脱敏了」，且没有任何地方能归因。
    //
    // `ext_protocol` 缺失（老引擎）也算不匹配：那时无法确认契约一致。
    protoMismatch = cache.protocol !== EXT_PROTOCOL_VERSION;
    await applyProtoBadge(protoMismatch);
    // 自愈：ping 成功即证明「引擎可达 + token 有效 + 面板开关已开」三件事同时成立，
    // 两个退避窗口都没有继续存在的理由，立刻解除。
    // 不这么做的话：用户改对 token 后仍要盲等最多 60s 才恢复脱敏，而这 60s 里的流量
    // 是**静默未脱敏**的——popup 显示绿标、实际在裸奔，是最糟的组合。
    downUntil = 0;
    authHoldUntil = 0;
    authHoldErr = '';
    authProbeAt = 0;
    // 状态也要跟着清：之前可能是 invalid_token（token 填错时打的标），
    // 用户改对后如果只有退避窗口被清、状态没清，popup 会一直红着说 token 失效。
    // 实测：SW 冷启动时空 token 打默认端口必吃 403，状态会被钉在 invalid_token，
    // 不在这里清就再也绿不回来（除非真的发一次对话）。
    await setStatus('ok', '');
    return cache;
  }
  // 401 / 403：**引擎在跑**，只是不认我们（token 错 / 面板把扩展桥关了）。
  //
  // 必须跟「连不上」区分开。不区分的后果：popup 看到 `alive: false` 就显示
  // 「检测到本地引擎没运行，点这里去下载」——用户真的重装一遍，装完还是同一个 403，
  // 排查方向被彻底带偏。这里显式把状态打成 invalid_token / disabled，
  // renderGuide 据此判定「引擎在跑」从而**不**显示下载引导。
  const err = String((data && (data.error || data.reason)) || '');
  if (r.http === 401 || r.http === 403) {
    await setStatus(err === 'ext_bridge_disabled' ? 'disabled' : 'invalid_token',
                    err || ('http_' + r.http));
    // 引擎活着就不该进直通退避窗口，否则会把「token 错」伪装成「引擎挂了」
    downUntil = 0;
    cache = { ...cache, alive: false, at: Date.now() };
    return cache;
  }
  // ping 失败也走默认桶，不改缓存里的开关值（避免"拿不到就改行为"）
  cache = { ...cache, alive: false, at: Date.now() };
  return cache;
}

/**
 * 统一调用入口：熔断 + (A)/(B) 归类。
 * 返回 {ok, body} | {ok:false, blocking:true} | {ok:false, passthrough:true}
 */
async function safeCall(path, body) {
  // 本次调用是否已经处在「配置性拒绝」退避期内。必须在任何分支改动 authHoldUntil
  // 之前取：它决定这次失败是"刚进入退避"（下一次调用立刻探测）还是"探测又失败"
  // （继续按 AUTH_PROBE_MS 间隔，绝不能重置成当下——那等于取消防洪，每 chunk 一行）。
  const inAuthHold = Date.now() < authHoldUntil;
  if (Date.now() < downUntil) {
    // detail 用**稳定字符串**而不是「passthrough 45s」：倒计时由 popup 从
    // downRemainingMs 本地走字（`renderStatus` + 逐秒 tick）。把秒数写进 detail 会让
    // 每一 chunk 的状态都"变了"，既刷 storage 又让 setStatus 的幂等短路失效。
    await setStatus('down', 'engine_unreachable');
    return { ok: false, blocking: await isBlockOnDown(), passthrough: true, error: 'engine_down_window' };
  }
  if (Date.now() < authHoldUntil) {
    if (Date.now() < authProbeAt) {
      // 退避期内：不再逐 chunk 打 panel（否则每 chunk 一条 `_guard_reject` 冲掉日志），
      // 但状态**必须继续红标**，且原因与 down 窗口区分开——这正是 invalid_token 与
      // engine_unreachable 展示不同的原因（SPEC §3.6）。
      await setStatus(authHoldErr === 'ext_bridge_disabled' ? 'disabled' : 'invalid_token', authHoldErr);
      return { ok: false, blocking: await isBlockOnDown(), passthrough: true, error: authHoldErr, http: 403 };
    }
    // 到点放行一次真实请求当探测：状态一旦被修好（改对 token / 打开面板开关），
    // 下一次成功调用就会把退避清掉，用户不必盲等整段窗口。
    authProbeAt = Date.now() + AUTH_PROBE_MS;
    // 不 return，落到下面的真实调用
  }
  let r;
  try {
    r = await callPanel(path, body);
  } catch (e) {
    // ⚠️ 必须区分「引擎慢」与「引擎不在」。
    //
    // `downUntil` 是**全局** 60s 直通窗口，窗口内连 `restore` 也一律透传——而 restore 是
    // **每 SSE chunk 一次**调用，于是一次超时就让**整条回复**（以及所有标签页）的后续
    // chunk 全部丢掉还原，页面上一大段裸 `{{...}}`。真机表现就是「时好时坏、位置随机」。
    //
    // 超时（AbortController 触发）只证明「这一次调用慢」，不构成「引擎挂了」的证据：
    // 引擎侧 `/api/ext/*` 走一把全局锁串行，多标签页并发或 NER 冷启动都可能超 15s。
    // 这类情况只把**本次**按直通处理，不进窗口、不污染其他调用与其他流。
    // 只有连接类错误（ECONNREFUSED / DNS 失败 / 端口没人监听）才进窗口——那才是「引擎不在」。
    const aborted = !!(e && (e.name === 'AbortError' || /abort/i.test(String((e && e.message) || ''))));
    if (aborted) {
      await setStatus('passthrough', 'engine_timeout');
      return { ok: false, blocking: await isBlockOnDown(), passthrough: true, error: 'engine_timeout' };
    }
    // 连接拒绝 / DNS：全属 (B) 默认桶 → 进 60s 直通期
    downUntil = Date.now() + DOWN_WINDOW_MS;
    await setStatus('down', 'engine_unreachable');
    return { ok: false, blocking: await isBlockOnDown(), passthrough: true, error: 'engine_unreachable' };
  }
  const data = r.data;
  if (isBlocking(data)) {
    // (A)：立即阻断，**不熔断**（引擎活着，只是这一单失败）
    await setStatus('error', (data && data.error) || 'engine_error');
    return { ok: false, blocking: true, error: (data && data.error) || 'engine_error' };
  }
  if (r.http >= 200 && r.http < 300 && data && data.ok) {
    downUntil = 0;
    authHoldUntil = 0;
    authHoldErr = '';
    authProbeAt = 0;
    await setStatus('ok', '');
    return { ok: true, body: data };
  }
  // (B) 默认桶：403 ext_bridge_disabled / 403 invalid_token / origin_rejected /
  // host_rejected / 无 blocking 的 500 / 解析失败 …… 全部直通
  const err = (data && data.error) || `http_${r.http}`;
  if (err === 'invalid_token' || err === 'ext_bridge_disabled') {
    // 这两类 403 是**持续性**的（用户配置错了 / 面板开关关着），不会自己好，
    // 所以进退避期；否则 restore 每 chunk 一次会把引擎日志刷爆。
    // 状态分开给：invalid_token 红标「token 失效」，ext_bridge_disabled 红标「扩展已关闭」。
    authHoldUntil = Date.now() + AUTH_HOLD_MS;
    // 首次进入退避：探测点放在**当下**，下一次调用就是一次探测。固定写 `+ AUTH_PROBE_MS`
    // 会让「面板重新打开开关 / 改对 token」后的第一个请求继续直通（明文出网），
    // 最长静默 5s（e2e test_07 覆盖的就是这条）。探测再次失败时保持 5s 间隔，
    // 不会退化成每 chunk 一次（否则面板 800 行环形缓冲会被一条回答冲干净）。
    authProbeAt = inAuthHold ? Date.now() + AUTH_PROBE_MS : Date.now();
    authHoldErr = err;
    await setStatus(err === 'invalid_token' ? 'invalid_token' : 'disabled', err);
  } else {
    await setStatus('passthrough', err);   // 未识别状态：元数据缓冲里能看到 status
    await pushRecent({ host: body && body.host, path, action: 'skip', count: 0, status: `passthrough:${err}` });
  }
  return { ok: false, blocking: await isBlockOnDown(), passthrough: true, error: err, http: r.http };
}

// ── 业务处理 ────────────────────────────────────────────────────────────────

/**
 * 打字探针（autocomplete）判定。
 *
 * 【为什么需要】ChatGPT 等站点有补全接口，会**在用户还没点发送时**就把输入框内容发出去。
 * 实测（2026-09-20）送过来的是**未上屏的拼音中间态**：
 *     {"input_text":"帮我整合y'xia"} → NER 把 "y'xia" 判成 NAME
 *     {"input_text":"帮我整合y'x"}   → NER 把 "y'x"（仅 3 字符）判成 ORG
 * 这些垃圾映射本身无害（碎片不可能与真实姓名碰撞），但一旦写进主对话的复用表，
 * 后续真实文本里出现同样的串就会被替换掉——属**跳轮污染**，用户可见。
 *
 * 【为什么不复用 sid】打字探针**脱敏照做**（隐私不能降：碎片里也可能真带手机号），
 * 但不参与会话复用——映射不跳请求、不进主对话会话，污染面到此为止。
 *
 * 【判据为什么用 body 而不是 URL】这类请求与正常对话同处 `/backend-api/` 前缀下，
 * 路径区分不了；`input_text` / `num_completions` 是补全接口独有的字段。
 * 判定必须在 SW 侧做：页面上报的 payload 一律不可信（与 host/sid 同一条原则）。
 */
function isTypingProbe(text) {
  // 便宜预筛：绝大多数请求两个字段都没有，没必要为它们 JSON.parse。
  if (text.indexOf('"num_completions"') === -1 && text.indexOf('"input_text"') === -1) {
    return false;
  }
  // 必须按**顶层键**判定。全文子串匹配会误伤：用户（Maskit 的用户就是开发者）
  // 把带 `"input_text":` 的日志/JSON 贴进对话是日常，那轮真实对话因此被判成探针、
  // 不复用 sid，回复里的占位符再也还原不回来，而页面上看不出任何异常。
  try {
    const o = JSON.parse(text);
    return !!o && typeof o === 'object' && !Array.isArray(o)
      && ('num_completions' in o || 'input_text' in o);
  } catch (e) {
    return false;   // 非 JSON（multipart 之类）→ 不是探针
  }
}

/**
 * 扩展上报「URL 命中对话白名单，但 body 的 content-type 打不开」。
 *
 * 这是本系统唯一一类无感知漏脱敏（详见 bridge-main.js 的 reportUnsupportedBody）。
 * 引擎侧落一条 SKIP 事件（复用 _emit_skip），reason=unsupported_content_type。
 * 去重与防刷在引擎端点内做，这里只做站点开关与总开关的兜底。
 */
async function handleWarn(payload, tabId, host) {
  const path = payload && typeof payload.path === 'string' ? payload.path : '';
  const ct = payload && typeof payload.content_type === 'string' ? payload.content_type : '';
  const cfg = await getConfig();
  if (cfg.enabled === false) return { ok: false, passthrough: true, error: 'ext_disabled' };
  if (!siteCovers(host, cfg.enabledSites)) return { ok: false, passthrough: true, error: 'site_disabled' };
  const r = await safeCall('/api/ext/warn', { host, path, content_type: ct });
  return r.ok ? r.body : { ok: false };
}

async function handleMask(payload, tabId, host) {
  // payload 里的 host / sid 一律忽略（页面提供不可信）
  const text = payload && typeof payload.text === 'string' ? payload.text : '';
  if (!text) return { ok: false, passthrough: true };

  // 站点开关在这里兜底——**配置是唯一真相来源**。
  //
  // 为什么必须在这一层：chatgpt.com / claude.ai 是 manifest 里静态声明的 content script，
  // 而静态脚本**没法**用 `unregisterContentScripts` 注销（它不是动态注册的）。
  // 于是用户在设置里删掉 ChatGPT 后，脚本照样注入、照样把 body 送过来——
  // 界面显示「已删除」，实际还在打码，这是比"删不掉"更糟的一种撒谎。
  // 不在这里认账，就没有别的地方能拦住了。
  const cfg = await getConfig();
  // 扩展总开关（审计 B3）：`enabled=false` 必须在这里认账。
  //
  // 此前全文件只有 `background.js` 的快照分支读过 `cfg.enabled`，那是**仅供展示**的；
  // 于是用户在设置页取消勾选并保存后，popup 明确显示「扩展已停用」，
  // 而内容脚本照常注入、这里照常把原文送出去打码、页面照常被改写——
  // 界面说一套、字节做一套，与上面站点开关是同一种撒谎（且这次是总开关）。
  //
  // 面板侧的 `ext_bridge_enabled` 是**另一本账**（服务端自己的开关），不能替代这里：
  // 用户关的是扩展，扩展就得自己停下来。直通（而非阻断）与 options 页文案一致：
  // 「关闭后网页请求原样直连」。
  if (cfg.enabled === false) {
    return { ok: false, passthrough: true, error: 'ext_disabled' };
  }
  if (!siteCovers(host, cfg.enabledSites)) {
    return { ok: false, passthrough: true, error: 'site_disabled' };
  }
  // 带上本 tab + host 最近签发的 sid 以复用引擎会话（理由见 findRecentSid）。
  // 不传的后果不是报错而是「部分占位符永远还原不回来」。
  //
  // 打字探针（autocomplete）**例外**：不复用 sid，防止未上屏的拼音碎片被 NER 误判后
  // 混进主对话映射表（跳轮污染，详见 isTypingProbe 注释）。脱敏照做。
  const sid = isTypingProbe(text) ? null : await findRecentSid(tabId, host);
  const r = await safeCall('/api/ext/mask', { text, host, sid });
  if (r.ok) {
    await rememberSid(r.body.sid, tabId, host);
    await pushRecent({ host, path: 'mask', action: 'mask', count: 0, status: 'ok' });
    return r.body;
  }
  if (r.blocking) return { ok: false, blocking: true, error: r.error };
  await pushRecent({ host, path: 'mask', action: 'skip', count: 0, status: 'passthrough' });
  return { ok: false, passthrough: true, error: r.error };
}

async function handleMaskFile(payload, tabId, host) {
  let filename = payload && typeof payload.filename === 'string' ? payload.filename.trim() : '';
  const base64 = payload && typeof payload.base64 === 'string' ? payload.base64 : '';
  // sid 优先用页面传来的（MAIN world 持有本次会话值），没有则复用本 tab+host 最近签发的。
  const sid = (payload && typeof payload.sid === 'string' && payload.sid)
    || (await findRecentSid(tabId, host));
  if (!base64) return { ok: false, passthrough: true };
  if (!filename) filename = 'attachment.xlsx';

  const cfg = await getConfig();
  // 总开关同 handleMask（审计 B3）：文档链路也一样，不能只在文本链路生效。
  if (cfg.enabled === false) {
    return { ok: false, passthrough: true, error: 'ext_disabled' };
  }
  if (!siteCovers(host, cfg.enabledSites)) {
    return { ok: false, passthrough: true, error: 'site_disabled' };
  }
  const r = await safeCall('/api/ext/mask-file', { filename, base64, host, sid });
  if (r.ok) {
    if (r.body && r.body.sid) {
      await rememberSid(r.body.sid, tabId, host);
    }
    await pushRecent({ host, path: `mask-file:${filename}`, action: 'mask', count: (r.body && r.body.hit_count) || 0, status: 'ok' });
    return r.body;
  }
  if (r.blocking) return { ok: false, blocking: true, error: r.error };
  await pushRecent({ host, path: `mask-file:${filename}`, action: 'skip', count: 0, status: 'passthrough' });
  return { ok: false, passthrough: true, error: r.error };
}

async function handleMaskImage(payload, tabId, host) {
  const base64 = payload && typeof payload.base64 === 'string' ? payload.base64 : '';
  const prompt = payload && typeof payload.prompt === 'string' ? payload.prompt : '';
  const sid = (payload && typeof payload.sid === 'string' && payload.sid)
    || (await findRecentSid(tabId, host));
  if (!base64) return { ok: false, passthrough: true };

  const cfg = await getConfig();
  if (cfg.enabled === false) {
    return { ok: false, passthrough: true, error: 'ext_disabled' };
  }
  if (!siteCovers(host, cfg.enabledSites)) {
    return { ok: false, passthrough: true, error: 'site_disabled' };
  }
  const r = await safeCall('/api/ext/mask-image', { base64, prompt, host, sid });
  if (r.ok) {
    if (r.body && r.body.sid) {
      await rememberSid(r.body.sid, tabId, host);
    }
    await pushRecent({ host, path: 'mask-image', action: 'mask', count: (r.body && r.body.hit_count) || 0, status: 'ok' });
    return r.body;
  }
  if (r.blocking) return { ok: false, blocking: true, error: r.error };
  await pushRecent({ host, path: 'mask-image', action: 'skip', count: 0, status: 'passthrough' });
  return { ok: false, passthrough: true, error: r.error };
}

async function handleRestore(payload, host) {
  const text = payload && typeof payload.text === 'string' ? payload.text : '';
  const body = {
    text,
    sid: String((payload && payload.sid) || ''),
    stream_id: String((payload && payload.stream_id) || ''),
    final: !!(payload && payload.final),
    // content-type 是**分帧方式的唯一依据**（引擎据它决定按 SSE 空行 / NDJSON 换行 /
    // 整体处理）。漏传它 → 引擎退回旧的整段文本还原 → 被事件边界切开的占位符永远
    // 拼不回来，页面露出裸 `{{...}}`。这个字段漏了不会报错，只会安静地不还原。
    content_type: String((payload && payload.content_type) || ''),
    host,                       // host 用 SW 推导值，不用 payload 里的
  };
  const r = await safeCall('/api/ext/restore', body);
  if (r.ok) {
    if (body.final) {
      await pushRecent({ host, path: 'restore', action: 'restore', count: 0, status: 'ok' });
    }
    return r.body;
  }
  // 还原方向**恒透传**（红线 3）：连 (A) 也不在这里阻断——打码那一步已经拦过了，
  // 还原失败再阻断只会让用户看到半截响应。
  if (body.final) {
    await pushRecent({ host, path: 'restore', action: 'skip', count: 0, status: 'passthrough' });
  }
  return { ok: false, text };
}

async function handlePing() {
  try {
    return await refreshPing();
  } catch (e) {
    return { alive: false, version: '', blockWhenDown: false, recordEvents: true, stats: null };
  }
}

/** popup / options 需要的汇总（只读元数据，绝不含正文）。 */
async function handleAdmin(op) {
  if (op === 'snapshot') {
    const cfg = await getConfig();
    const session = await chrome.storage.session.get(null);
    const sids = Object.entries(session).filter(([, v]) => v && typeof v === 'object' && typeof v.issuedAt === 'number');
    let bytes = null;
    try {
      // R10：manifest 定的最低版本 111 上 storage.session 配额只有 ~1MB
      // （Chrome 112 才提到 ~10MB），所以必须能量化观察占用
      bytes = await chrome.storage.session.getBytesInUse(null);
    } catch (e) {
      bytes = null;
    }
    return {
      ok: true,
      config: {
        enabled: cfg.enabled, panelUrl: cfg.panelUrl,
        enabledSites: cfg.enabledSites, hasToken: !!cfg.token,
        wideMode: cfg.wideMode === true,
      },
      status: await readStatus(),
      recent: (await chrome.storage.session.get(RECENT_KEY))[RECENT_KEY] || [],
      unmatched: (await chrome.storage.session.get(UNMATCHED_KEY))[UNMATCHED_KEY] || {},
      // 本页是否出现过带文件的请求（用于提示「附件/图片内容不脱敏」）
      attachments: (await chrome.storage.session.get(ATTACH_KEY))[ATTACH_KEY] || {},
      // 引擎不在时 popup 要给的去向——扩展不能独立工作，必须明说去哪装
      downloadUrl: DOWNLOAD_URL,
      // 协议握手：不一致时 popup 必须显式报出来，不能等用户自己发现「怎么不脱敏了」
      protoMismatch,
      engineProtocol: (cache && typeof cache.protocol === 'number') ? cache.protocol : null,
      daily: (await chrome.storage.session.get(DAILY_KEY))[DAILY_KEY] || null,
      sidCount: sids.length,
      sessionBytes: bytes,
      sessionQuotaBytes: SESSION_QUOTA_HINT,
      downRemainingMs: Math.max(0, downUntil - Date.now()),
      // 403 配置性拒绝的退避剩余：popup 据此在红标里走字「Ns 后自动重试」，
      // 否则用户改对 token 后只看到红标不变，以为没生效（见 AUTH_HOLD_MS 注释）。
      authHoldRemainingMs: Math.max(0, authHoldUntil - Date.now()),
      authHoldError: authHoldErr,
      cache,
    };
  }
  if (op === 'ping') return { ok: true, ping: await handlePing() };
  if (op === 'clearRecent') {
    await chrome.storage.session.set({ [RECENT_KEY]: [], [UNMATCHED_KEY]: {}, [STATUS_KEY]: { engine: 'unknown', detail: '', at: Date.now() } });
    return { ok: true };
  }
  if (op === 'resync') {
    const failed = await syncDynamicScripts();
    return { ok: true, failed };
  }
  // 这里**故意没有** `rotateToken`：`/api/ext/rotate-token` 是 API_TOKEN 鉴权
  // （SPEC §5.3 T9 断言「ext_token 打 rotate-token → 403」），而扩展手里只有
  // ext_token —— 这个 op 100% 失败。它原先存在，只是因为 options 页有个
  // 「在本机面板旋转」按钮在用 ext_token 去调；那个按钮已改成打开面板设置页。
  // 与其留一个必然报错的死路径，不如不留（要旋转去面板，那里才有 API_TOKEN）。
  return { ok: false, error: 'unknown_op' };
}

// ── 消息入口 ────────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || sender.id !== chrome.runtime.id) return;

  // ⚠️ 判定「是不是扩展自己的页面」**绝不能**用 `!sender.tab`。
  //
  // 实测（2026-09-16，真 Chrome）：以标签页打开的选项页，其 sender 是
  // `{ id: '<extId>', tab: {…}, url: 'chrome-extension://<extId>/options.html' }` ——
  // **`sender.tab` 是有值的**（它确实占着一个浏览器标签页）。于是 `!sender.tab` 为假，
  // admin 分支永远进不去，函数一路走到末尾返回 undefined；因为没有 `return true`，
  // 消息端口立刻关闭，页面侧恒收到：
  //     "The message port closed before a response was received."
  // 表现到界面上就是：选项页「测试连接」永远报失败、会话占用那行永远空白、
  // 添加站点后拿不到重注册确认（而 SW 侧其实一切正常）——三处症状同一个根因。
  //
  // popup 不受影响（它不是 tab），所以这个 bug 只在选项页出现，很容易被漏掉。
  // 支持多浏览器扩展内部协议：Chromium (chrome-extension:)、Firefox (moz-extension:)、Safari (safari-web-extension:)
  const senderUrl = String((sender && sender.url) || '');
  const fromExtPage = senderUrl.startsWith('chrome-extension:') ||
                      senderUrl.startsWith('moz-extension:') ||
                      senderUrl.startsWith('safari-web-extension:');
  if (fromExtPage) {
    // 扩展自身页面（popup / options）：只能做管理动作，且**不参与**打码链路
    // ——host 必须从真实网页的 tab 推导，所以这里不给 mask/restore。
    if (msg.action === 'admin') {
      handleAdmin(msg.op).then(sendResponse).catch((e) => sendResponse({ ok: false, error: String(e) }));
      return true;
    }
    return;
  }

  // 打码链路：只认真实网页里的 content script。
  // 优先取 sender.url（当前 frame 自身的真实 URL），避免 iframe 嵌 AI 页面因顶层域不同被误拦
  if (!sender.tab) return;
  const host = safeHostname(sender.url || sender.tab.url);
  const tabId = sender.tab.id;
  if (msg.action === 'mask') {
    handleMask(msg.payload, tabId, host).then(sendResponse).catch((e) => sendResponse({ ok: false, passthrough: true, error: String(e) }));
    return true;
  }
  if (msg.action === 'mask_file') {
    handleMaskFile(msg.payload, tabId, host).then(sendResponse).catch((e) => sendResponse({ ok: false, passthrough: true, error: String(e) }));
    return true;
  }
  if (msg.action === 'mask_image') {
    handleMaskImage(msg.payload, tabId, host).then(sendResponse).catch((e) => sendResponse({ ok: false, passthrough: true, error: String(e) }));
    return true;
  }
  if (msg.action === 'warn') {
    // 可观测性通道：只上报元数据，失败也不影响请求链路。
    handleWarn(msg.payload, tabId, host).then(sendResponse).catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
  if (msg.action === 'restore') {
    // 校验 sid 属于该 tab（storage.session 异步读）
    validateSid(msg.payload && msg.payload.sid, tabId).then(async (ok) => {
      if (!ok) {
        // 签发表查不到（SW 冷启动读不到 session storage / 扩展更新把它清了 / 真的跨 tab）：
        // 按安全门**不还原**、原样透传（绝不借全局复用表还原）。但这必须留痕——否则
        // 页面上一大段裸 `{{...}}` 与「引擎坏了」在用户侧完全无法区分（真机排查时被误判过）。
        // 只记 final 那一帧，避免每 chunk 一行把元数据缓冲刷掉。
        if (msg.payload && msg.payload.final) {
          await pushRecent({ host, path: 'restore', action: 'skip', count: 0, status: 'sid_denied' });
        }
        sendResponse({ ok: false, text: (msg.payload && msg.payload.text) || '' });
        return;
      }
      handleRestore(msg.payload, host)
        .then(sendResponse)
        .catch((e) => sendResponse({ ok: false, text: (msg.payload && msg.payload.text) || '' }));
    });
    return true;
  }
  if (msg.action === 'ping') {
    handlePing().then(sendResponse).catch(() => sendResponse({ alive: false }));
    return true;
  }
  if (msg.action === 'note') {
    // 「本页 POST 未命中白名单」的 path（只存 path，不含 query 之外的任何内容）
    if (msg.payload && msg.payload.kind === 'unmatched_post') {
      pushUnmatched(tabId, String(msg.payload.path || '').slice(0, 200));
    }
    // 「本页有请求带文件上传」：只记类型，不记内容
    if (msg.payload && msg.payload.kind === 'attachment') {
      pushAttachment(tabId, msg.payload);
    }
    sendResponse({ ok: true });
    return true;
  }
  if (msg.action === 'config') {
    // 拦截范围下发（MAIN world 读不到 chrome.storage，只能问 SW）。
    // 只回非敏感的行为开关；token / panelUrl 一律不给页面上下文。
    getConfig()
      .then((c) => sendResponse({ wideMode: c.wideMode === true }))
      .catch(() => sendResponse({ wideMode: false }));
    return true;
  }
});

function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return '';
  }
}

// ── 动态站点注册（权限手势 + 重注册） ─────────────────────────────────────────
//
// 【未实测，按 Chrome 公开行为设计】静态 content_scripts 已覆盖默认两站；用户新增的站点
// 走动态注册：options 页在**用户手势内**先 `chrome.permissions.request({origins})`，
// 成功后让 SW 重注册（单一写入者，避免 options 与 SW 各注册一遍互相覆盖）。
// `onInstalled` + `onStartup` 都会重注册——动态注册的内容脚本在 SW 重启后**不保证**还在。
//
// 返回未能注册的脚本（未授权 / 非法 match 等），由 options 如实展示，不静默吞掉。
//
// ⚠️ 一个**实测踩过**的坑（2026-09-15，真 Chrome + Playwright）：
//   ① 字段名是 **`runAt`（驼峰）**，不是 `run_at`。manifest 里写 `run_at`，
//      但 `chrome.scripting.registerContentScripts()` 的 ScriptInjection 对象用的是
//      `runAt`。写成蛇形会抛 "Unexpected property: 'run_at'"，而它被下面的
//      `catch` 收进 failures —— **动态注册等于 100% 静默失效**（只有用户新增站点时才看到提示）。
//
// 💡 `siteMatchPattern` 已挪到 `shared.js`：它原先在这里和 `options.js` 各有一份，
//    而 `options.js` 是**申请权限**的一方、这里是**注册**的一方——两边规则不一致时
//    「权限申请成功但注册失败」，用户只看到一句 regFailed。现在同源，改一处即全改。
const REGFAIL_KEY = 'maskit:regFailures';

/**
 * 并发锁：同一时刻只允许一次重注册在跑。
 *
 * 为什么必须有（2026-09-16 真机复现）：`onInstalled` / `onStartup` / SW 被唤醒 /
 * options 的 resync 都会调它，两个调用叠在一起时时序是
 *   A 读 existing → B 读 existing（同一份）→ A 注销+注册 → B 注销+注册
 * 第二次注册时上一轮的脚本已经在了（A 刚写进去），Chrome 抛
 *   "Duplicate script ID 'maskit-main-grok.com'"
 * 于是该站点**不注入、不打码**，而 failures 只在 options 手动 resync 时才展示 ——
 * 用户看到的是「已添加」，实际是静默未脱敏。
 */
let syncInFlight = null;

async function syncDynamicScripts() {
  // 已有在跑的重注册：直接复用它的结果，不发起第二次。
  if (syncInFlight) return syncInFlight;
  syncInFlight = (async () => {
    try {
      return await doSyncDynamicScripts();
    } finally {
      syncInFlight = null;
    }
  })();
  return syncInFlight;
}

async function doSyncDynamicScripts() {
  const cfg = await getConfig();
  const sites = (cfg.enabledSites || []).filter((d) => d && !STATIC_SITES.includes(d));
  const wanted = new Map();
  for (const domain of sites) {
    wanted.set(`maskit-isolated-${domain}`, {
      id: `maskit-isolated-${domain}`,
      matches: [siteMatchPattern(domain)],
      js: ['bridge-isolated.js'],
      runAt: 'document_start',
      allFrames: true,
      world: 'ISOLATED',
    });
    wanted.set(`maskit-main-${domain}`, {
      id: `maskit-main-${domain}`,
      matches: [siteMatchPattern(domain)],
      js: ['bridge-main.js'],
      runAt: 'document_start',
      allFrames: true,
      world: 'MAIN',
    });
  }
  const existing = await chrome.scripting.getRegisteredContentScripts().catch(() => []);
  const stale = existing.filter((s) => s.id.startsWith('maskit-')).map((s) => s.id);
  if (stale.length) {
    await chrome.scripting.unregisterContentScripts({ ids: stale }).catch(() => {});
  }
  const failures = [];
  for (const script of wanted.values()) {
    try {
      await chrome.scripting.registerContentScripts([script]);
    } catch (e) {
      // 未授权的站点会被 Chrome 拒绝；逐个注册，失败记录后跳过（options 里会提示）
      failures.push({ id: script.id, error: String((e && e.message) || e) });
    }
  }
  // 落一份到 session：`onStartup`/`onInstalled` 触发的重注册没有调用方接返回值，
  // 不落盘的话「注册失败」就只剩一句没人看的 catch（上面 ① 的坑正是因为这点潜伏了一轮）。
  try {
    await chrome.storage.session.set({ [REGFAIL_KEY]: failures });
  } catch (e) {
    /* 配额/环境异常不该影响注册主流程 */
  }
  // 重注册只对「之后新加载的页面」生效，已开着的标签页要补一次主动注入（理由见函数注释）。
  await injectIntoOpenTabs(sites);
  return failures;
}

/**
 * 主动注入**已经打开**的标签页。
 *
 * 为什么必须有（2026-09-20 真机）：manifest 里静态声明的 chatgpt.com / claude.ai，
 * 在扩展被重新加载时 Chrome 会把 content script 自动重新注入到已开着的标签页；
 * 而动态注册的站点（豆包 / DeepSeek 等用户自己加的）**不会** ——
 * `registerContentScripts` 只对注册之后新加载的页面生效。
 * 于是重载扩展后的真机表现是「ChatGPT / Claude 一切正常，豆包 / DeepSeek 一条记录都没有」，
 * 用户看不出是注入没生效，只会以为整个扩展坏了。
 * 这里补一次主动注入，把「请手动刷新页面」这一步消掉。
 *
 * 幂等：两个 bridge 脚本各自有 `window.__MASKIT_*__` 守卫，重复注入是空操作。
 * 失败必须吞掉：chrome:// 页面、未授权的站点、已关闭的标签页都会抛，
 * 它们不该让注册主流程失败。
 */
async function injectIntoOpenTabs(sites) {
  if (!sites.length || !chrome.scripting || !chrome.tabs) return;
  let tabs = [];
  try {
    tabs = await chrome.tabs.query({});
  } catch (e) {
    return;
  }
  for (const tab of tabs) {
    if (!tab || !tab.id || !tab.url) continue;
    let host = '';
    try {
      host = new URL(tab.url).hostname;
    } catch (e) {
      continue;                        // chrome://、about:blank、扩展页等无法解析的 URL
    }
    if (!siteCovers(host, sites)) continue;
    // 顺序固定：isolated 先建好中继，main 再 hook（与 manifest 里的声明顺序一致）
    for (const [file, world] of [['bridge-isolated.js', 'ISOLATED'], ['bridge-main.js', 'MAIN']]) {
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: true },
          files: [file],
          world,
        });
      } catch (e) {
        /* 未授权 / 特殊页面：跳过该文件，不影响其他标签页 */
      }
    }
  }
}

chrome.runtime.onInstalled.addListener(() => {
  pruneSids();
  syncDynamicScripts();
  refreshPing().catch(() => {});
});

chrome.runtime.onStartup.addListener(() => {
  pruneSids();
  syncDynamicScripts();
  refreshPing().catch(() => {});
});

// SW 每次被唤醒也顺手校准一次（MV3 SW 会被回收重建，onInstalled/onStartup 不一定都跑）
pruneSids();
