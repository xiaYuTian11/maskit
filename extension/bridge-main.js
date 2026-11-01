/* Data Maskit Browser Bridge — MAIN world hook 层
 *
 * 跑在**页面上下文**（world:"MAIN", run_at:"document_start"，实测先于页面脚本 hook 成功）。
 * 这里没有 chrome.* 特权，所有特权操作经 postMessage（带 nonce）转给 ISOLATED 层。
 *
 * ⚠️ MAIN world 的一切都视为**可被页面读取**：token 绝不经过这里，请求/响应原文也不外发，
 *    只把文本交给扩展侧打码/还原（打码只进不出）。
 */
(() => {
  'use strict';
  if (window.__MASKIT_BRIDGE__) return;
  window.__MASKIT_BRIDGE__ = true;

  const BRIDGE_TIMEOUT_MS = 3000;
  // 文本 body 的**下限**：短于它连一次桥都不值得走（审计 M4）。
  //
  // 原值是 80，理由是「滤掉 GET 语义的查询串」。但那个理由早已不成立——
  // 上面的 fetch hook 现在**先按方法过滤**（只放行 POST/PUT/PATCH），GET 查询串根本到不了这里。
  // 于是 80 只剩下一个效果：≤80 字符的写请求**不打码、不记录、无提示**，
  // 与 multipart 分支（无长度阈值）自相矛盾，属「静默未脱敏」。
  //
  // 取 8 而不是 0：短于 8 字符的 body（`{}`、`{"a":1}`、abort 请求）不可能承载任何
  // 现实中的敏感值——最短的现实 PII 是 11 位手机号 / 18 位身份证 / 9 字符邮箱，
  // 全都在 8 之上。保留这个下限只为省掉这些必然无命中的桥调用，
  // 而**它不再能掩盖任何有意义的请求**。
  const MIN_MASKABLE_LEN = 8;

  // 单份 Office 附件的原始字节上限，**必须与引擎侧闸门对齐**（审计 M5）。
  //
  // `panel._EXT_MAX_BODY = 32MB` 是请求体（JSON 信封）上限，而整份文件要 base64 后
  // 塞进去，膨胀 4/3 —— 原值 25MB 恰好卡在边界之上：25MB 原始文件 ≈ 33.3MB 请求体
  // → 413 + `blocking:true` → 扩展按 (A) 类无条件阻断 → 页面**网络错误**
  // （不是降级直通）。用户传一个 24–25MB 的 docx 会看到整页请求失败。
  //
  // 反推：`4 * ceil(n/3) + 信封 ≈ 32MB` → n 上限约 24.0MB。这里取 23MB，
  // 留约 1.4MB 余量给文件名/headers 等开销。超限的文件会落到 `kind:'raw'` 分支
  // **原样透传并由 `attachment` note 诚实上报「未脱敏 N 个」**——
  // 页面能用，用户也知道它没被保护。这比「硬失败」和「静默放行」都好。
  const MAX_OOXML_BYTES = 23 * 1024 * 1024;

  // 单张图片的原始字节上限：与 OOXML 用同一个数（同一道 32MB 信封闸门反推出来）。
  // 超限的图片落到 `raw` 分支原样透传，并由 attachment note 如实报「未脱敏」——
  // 理由与上面相同：不硬失败、不静默放行。
  const MAX_IMAGE_BYTES = MAX_OOXML_BYTES;

  // ─── postMessage 桥（nonce 校验） ───
  const pending = new Map();
  const bridge = {
    call(action, payload, timeoutMs = BRIDGE_TIMEOUT_MS) {
      return new Promise((resolve) => {
        const nonce = (crypto.randomUUID && crypto.randomUUID()) || String(Math.random()).slice(2);
        const timer = setTimeout(() => {
          pending.delete(nonce);
          resolve(null);                       // 超时按 (B) 直通处理
        }, timeoutMs);
        pending.set(nonce, { resolve, timer });
        window.postMessage({ type: 'MASKIT_BRIDGE_REQ', nonce, action, payload }, location.origin);
      }).then((result) => {
        // 【桥健康度记账】唯一能观测「扩展是否还在」的信号就是这里：重载/更新扩展会销毁
        // 本页的 content script 上下文，ISOLATED 侧与 SW 都换了新的 —— MAIN 侧再
        // postMessage 就没人应答，一路超时返回 null。连续多次拿不到结果就认定桥断了
        // （处置见 restoreNativeAndStop）。拿 callback 包在这里而不是两个 resolve 处，
        // 是为了让超时与正常响应两条分支天然共用一条记账路径。
        noteBridgeCall(result != null);
        return result;
      });
    },
    notify(action, payload) {
      window.postMessage({ type: 'MASKIT_BRIDGE_REQ', nonce: null, action, payload }, location.origin);
    },
  };

  // ─── mask 的专用调用：更长超时 + 一次重试 ───
  //
  // `mask` 是整条链路上**唯一**「桥超时 = 明文出网」的调用：桥一超时，MAIN 侧拿不到
  // `r.sid` 会走 (B) 分支把**原始请求体**发出去（未脱敏），而且**整条响应也不会被还原**
  // （`sid` 为空 → 不包 wrapResponse）。restore 超时只是少还原几个字，代价完全不同。
  //
  // 3s 对 mask 太紧：引擎侧 `/api/ext/*` 走一把全局锁串行（`panel._EXT_LOCK`），
  // 多标签页并发、或 NER 冷启动时，单次 mask 超过 3s 很正常。这里给 6s，并在失败时
  // 重试一次。重试成功的第一个 sid 会在引擎侧成为孤儿会话，由会话 TTL 自然回收。
  const MASK_TIMEOUT_MS = 6000;
  // 文件/图片类打码的页↔SW 超时。**必须大于** SW→引擎那一道（background.js 的
  // `HEAVY_CALL_TIMEOUT_MS = 150s`），否则引擎还在跑 OCR、页面这边已经超时收手：
  // `bridge.call` 超时 resolve(null)，调用方按“没换成”处理 → **原图/原文件上行**。
  // 这是一条静默漏脱敏路径：引擎那边本来会明确回 503 阻断，但前端先走了。
  // 层数：Office OCR 40s / PDF OCR 120s（引擎） < 150s（SW） < 180s（本超时）。
  const HEAVY_CALL_TIMEOUT_MS = 180000;
  const maskOnce = (text) => bridge.call('mask', { text }, MASK_TIMEOUT_MS);
  const callMask = async (text) => {
    // ⚠️ `blocking`（引擎 413 超限 / 503 管线失败 / 400 参数错）是**确定性拒绝**，
    // **绝不重试**：重试只会拿同一份负载再打一次，既慢又白烧。它必须原样上抛给
    // 调用点去 `throw new TypeError('Failed to fetch')`，走 fail-closed
    // —— 宁可页面报网络错误，也绝不放行未脱敏明文出网。
    const first = await maskOnce(text);
    if (first && first.blocking) return first;
    if (first) return first;
    // 桥超时/失败 → 重试一次（覆盖引擎全局锁排队与 NER 冷启动的偶发超时）。
    return await maskOnce(text);
  };
  window.addEventListener('message', (e) => {
    if (e.origin !== location.origin) return;
    if (!e.data || e.data.type !== 'MASKIT_BRIDGE_RESP') return;
    const p = pending.get(e.data.nonce);
    if (p) {
      clearTimeout(p.timer);
      pending.delete(e.data.nonce);
      p.resolve(e.data.result);
    }
  });

  // ─── 拦截策略：广泛模式（默认，零适配）/ 窄模式（只认对话接口） ───
  //
  // 【为什么从白名单改成黑名单】原方案要求路径命中 LLM_PATH_HINTS 才打码，于是每加一个
  // 新站点都要先猜接口路径——猜错就**整站静默未脱敏**（页面毫无异常，内容裸着发出去）。
  // 2026-09-16 实测 18 站，有 4 个海外站就是这样漏掉的（Gemini/Grok/Perplexity/Poe 的
  // 路径一个关键词都不带）。逐个补路径是打地鼠：站点改版一次就失效一次。
  //
  // 广泛模式的判定是三层：
  //   ① 认证/埋点/噪声路径 → 永不打码（黑名单）
  //   ② 命中对话接口形态   → 一定打码（**跨域也算**，兜住 API 在独立域的站点）
  //   ③ 其余同站 POST      → 也送引擎（广泛模式独有；引擎没匹配到敏感信息就原样返回）
  //
  // 同站限定是关键：埋点几乎全是跨域（clarity.ms / sentry.io / volces.com / 百度统计…），
  // 一条「不同站就不碰」就能滤掉绝大部分噪声，而 AI 站点的对话请求基本都在本站或子域。
  const LLM_PATH_HINTS = [
    /\/api\/.*conversation/i,
    /\/backend-api\//i,
    /\/(?:v[0-9]+\/)?(?:chat|completions?|messages|responses)/i, // completions? 兼容单复数，覆盖 Claude/DeepSeek/Kimi 等
    /\/samantha\/chat\//i,                                        // 豆包（Doubao）
    /\/api\/(?:v[0-9]+\/)?chat\//i,                               // Kimi / 通义千问等
    /\/_\/BardChatUi\//i,   // Google Gemini（含 StreamGenerate / batchexecute）
    /\/app-chat\//i,        // Grok（xAI）：/rest/app-chat/conversations/…
    /\/rest\/sse\//i,       // Perplexity：/rest/sse/perplexity_ask
    /\/api\/gql/i,          // Poe：GraphQL 端点 /api/gql_POST
    // ── 文件/附件上传端点（ChatGPT / Claude / 各主流 Web AI / 豆包） ──
    /\/(?:api|backend-api|alice|v[0-9]+)\/.*(?:upload|files?|attachment|resource|convert|doc)/i,
  ];

  /**
   * 永不打码的路径黑名单。
   *
   * ① 认证类：EMAIL/PHONE 是**默认开启**的内置规则，登录表单里 `{"email":"a@b.com"}`
   *    会被打成 `{{EMAIL_xxxxxx}}`（实测），一旦打码就登录不上——这是硬失败，必须排除。
   * ② 埋点/遥测类：不是内容，送引擎纯属浪费，且占位符混进埋点会造成数据污染。
   * ③ 只读类（history/list/detail）：不带用户新输入，没有打码价值。
   *
   * 黑名单命中就**直接放行**，不再走引擎——宁可少打一次码，也不能让登录表单坏掉。
   */
  const NEVER_MASK_PATH = [
    // 认证 / 凭据
    /(login|signin|sign-?in|signup|sign-?up|register|logout|auth|oauth|sso|session|token|password|credential|passwd|captcha|verify|verification|sms|otp|2fa|mfa)/i,
    // 埋点 / 遥测 / 监控
    /(\/|_|-|\.)(log|logs|logging|logger|beacon|telemetry|track|tracking|tracker|analytics|metric|metrics|monitor|monitoring|report|reports|collect|collector|event|events|stats|stat|perf|performance|apm|rum|sentry|clarity|error|errors|exception|crash|heartbeat|health|healthcheck|alive|ping|feedback|survey|abtest|ab-?test|experiment)($|\/|_|-|\.|\?|\d)/i,
    // 配置 / 静态字典（不含用户输入）
    /(\/|_|-|\.)(config|configs|settings|preference|preferences|i18n|locale|lang|dict|theme|version|update|upgrade|announce|notice|notification|invite|referral|share|balance|quota|billing|payment|order)($|\/|_|-|\.|\?|\d)/i,
  ];

  /** 同站判定：完全同 host，或互为子域（api.doubao.com ↔ www.doubao.com）。 */
  const isSameSite = (host) => {
    const h = String(host || '').toLowerCase();
    const p = location.hostname.toLowerCase();
    if (!h || !p) return false;
    if (h === p) return true;
    return h.endsWith('.' + p) || p.endsWith('.' + h);
  };

  /**
   * 是否该对这次请求打码。
   * 先判白名单（命中直接打码，防止 events/settings 误杀真实对话接口）；
   * 再判黑名单（排除认证/埋点/配置等非对话管理接口）；
   * 兜底：广泛模式下同站其余 POST 送引擎，默认精准模式下直接放行。
   */
  const shouldMaskUrl = (url, wide) => {
    let u, path;
    try {
      u = new URL(url, location.href);
      path = u.pathname;
    } catch (e) {
      return false;
    }
    if (LLM_PATH_HINTS.some((rx) => rx.test(path))) return true;   // 对话接口优先打码（跨域也算）
    if (NEVER_MASK_PATH.some((rx) => rx.test(path))) return false; // 认证/埋点/管理排除
    return !!wide && isSameSite(u.hostname);
  };

  // 广泛模式开关由 SW 下发（chrome.storage 在 MAIN world 不可用）。默认 false（精准对话模式）。
  // 且**只问一次**并缓存——每个请求都问一次 storage 不划算，而这个值改了刷新页面就生效。
  let wideModePromise = null;
  const getWideMode = async () => {
    if (!wideModePromise) {
      wideModePromise = bridge.call('config', {})
        .then((r) => (r && typeof r.wideMode === 'boolean' ? { wideMode: r.wideMode } : null))
        .catch(() => null);
    }
    const res = await wideModePromise;
    if (!res) {
      wideModePromise = null;          // 拿不到就重试，不把「未知」固化成「精准模式」
      return { wideMode: false };      // 本次仍按精准模式（保守），但不写进缓存
    }
    return res;
  };

  // ─── 可打码 body 判定（成对原则的落地点） ───
  // Request 的 body 可能是 FormData / Blob / URLSearchParams / ReadableStream —— 把它
  // clone().text() 读成字符串再 new Request(old, {body: 字符串}) 回写，会保留原来的
  // `Content-Type: multipart/form-data; boundary=…` 却把实体换成纯文本，上游直接 400。
  // 所以文本分支只吃文本类 content-type；multipart 走**独立的 FormData 分支**（见
  // maskMultipart），不再像 v1 那样整体跳过——跳过的代价是「带附件的请求完全不脱敏」。
  const MASKABLE_CT = /^(application\/json|application\/(x-)?ndjson|application\/json-seq|application\/x-www-form-urlencoded|text\/)/i;
  const MULTIPART_CT = /^multipart\/form-data/i;
  const isMaskableBody = (req) => MASKABLE_CT.test((req.headers.get('content-type') || '').trim());
  const isMultipart = (req) => MULTIPART_CT.test((req.headers.get('content-type') || '').trim());

  /**
   * 上报「该打码、却打不开 body」的请求，让它出现在事件页，而不是无声消失。
   *
   * 为什么必须上报：`isUrlMaskable && !isMaskableBody` 是本系统唯一的**无感知漏脱敏**
   * —— URL 命中对话白名单说明我们判断它该脱敏，content-type 不在可打码集合又说明
   * 我们根本没读到内容。结果是用户以为内容被保护，实际原样明文出网，而页面上
   * 毫无异常。实测（2026-09-20）尚无站点走到这一支；一旦某站改用 x-protobuf
   * 或二进制 JSON 提交对话，就会整站静默漏掉，届时唯一的线索就是这条上报。
   *
   * 只送元数据（上游 path / content-type），**绝不送正文**：这条链路的意义恰恰是
   * 「我们没能处理它」，把正文带过去等于把已经漏出去的明文再抄一份。
   * 上报失败一律静默——它只是可观测性，绝不能反过来影响请求本身。
   */
  const reportUnsupportedBody = (url, ct) => {
    try {
      let path = String(url || '');
      try { path = new URL(url, location.href).pathname; } catch (e) { /* 非法 URL 就用原串 */ }
      bridge.call('warn', { path: path.slice(0, 200), content_type: String(ct || '').slice(0, 80) }, 2000)
        .catch(() => {});
    } catch (e) { /* 上报绝不影响请求 */ }
  };
  const initBodyIsText = (init) => !!init && typeof init.body === 'string';
  const initBodyIsURLSearchParams = (init) =>
    !!init && typeof URLSearchParams !== 'undefined' && init.body instanceof URLSearchParams;
  const initBodyIsFormData = (init) =>
    !!init && typeof FormData !== 'undefined' && init.body instanceof FormData;
  const initBodyIsBlob = (init) =>
    !!init && typeof Blob !== 'undefined' && init.body instanceof Blob;
  const initBodyIsArrayBuffer = (init) =>
    !!init && (init.body instanceof ArrayBuffer || (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(init.body)));

  // ─── 文件/存储桶与上传端点判定 ───
  const STORAGE_OR_UPLOAD_HOSTS = [
    /\.oaiusercontent\.com$/i,
    /\.s3[.-][a-z0-9-]+\.amazonaws\.com$/i,
    /\.s3\.amazonaws\.com$/i,
    /\.blob\.core\.windows\.net$/i,
    /\.storage\.googleapis\.com$/i,
    /\.aliyuncs\.com$/i,
    /\.myqcloud\.com$/i,
    /\.volces\.com$/i,
    /\.volccdn\.com$/i,
    /claude\.ai$/i,
    /chatgpt\.com$/i,
    /doubao\.com$/i,
    /deepseek\.com$/i,
  ];

  const isUploadOrStorageUrl = (url) => {
    let u;
    try {
      u = new URL(url, location.href);
    } catch (e) {
      return false;
    }
    if (STORAGE_OR_UPLOAD_HOSTS.some((rx) => rx.test(u.hostname))) return true;
    if (LLM_PATH_HINTS.some((rx) => rx.test(u.pathname))) return true;
    return false;
  };

  /** 是否该对文件/附件类请求打码（包含跨域对象存储桶直传）。 */
  const shouldMaskFileUrl = (url, wide) => {
    return shouldMaskUrl(url, wide) || isUploadOrStorageUrl(url);
  };

  /**
   * 这次 init 的 body 是否会真的被读一遍（而不是直接丢下不管）。
   *
   * 用途只有一个：init 路径（`fetch(url, { body })`）下，判断「URL 命中对话白名单，
   * 但我们压根没读过这个 body」—— 那就是无感知漏脱敏，必须留痕。
   * 注意 Blob 的门槛是 isUploadOrStorageUrl（与 maskSingleFile 的调用条件同源）：
   * 即使在 LLM 路径上，maskSingleFile 也会实际读取并判定它，属于「处理过」，不算静默；
   * 真正没被读过的只有未枚举的形态（ReadableStream / Document…）。
   */
  const initBodyWillBeHandled = (init, url) =>
    !!init && (
      typeof init.body === 'string'
      || (typeof URLSearchParams !== 'undefined' && init.body instanceof URLSearchParams)
      || (typeof FormData !== 'undefined' && init.body instanceof FormData)
      || (typeof Blob !== 'undefined' && init.body instanceof Blob && isUploadOrStorageUrl(url))
      || initBodyIsArrayBuffer(init)
    );

  // ─── Office 二进制格式清单 ───
  //
  // ⚠️ 必须定义在 `isMaskableTextAttachment` **之前**，并被它**优先排除**。
  // 原因：Office 的 MIME 是 `application/vnd.openxmlformats-officedocument...`，
  // 其中 `openxmlformats` 含子串 `xml` —— 任何 `type.includes('xml')` 式的子串匹配
  // 都会把 docx/xlsx/pptx 全部误判成文本附件（真机实测，见下方判定函数注释）。
  const OOXML_FILE_EXTS = new Set(['docx', 'xlsx', 'pptx', 'wps', 'et', 'dps', 'doc', 'xls']);

  // 交给引擎「文档脱敏」入口的全部载体：OOXML 一套 + PDF。
  // PDF 走的是引擎里的另一条实现（逐页渲染 + 本机 OCR + 打码后重建），
  // 但对外是**同一个** `mask_file` 动作与同一套阻塞语义——扩展侧不需要分派。
  const DOC_FILE_EXTS = new Set([...OOXML_FILE_EXTS, 'pdf']);

  // 旧版 Office（OLE 复合二进制，.doc / .xls）：内容不是 ZIP，无法像 OOXML 那样解包改文本。
  // 引擎对它们的「转换」是**有损重建**（丢图片/表格/样式，二进制碎片还会混入正文），因此
  // 默认已关闭；关闭时这几个扩展名原样上行 = **完全不受保护**。单独列出只为给用户一条
  // 明确的提示（「请另存为 .docx / .xlsx」），否则用户看到的只是笼统的「附件不脱敏」，
  // 根本不知道该换格式。
  const LEGACY_OFFICE_EXTS = new Set(['doc', 'xls']);

  // ─── 文本类文件扩展名与单文件上限（支持拖拽上传脱敏） ───
  const TEXT_FILE_EXTS = new Set([
    'txt', 'text', 'md', 'markdown', 'mdown', 'csv', 'tsv', 'json', 'jsonl', 'ndjson',
    'xml', 'yaml', 'yml', 'py', 'pyw', 'js', 'mjs', 'cjs', 'jsx', 'ts', 'mts', 'cts', 'tsx',
    'html', 'htm', 'xhtml', 'css', 'scss', 'sass', 'less', 'sql', 'sh', 'bash', 'zsh',
    'bat', 'cmd', 'ps1', 'psm1', 'c', 'h', 'cpp', 'hpp', 'cc', 'hh', 'cxx', 'hxx',
    'cs', 'java', 'kt', 'kts', 'go', 'rs', 'php', 'rb', 'lua', 'r', 'swift', 'm', 'mm',
    'log', 'env', 'ini', 'conf', 'cfg', 'toml', 'properties', 'diff', 'patch', 'vue', 'svelte'
  ]);
  const MAX_TEXT_FILE_SIZE = 8 * 1024 * 1024; // 8MB 单文件上限

  /** 明确属于文本的 `application/*` 类型。**精确列举，禁止子串匹配**（理由见下方判定函数）。 */
  const TEXT_APP_MIMES = new Set([
    'application/json', 'application/x-ndjson', 'application/ndjson', 'application/jsonl',
    'application/xml', 'application/xhtml+xml', 'application/x-yaml', 'application/yaml',
    'application/toml', 'application/sql', 'application/javascript', 'application/x-javascript',
    'application/ecmascript', 'application/x-sh', 'application/x-httpd-php',
    'application/x-latex', 'application/x-tex', 'application/rtf',
  ]);

  const isMaskableTextAttachment = (v) => {
    if (!v || typeof v !== 'object') return false;
    const size = typeof v.size === 'number' ? v.size : 0;
    if (size <= 0 || size > MAX_TEXT_FILE_SIZE) return false;
    const name = String(v.name || '').trim();
    if (name.includes('.')) {
      const ext = name.split('.').pop().toLowerCase();
      // Office 二进制**必须先排除**：它的 MIME 含 `openxmlformats` 子串，走 MIME 判定必被误判。
      if (OOXML_FILE_EXTS.has(ext)) return false;
      if (TEXT_FILE_EXTS.has(ext)) return true;
    }
    // MIME 兜底只认**精确**文本类型，禁止子串匹配。
    //
    // 旧写法 `type.includes('json'|'xml'|'yaml')` 是本仓库最隐蔽的一处误判：
    // `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`（xlsx）与
    // docx/pptx 的 MIME 全都含 `xml` → 全部被当成文本附件 → `file.text()` 把二进制 zip
    // 按 UTF-8 解码（非法字节变 U+FFFD）再编码回写，文件当场损坏。
    // 真机实测：6488 字节的 xlsx 经此路径变成 11044 字节的非 zip，上传到
    // ChatGPT/Claude 表现为「附件解析失败」，而扩展侧一切"正常"、无任何告警。
    const type = String(v.type || '').toLowerCase().split(';')[0].trim();
    if (!name || !type) return false;
    return type.startsWith('text/') || TEXT_APP_MIMES.has(type);
  };

  /** 附件是否是图片（既用于分类打码，也用于「未脱敏文件里有图片」的诚实提示）。 */
  const isImageItem = (item) => {
    const v = (item && (item.file || item.value)) || null;
    return !!(v && typeof v.type === 'string' && v.type.startsWith('image/'));
  };

  // ─── 文本附件的「等长对齐」 ───
  //
  // 真机实测（2026-09-20）：上游（ChatGPT `/backend-api/files/process_upload_stream`）
  // 按**上传前声明的字节数**校验实收字节数，差一个字节就回 `file_size_mismatch`
  // 把整个附件拒收。Office 分支能过，是因为引擎侧 `_pad_zip_to_size` 把重压缩后的
  // zip 补回了原始大小；文本分支没有对应机制，脱敏一改长度（占位符 `{{LABEL_后缀}}`
  // 通常比手机号、短密钥长）上传就失败 —— 真机表现就是「Excel / Word 能传，txt 传不了」。
  //
  // 这里在扩展侧补上同样的对齐语义：
  //   ① 脱敏后更短 → 尾部补空格（空白对 LLM 无副作用，也不引入任何新语义）
  //   ② 恰好等长 → 直接用
  //   ③ 脱敏后更长 → 无法缩短。**放弃脱敏、原样上传**，宁可不上码也不能让用户
  //      传不了文件。注意这不是「静默跳过」：返回 masked=false，调用方会把它
  //      计入 unmaskedCount 并在提示里如实体现，不会谎报成已保护。
  const TEXT_ENCODER = new TextEncoder();

  function alignTextToSize(maskedContent, originalContent, orig) {
    const changed = maskedContent !== originalContent;
    // 目标长度取**文件对象自身的 size**（= 站点向服务端声明的那个数），
    // 而不是重新编码后的长度：原始文件若是非 UTF-8 编码，两者会不相等，
    // 那时只有 orig.size 才是服务端真正比对的基准。
    const target = (orig && typeof orig.size === 'number' && orig.size > 0)
      ? orig.size
      : TEXT_ENCODER.encode(originalContent).length;
    const maskedBytes = TEXT_ENCODER.encode(maskedContent).length;
    if (maskedBytes === target) {
      return { content: maskedContent, masked: changed };
    }
    if (maskedBytes < target) {
      return { content: maskedContent + ' '.repeat(target - maskedBytes), masked: changed };
    }
    return { content: originalContent, masked: false };
  }

  // ─── Office 格式识别与二进制/Base64 互转 ───
  // `OOXML_FILE_EXTS` 定义见上方（必须先于文本判定生效，理由见其注释）。
  const OOXML_MIME_MAP = {
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
    'application/msword': 'doc',
    'application/vnd.ms-excel': 'xls',
    'application/vnd.ms-powerpoint': 'pptx',
    'application/pdf': 'pdf',
  };

  function resolveFileExt(v, urlHint) {
    if (v && typeof v.name === 'string' && v.name.includes('.')) {
      return v.name.split('.').pop().toLowerCase().trim();
    }
    if (v && typeof v.type === 'string') {
      const mime = v.type.toLowerCase().split(';')[0].trim();
      if (OOXML_MIME_MAP[mime]) return OOXML_MIME_MAP[mime];
      if (mime === 'text/plain') return 'txt';
      if (mime === 'text/csv') return 'csv';
      if (mime === 'text/markdown') return 'md';
      if (mime === 'application/json') return 'json';
    }
    if (urlHint) {
      try {
        const p = new URL(urlHint, location.href).pathname;
        if (p.includes('.')) return p.split('.').pop().toLowerCase().trim();
      } catch (e) { /* ignore */ }
    }
    return '';
  }

  const isOOXMLAttachment = (v, urlHint) => {
    if (!v || typeof v !== 'object') return false;
    const size = typeof v.size === 'number' ? v.size : 0;
    if (size <= 0 || size > MAX_OOXML_BYTES) return false;  // 上限见 MAX_OOXML_BYTES 注释
    const ext = resolveFileExt(v, urlHint);
    return DOC_FILE_EXTS.has(ext);
  };

  /** 快速检查二进制前4字节是否为 ZIP 魔数 PK\x03\x04 */
  function isZipMagic(bytes) {
    if (!bytes || bytes.length < 4) return false;
    return bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
  }

  /** 快速检查前5字节是否为 PDF 魔数 `%PDF-`。
   *  为什么要它：扩展名/MIME 经常被站点抹掉（上传名变成 `attachment.bin`），
   *  而 PDF 不是 ZIP，只靠 isZipMagic 会让 PDF 落入 raw 分支原样上行——
   *  等于换个名字就绕过脱敏。 */
  function isPdfMagic(bytes) {
    if (!bytes || bytes.length < 5) return false;
    return bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44
      && bytes[3] === 0x46 && bytes[4] === 0x2d;
  }

  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary);
  }

  function base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }



  /**
   * multipart 打码：文本字段、常见文本附件与 Office 文档（.docx/.xlsx/.pptx）打码，其它二进制/图片原样透传。
   *
   * 为什么可以这么做：`Request.formData()` 会把 multipart 解析成 [name, string|File] 条目，
   * 我们用打码后的字符串 + 重新组装的 File 拼一个 FormData，再交给 fetch 自动生成**新的**
   * boundary —— 不存在手写 boundary 写坏的问题。
   *
   * 为什么必须显式删掉 `content-type`：见 `new Request(resource, {body})` 那处注释。
   * 旧头里是**旧 boundary**，留着等于告诉上游按一条已经不存在的分隔线去切分实体 → 400。
   *
   * 文本类附件（.txt/.md/.csv/.py/.json 等）：通过 `file.text()` 读取其纯文本并连同
   * 提示词一起打码，用打码后的文本构造同名 `new File` 替换原文件；
   * Office 文档（.docx/.xlsx/.pptx）：送引擎原生解包替换内部 XML 文本并封包回写；
   * 图片与其它格式：保持原样透传，若有未脱敏文件则通过 popup 提醒用户。
   */
  const FIELD_SEP = '\u0001\u0002__MASKIT_PART__\u0002\u0001';
  async function maskMultipart(fd) {
    const entries = [...fd.entries()];
    const items = [];
    const texts = [];

    for (const [k, v] of entries) {
      if (typeof v === 'string') {
        items.push({ kind: 'string', key: k, value: v });
        texts.push(v);
      } else if (isOOXMLAttachment(v)) {
        // Office 二进制**必须排在文本判定之前**：文本分支会把二进制按 UTF-8 读坏
        // （见 `isMaskableTextAttachment` 注释）。顺序反了 = Office 打码永不生效。
        items.push({ kind: 'ooxmlFile', key: k, file: v });
      } else if (isImageItem({ file: v }) && v.size > 0 && v.size <= MAX_IMAGE_BYTES) {
        // 图片走 mask_image（本机 OCR 判定 + 物理打码），而不是原样透传：
        // 截图里同样有手机号、工号、表格数据，这条路以前只会弹一句「图片未脱敏」。
        // 放在文本判定之前是为了让 `image/svg+xml` 这类带 xml 字样的类型不被文本
        // 分支抢走（它会被当纯文本读写一遍，既无意义又拿不到打码）。
        items.push({ kind: 'imageFile', key: k, file: v });
      } else if (isMaskableTextAttachment(v)) {
        let content = null;
        try {
          content = await v.text();
        } catch (e) {
          content = null;
        }
        if (typeof content === 'string') {
          items.push({ kind: 'textFile', key: k, file: v });
          texts.push(content);
        } else {
          items.push({ kind: 'raw', key: k, value: v });
        }
      } else if (v && typeof v === 'object' && typeof v.slice === 'function' && v.size > 0 && v.size <= MAX_OOXML_BYTES) {
        // 魔数兜底：文件名被抹除或 MIME 为二进制流时，按内容判定载体：
        //   PK\x03\x04 → OOXML；%PDF- → PDF。两者都交给引擎的文档入口。
        let isDocMagic = false;
        try {
          const headBuf = await v.slice(0, 5).arrayBuffer();
          const head = new Uint8Array(headBuf);
          isDocMagic = isZipMagic(head) || isPdfMagic(head);
        } catch (e) {
          isDocMagic = false;
        }
        if (isDocMagic) {
          items.push({ kind: 'ooxmlFile', key: k, file: v });
        } else {
          items.push({ kind: 'raw', key: k, value: v });
        }
      } else {
        items.push({ kind: 'raw', key: k, value: v });
      }
    }

    const hasOOXML = items.some((item) => item.kind === 'ooxmlFile');
    const hasImage = items.some((item) => item.kind === 'imageFile');
    if (!texts.length && !hasOOXML && !hasImage) {
      const raws = items.filter((item) => item.kind === 'raw');
      if (raws.length) {
        bridge.notify('note', {
          kind: 'attachment',
          image: raws.some(isImageItem),
          count: raws.length,
          maskedCount: 0,
        });
      }
      return null;                                  // 没有可打码的文本或文档
    }

    let sid = null;
    let parts = [];
    // 任一字符串字段/附件被真正改写？用于零触碰判定（一个敏感值都没命中就不重建请求）。
    let textChanged = false;
    if (texts.length > 0) {
      const joined = texts.join(FIELD_SEP);
      if (joined) {
        const r = await callMask(joined);
        if (r && r.blocking) return { blocking: true };  // (A) 无条件阻断，交给调用方抛
        if (r && r.ok) {
          sid = r.sid;
          parts = String(r.masked_text || '').split(FIELD_SEP);
          if (String(r.masked_text || '') !== joined) textChanged = true;
        }
      }
    }

    const out = new FormData();
    let textIdx = 0;
    for (const item of items) {
      if (item.kind === 'string') {
        out.append(item.key, parts.length === texts.length ? parts[textIdx++] : item.value);
      } else if (item.kind === 'textFile') {
        const orig = item.file;
        if (parts.length === texts.length) {
          const maskedContent = parts[textIdx];
          const originalContent = texts[textIdx];
          textIdx++;
          // 脱敏后必须与原始文件**等字节数**，否则上游按声明的 file_size 校验会拒收
          // （见 alignTextToSize 注释：这是「Excel / Word 能传、txt 传不了」的根因）。
          const aligned = alignTextToSize(maskedContent, originalContent, orig);
          let replacement;
          if (typeof File !== 'undefined' && orig instanceof File) {
            replacement = new File([aligned.content], orig.name, {
              type: orig.type || 'text/plain',
              lastModified: orig.lastModified || Date.now(),
            });
          } else {
            replacement = new Blob([aligned.content], { type: (orig && orig.type) || 'text/plain' });
          }
          out.append(item.key, replacement, (orig && orig.name) || 'attachment.txt');
          // 内容**真的变了**才算已脱敏：引擎没命中敏感词时会原样回传，
          // 那时报成已脱敏，就是把「未保护」包装成「已保护」。
          // 对齐失败（脱敏后反而更长）时 aligned.masked 恒为 false，同样如实计入未脱敏。
          if (aligned.masked) item.masked = true;
        } else {
          out.append(item.key, orig, orig && orig.name);
        }
      } else if (item.kind === 'ooxmlFile') {
        const orig = item.file;
        let replaced = false;
        try {
          const buf = await orig.arrayBuffer();
          const b64 = arrayBufferToBase64(buf);
          const fName = (orig && typeof orig.name === 'string' && orig.name) || 'attachment';
          const r = await bridge.call('mask_file', { filename: fName, base64: b64, sid }, HEAVY_CALL_TIMEOUT_MS);
          if (r && r.blocking) return { blocking: true };  // (A) 必须立即阻断，严禁把未脱敏原文件漏传出网
          if (r && r.ok && r.base64) {
            sid = sid || r.sid;
            const bytes = base64ToUint8Array(r.base64);
            let defaultMime = 'application/octet-stream';
            const fExt = resolveFileExt(orig, '');
            if (fExt === 'xlsx') defaultMime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
            else if (fExt === 'docx') defaultMime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
            else if (fExt === 'pptx') defaultMime = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
            else if (fExt === 'pdf') defaultMime = 'application/pdf';

            let replacement;
            if (typeof File !== 'undefined' && orig instanceof File) {
              replacement = new File([bytes], fName, {
                type: orig.type || defaultMime,
                lastModified: orig.lastModified || Date.now(),
              });
            } else {
              replacement = new Blob([bytes], { type: (orig && orig.type) || defaultMime });
            }
            out.append(item.key, replacement, fName);
            // 引擎在「无敏感信息」或「体积无法对齐而放弃脱敏」时会原样回传字节，
            // 只有 hit_count > 0 才说明内容真被改写过，才敢报「已脱敏」。
            if (typeof r.hit_count === 'number' && r.hit_count > 0) item.masked = true;
            replaced = true;
          }
        } catch (e) {
          console.warn('[Maskit Bridge] OOXML mask error:', e);
          replaced = false;
        }
        if (!replaced) {
          out.append(item.key, orig, (orig && orig.name) || 'attachment.xlsx');
        }
      } else if (item.kind === 'imageFile') {
        const orig = item.file;
        let replaced = false;
        try {
          const r = await maskImageBlob(orig, sid);
          if (r && r.blocking) return { blocking: true };  // (A)：OCR 不可用/扫不了，严禁原图出网
          if (r && r.bytes) {
            sid = sid || r.sid;
            const fName = (orig && typeof orig.name === 'string' && orig.name) || 'image.png';
            const mime = (orig && orig.type) || 'image/png';
            let replacement;
            if (typeof File !== 'undefined' && orig instanceof File) {
              replacement = new File([r.bytes], fName, {
                type: mime,
                lastModified: orig.lastModified || Date.now(),
              });
            } else {
              replacement = new Blob([r.bytes], { type: mime });
            }
            out.append(item.key, replacement, fName);
            // 只有真用打码字节重建过文件才计已脱敏（引擎在“判定干净”与
            // “能力开关关着”时都会原样回传，那两种不能报成已保护）。
            item.masked = true;
            replaced = true;
          }
        } catch (e) {
          console.warn('[Maskit Bridge] image mask error:', e);
          replaced = false;
        }
        if (!replaced) {
          out.append(item.key, orig, (orig && orig.name) || 'image');
        }
      } else {
        out.append(item.key, item.value, item.value && item.value.name);
      }
    }

    // 计数**只认真的替换成功的文件**（标记见上面 append 循环）。此处是「诚实上报」的
    // 唯一关键点：此前在进入循环前就乐观累加 maskedFileCount，于是引擎超时、文本掩码
    // 失败、OOXML 解包失败时，文件原样上行、popup 却告诉用户「已脱敏 N 个文件」——
    // 把最危险的失败模式（以为被保护了，其实没有）包装成成功，比不提示更糟。
    let maskedCount = 0;
    let unmaskedCount = 0;
    let hasUnmaskedImage = false;
    // 未脱敏的旧版 Office 文件单独计数：它们不是「漏了」而是「这类格式做不到」，
    // 提示语与普通附件完全不同（要引导用户另存为 .docx / .xlsx）。
    let legacyUnmaskedCount = 0;
    for (const item of items) {
      if (item.kind === 'string') continue;
      if (item.masked) {
        maskedCount++;
      } else {
        unmaskedCount++;
        if (isImageItem(item)) hasUnmaskedImage = true;
        if (item.kind === 'ooxmlFile' && LEGACY_OFFICE_EXTS.has(resolveFileExt(item.file, ''))) {
          legacyUnmaskedCount++;
        }
      }
    }
    if (unmaskedCount > 0 || maskedCount > 0) {
      bridge.notify('note', {
        kind: 'attachment',
        image: hasUnmaskedImage,
        count: unmaskedCount,
        maskedCount: maskedCount,
        legacyCount: legacyUnmaskedCount,
      });
    }
    // 零触碰原则（与文本 / Blob 分支一致）：一个敏感值都没命中时**不要重建 FormData**——
    // 重建会换掉 boundary、改变请求字节指纹，对签名敏感的站点是纯风险而收益为零。
    // 返回 null = 调用方原样放行原始请求（顺带也就不存在「需要还原的响应」）。
    // 主域（claude.ai / chatgpt.com …）被整体当作上传域，所以这里能拦下域内**所有**
    // FormData POST，零触碰也因此变成了必要而非可选项。
    if (!textChanged && maskedCount === 0) return null;
    return { body: out, sid: sid, masked: true };
  }

  /**
   * 单张图片 → 引擎做本机 OCR 判定 + 物理打码。
   *
   * 返回三态，调用方必须区分（与 `mask_file` 同一套口径）：
   *   · `{blocking:true}`：引擎明确阻断（OCR 未就绪 / 扫不了 / 输出被截断），
   *     整个请求不发出；
   *   · `{bytes}`：真改写过了，用这份字节重建文件；
   *   · `null`：不碰请求（能力开关关着 / 判定无敏感信息 / 引擎不可达）。
   *
   * 不传 `prompt`：扩展侧拿不到用户输入框里的原话，引擎因此按默认的“保留图片”
   * 意图处理（只会回图片字节或 passthrough，不会回 TEXT_ONLY——那是面板/网页端
   * 才能做的“用文本替掉图片”交互，在 multipart 里硬换会把请求结构弄坏）。
   */
  async function maskImageBlob(blob, sid) {
    if (!blob || typeof blob.arrayBuffer !== 'function') return null;
    const buf = await blob.arrayBuffer();
    const r = await bridge.call('mask_image', { base64: arrayBufferToBase64(buf), sid }, HEAVY_CALL_TIMEOUT_MS);
    if (r && r.blocking) return { blocking: true };
    // `hit_count > 0` 才算真改写：引擎在「判定干净」和「开关关着」时都会原样回传，
    // 把这两种报成“已脱敏”就是把未保护包装成已保护。
    if (r && r.ok && Number(r.hit_count) > 0 && typeof r.base64 === 'string' && r.base64) {
      return { bytes: base64ToUint8Array(r.base64), sid: r.sid || sid, mode: r.mode || '' };
    }
    return null;
  }

  /**
   * 单文件（Blob / File）直传打码：覆盖对象存储直传（S3 / OSS / OAI）与单文件 POST/PUT。
   * 支持 Office 文档（.docx / .xlsx / .pptx）、常见文本附件（.txt / .csv / .json 等）
   * 与图片（走本机 OCR + 物理打码）。
   */
  async function maskSingleFile(blob, urlHint) {
    if (!blob || typeof Blob === 'undefined' || !(blob instanceof Blob)) return null;

    let ext = resolveFileExt(blob, urlHint);
    let isOOXML = OOXML_FILE_EXTS.has(ext);
    let isText = isMaskableTextAttachment(blob);

    // 魔数兜底：当没有明确扩展名或 MIME 类型为通用的 application/octet-stream 时，
    // 按前几个字节判定载体（PK\x03\x04 → OOXML；%PDF- → PDF）。
    if (!isOOXML && !isText && blob.size > 4 && blob.size <= MAX_OOXML_BYTES) {
      try {
        const headBuf = await blob.slice(0, 5).arrayBuffer();
        const head = new Uint8Array(headBuf);
        if (isZipMagic(head) || isPdfMagic(head)) {
          isOOXML = true;
          // 真实格式未知：**不猜 xlsx**。ext 留空后 filename 退化为 'attachment.bin'，
          // 由引擎按魔数/内部结构嗅探真实格式。猜成 xlsx 会让 docx/pptx 被按 xlsx
          // 解析、一个条目都匹配不上 → hits=0 → 静默不脱敏。
          ext = '';
        }
      } catch (e) { /* ignore */ }
    }

    if (!isOOXML && !isText) {
      if (isImageItem({ file: blob })) {
        if (blob.size > 0 && blob.size <= MAX_IMAGE_BYTES) {
          try {
            const r = await maskImageBlob(blob, null);
            if (r && r.blocking) return { blocking: true };   // (A)：别让原图出网
            if (r && r.bytes) {
              const fName = (typeof blob.name === 'string' && blob.name) || 'image.png';
              let replacement;
              if (typeof File !== 'undefined' && blob instanceof File) {
                replacement = new File([r.bytes], fName, {
                  type: blob.type,
                  lastModified: blob.lastModified || Date.now(),
                });
              } else {
                replacement = new Blob([r.bytes], { type: blob.type });
              }
              bridge.notify('note', { kind: 'attachment', image: false, count: 0, maskedCount: 1 });
              return { body: replacement, sid: r.sid, masked: true };
            }
          } catch (e) {
            console.warn('[Maskit Bridge] image mask error:', e);
          }
        }
        // 没换成（能力关着 / 判定干净 / 超限 / 引擎不可达）：原样透传，但必须诚实提醒
        // “这张图没被保护”——静默放过是这条路以前最糟的地方。
        bridge.notify('note', { kind: 'attachment', image: true, count: 1, maskedCount: 0 });
      }
      return null;
    }

    const filename = (blob && typeof blob.name === 'string' && blob.name)
      || (ext ? `attachment.${ext}` : 'attachment.bin');

    // 1. Office 文档处理分支
    if (isOOXML) {
      if (blob.size > MAX_OOXML_BYTES) {
        bridge.notify('note', { kind: 'attachment', image: false, count: 1, maskedCount: 0 });
        return null;
      }
      try {
        const buf = await blob.arrayBuffer();
        const bytes = new Uint8Array(buf);
        // 非文档魔数 → 不碰这个请求（原样上行），与“零触碰”原则一致。
        if (!isZipMagic(bytes) && !isPdfMagic(bytes)) return null;

        let defaultMime = 'application/octet-stream';
        if (ext === 'xlsx') defaultMime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        else if (ext === 'docx') defaultMime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        else if (ext === 'pptx') defaultMime = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        else if (ext === 'pdf') defaultMime = 'application/pdf';

        const b64 = arrayBufferToBase64(buf);
        const r = await bridge.call('mask_file', { filename, base64: b64 }, HEAVY_CALL_TIMEOUT_MS);
        if (r && r.blocking) return { blocking: true };
        if (r && r.ok && r.base64) {
          // 引擎在「无敏感信息」或「体积无法对齐而放弃脱敏」时会**原样回传**字节。
          // 那种情况下既不重建请求（保持零触碰，不动站点的签名相关字节），
          // 也绝不报「已脱敏」——把「未保护」说成「已保护」是最危险的一类谎报。
          if (!(typeof r.hit_count === 'number' && r.hit_count > 0)) return null;
          const maskedBytes = base64ToUint8Array(r.base64);
          let replacement;
          if (typeof File !== 'undefined' && blob instanceof File) {
            replacement = new File([maskedBytes], filename, {
              type: blob.type || defaultMime,
              lastModified: blob.lastModified || Date.now(),
            });
          } else {
            replacement = new Blob([maskedBytes], { type: blob.type || defaultMime });
          }
          bridge.notify('note', { kind: 'attachment', image: false, count: 0, maskedCount: 1 });
          return { body: replacement, sid: r.sid, masked: true };
        }
      } catch (e) {
        return null;
      }
      return null;
    }

    // 2. 文本类附件处理分支
    if (isText) {
      try {
        const content = await blob.text();
        if (content && content.length > 0) {
          const r = await callMask(content);
          if (r && r.blocking) return { blocking: true };
          if (r && r.ok && typeof r.masked_text === 'string') {
            // 无命中时引擎原样回传：不重建请求（零触碰）、不报「已脱敏」。
            if (r.masked_text === content) return null;
            // 与 multipart 分支同一套对齐语义：脱敏后字节数必须与原始文件一致，
            // 否则上游按声明的 file_size 校验会拒收（见 alignTextToSize 注释）。
            const aligned = alignTextToSize(r.masked_text, content, blob);
            // 对齐失败（脱敏后反而更长）：宁可不上码，也不能让用户的文件传不上去。
            // 这里返回 null = 完全不碰请求，站点看到的是原始文件，与「未脱敏」一致。
            if (!aligned.masked) return null;
            let replacement;
            if (typeof File !== 'undefined' && blob instanceof File) {
              replacement = new File([aligned.content], filename, {
                type: blob.type || 'text/plain',
                lastModified: blob.lastModified || Date.now(),
              });
            } else {
              replacement = new Blob([aligned.content], { type: blob.type || 'text/plain' });
            }
            bridge.notify('note', { kind: 'attachment', image: false, count: 0, maskedCount: 1 });
            return { body: replacement, sid: r.sid, masked: true };
          }
        }
      } catch (e) {
        return null;
      }
    }

    return null;
  }

  // ─── escape 由引擎按槽位判定 ───
  // 这里原先有一段「读首个 data: 行的首字符，猜整条流要不要 JSON 转义」的启发式。
  // 它已删除，原因有两条：
  //   1. **粒度错了**。escape 的语义是「这个值是不是要放进 JSON 字符串里」，
  //      而同一条流里 `choices[].delta.content`（正文，不转义）与
  //      `tool_calls[].function.arguments`（JSON 文本，必须转义）是**并存**的，
  //      整条流只能猜出一个值，必然有一个是错的。
  //   2. **它永远猜不准 SSE**。首帧往往只是 `data: {"choices":[...`，末尾的续帧
  //      不以 `data:` 开头，靠首帧推出来的值要一路用到流结束。
  // 现在由引擎 `_sse_text_slots()` 逐槽位给出 escape（与代理链路同一份实现）。
  // 扩展只需要告诉引擎 content-type —— 分帧方式（SSE 空行 / NDJSON 换行 / 整体）
  // 也由引擎判定，避免同一套规则在两边各写一遍然后悄悄漂移。

  const streamLike = (ct) =>
    ct.includes('text/event-stream') || ct.includes('application/json') || ct.includes('ndjson') || ct.includes('json-seq');

  // ─── fetch hook ───
  const origFetch = window.fetch;
  window.fetch = async function (...args) {
    let [resource, init] = args;
    let isReq = false;
    let url = '';
    let method = 'GET';
    try {
      isReq = resource instanceof Request;
      url = isReq ? resource.url : String(resource);
      method = (isReq ? resource.method : (init && init.method) || 'GET').toUpperCase();
    } catch (e) {
      return origFetch.apply(this, args);             // 任何解析意外：原样放行
    }
    // 只有带 body 的写方法值得过桥。**方法过滤是这里的主判据**——GET 语义的查询串
    // 在进任何长度判断之前就被挡掉了（MIN_MASKABLE_LEN 原先兼着这个职责，现已退回
    // 它真正的含义：只是一个「短到不可能有 PII」的下限，见其定义处）。
    if (method !== 'POST' && method !== 'PUT' && method !== 'PATCH') {
      return origFetch.apply(this, args);
    }

    const cfg = await getWideMode();
    const isUrlMaskable = shouldMaskUrl(url, cfg.wideMode);
    const isFileUrlMaskable = shouldMaskFileUrl(url, cfg.wideMode);

    if (!isUrlMaskable && !isFileUrlMaskable) {
      // 不打码不包装（成对原则）。窄模式下记一条「未命中对话接口的 POST」供反馈——
      // 广泛模式不记：它本就把同站 POST 全收了，记下来的全是跨域埋点，纯噪音。
      if (!cfg.wideMode) {
        try {
          const p = new URL(url, location.href).pathname;
          if (!NEVER_MASK_PATH.some((rx) => rx.test(p))) {
            bridge.notify('note', { kind: 'unmatched_post', path: p });
          }
        } catch (e) { /* ignore */ }
      }
      return origFetch.apply(this, args);
    }
    const minLen = MIN_MASKABLE_LEN;

    let sid = null;
    if (isReq) {
      // ── multipart：文本字段打码，文件打码 ──
      if (isMultipart(resource)) {
        const fd = await resource.clone().formData().catch(() => null);
        if (fd) {
          const m = await maskMultipart(fd);
          if (m && m.blocking) throw new TypeError('Failed to fetch');   // (A)
          if (m) {
            // 必须删掉 content-type（旧 boundary）和 content-length（打码后体积已变）
            const h = new Headers(resource.headers);
            h.delete('content-type');
            h.delete('content-length');
            resource = new Request(resource, { body: m.body, headers: h, signal: resource.signal });
            const res = await origFetch.call(this, resource);
            // 文件上传响应为普通 JSON 元数据，绝不可走 wrapResponse（避免删除 Content-Length 或插入 TransformStream）
            return (m.sid && m.masked) ? wrapResponse(res, m.sid) : res;
          }
        }
        return origFetch.apply(this, args);
      }

      // ── 单文件直传（仅当请求发往上传/存储桶端点时，识别 Blob 附件）──
      if (isUploadOrStorageUrl(url)) {
        const ct = (resource.headers.get('content-type') || '').toLowerCase();
        if (ct.includes('application/') || ct.includes('text/') || ct === '') {
          const cloned = resource.clone();
          const blob = await cloned.blob().catch(() => null);
          if (blob && (isOOXMLAttachment(blob, url) || isMaskableTextAttachment(blob))) {
            const m = await maskSingleFile(blob, url);
            if (m && m.blocking) throw new TypeError('Failed to fetch');
            if (m && m.masked) {
              const h = new Headers(resource.headers);
              h.delete('content-length');
              resource = new Request(resource, { body: m.body, headers: h, signal: resource.signal });
              return origFetch.call(this, resource);
            }
          }
        }
      }

      // 其它非文本 body（Blob / ReadableStream / ArrayBuffer）：读成字符串再回写会破坏
      // 原有语义，一律原样放行。
      //
      // ⚠️ 但「URL 命中对话白名单」+「body 打不开」= 无感知漏脱敏（见
      // reportUnsupportedBody 注释）。这一支必须留痕，且判定要在放行**之前**做：
      // 一旦先 return，就没有任何地方能知道这次明文出网了。
      // 注意 multipart 在上面（isMultipart 分支）已经 return，走不到这里。
      if (isUrlMaskable && !isMaskableBody(resource)) {
        reportUnsupportedBody(url, resource.headers.get('content-type') || '');
      }
      if (!isMaskableBody(resource) || !isUrlMaskable) return origFetch.apply(this, args);
      const raw = await resource.clone().text();
      if (raw.length > minLen) {
        const r = await callMask(raw);
        if (r && r.ok) {
          sid = r.sid;
          // 零触碰原则：只有当内容确实被替换脱敏时，才重新构造 Request。
          // 若内容未变，保留原生 resource 对象，防止破坏字节跳动/豆包等严格的风控签名（a_bogus）。
          if (r.masked_text !== raw) {
            resource = new Request(resource, { body: r.masked_text, signal: resource.signal });
          }
        } else if (r && r.blocking) {
          throw new TypeError('Failed to fetch');      // (A) 无条件阻断
        }
        // r.passthrough / r === null（桥超时）→ 原样放行（(B)）
      }
      return sid
        ? wrapResponse(await origFetch.call(this, resource), sid)
        : origFetch.call(this, resource);
    }

    let reqInit = init;
    const isUrlParams = initBodyIsURLSearchParams(init);
    if (initBodyIsFormData(init)) {
      const m = await maskMultipart(init.body);
      if (m && m.blocking) throw new TypeError('Failed to fetch');       // (A)
      if (m) {
        const h = new Headers((init && init.headers) || {});
        h.delete('content-type');
        h.delete('content-length');
        reqInit = { ...init, body: m.body, headers: h };
        const res = await origFetch.call(this, url, reqInit);
        return (m.sid && m.masked) ? wrapResponse(res, m.sid) : res;
      }
    } else if (initBodyIsBlob(init) && isUploadOrStorageUrl(url)) {
      const m = await maskSingleFile(init.body, url);
      if (m && m.blocking) throw new TypeError('Failed to fetch');
      if (m && m.masked) {
        const h = new Headers((init && init.headers) || {});
        h.delete('content-length');
        reqInit = { ...init, body: m.body, headers: h };
        const res = await origFetch.call(this, url, reqInit);
        return m.sid ? wrapResponse(res, m.sid) : res;
      }
    } else if (initBodyIsArrayBuffer(init)) {
      // 魔数先于分流：PDF 不是 ZIP，只认 ZIP 会让 PDF 直传落到文本分支。
      const bytes = init.body instanceof ArrayBuffer ? new Uint8Array(init.body) : new Uint8Array(init.body.buffer, init.body.byteOffset, init.body.byteLength);
      const isDoc = bytes.length > 4 && (isZipMagic(bytes) || isPdfMagic(bytes));
      if (isDoc && isFileUrlMaskable) {
        // ── ArrayBuffer 格式的 Office / PDF 直传 ──
        // 桥调用单独兜底（解析/桥异常 → r=null，即 (B) 原样放行），但 **blocking 判定必须
        // 留在 try 之外**：它是 throw，若写在 try 内会被同一个 catch 静默吞掉，引擎明确
        // 要求的阻断就落回下面的明文直发（同函数其它 blocking 点都在 catch 外）。
        let r = null;
        try {
          const b64 = arrayBufferToBase64(bytes.buffer);
          // 传无扩展名的通用名，让引擎按魔数/内部结构（%PDF- / xl/ / word/ / ppt/）嗅探真实格式。
          // 写死 'attachment.xlsx' 会让嗅探分支永不执行：docx/pptx 被按 xlsx 解析，
          // 一个条目都匹配不上 → hits=0 → 扩展判成「无敏感信息」而静默不脱敏。
          r = await bridge.call('mask_file', { filename: 'attachment', base64: b64 }, HEAVY_CALL_TIMEOUT_MS);
        } catch (e) { r = null; /* 桥不可用 → (B) 原样放行 */ }
        if (r && r.blocking) throw new TypeError('Failed to fetch');   // (A) 必须阻断
        if (r && r.ok && r.base64) {
          const maskedBytes = base64ToUint8Array(r.base64);
          const h = new Headers((init && init.headers) || {});
          h.delete('content-length');
          reqInit = { ...init, body: maskedBytes, headers: h };
          return origFetch.call(this, url, reqInit);
        }
      } else if (isUrlMaskable) {
        // ── 字节跳动/豆包 WebAssembly 文本内存字节数组脱敏分支 ──
        let rawText = null;
        let r = null;
        try {
          rawText = new TextDecoder().decode(init.body);
        } catch (e) { rawText = null; /* 非文本字节 → (B) 原样放行 */ }
        if (rawText && rawText.length > minLen) {
          try {
            r = await callMask(rawText);
          } catch (e) { r = null; }
        }
        if (r && r.blocking) throw new TypeError('Failed to fetch');   // (A) 必须阻断
        if (r && r.ok) {
          sid = r.sid;
          if (r.masked_text !== rawText) {
            const enc = new TextEncoder();
            const maskedBytes = enc.encode(r.masked_text);
            reqInit = { ...init, body: maskedBytes };
          }
        }
      }
    } else if ((initBodyIsText(init) || isUrlParams) && isUrlMaskable && (isUrlParams ? init.body.toString().length : init.body.length) > minLen) {
      const textToMask = isUrlParams ? init.body.toString() : init.body;
      const r = await callMask(textToMask);
      if (r && r.ok) {
        sid = r.sid;
        // 零触碰原则：未命中敏感词时不改写 init 对象，保护签名完整性
        if (r.masked_text !== textToMask) {
          reqInit = { ...init, body: isUrlParams ? new URLSearchParams(r.masked_text) : r.masked_text };
        }
      } else if (r && r.blocking) {
        throw new TypeError('Failed to fetch');        // (A)
      }
    }
    // 未枚举/处理不了的 body 形态（Blob 发往非上传 URL、ReadableStream、Document…）：
    // 原样放行，但 **URL 命中对话白名单时必须留痕** —— 与 isReq 路径
    // （`isUrlMaskable && !isMaskableBody`）同一条原则：判定要在放行**之前**做，
    // 否则没有任何地方能知道这次是明文出网。此前 init 路径一个上报点也没有。
    if (isUrlMaskable && !initBodyWillBeHandled(init, url)) {
      reportUnsupportedBody(url, new Headers((init && init.headers) || {}).get('content-type') || '');
    }
    return sid
      ? wrapResponse(await origFetch.call(this, url, reqInit), sid)
      : origFetch.call(this, url, reqInit);
  };

  // ─── 响应包装（仅已打码请求；sid=null 不碰） ───
  const wrapResponse = (res, sid) => {
    // 204/205/304 等 null-body 状态，new Response(body, {status}) 会抛 TypeError →
    // fetch 整体 reject → 页面网络错误。这类状态直接原样返回。
    if ([204, 205, 304].includes(res.status)) return res;
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    if (!res.body || !streamLike(ct)) return res;

    const streamId = (crypto.randomUUID && crypto.randomUUID()) || String(Math.random()).slice(2);
    const dec = new TextDecoder();
    const enc = new TextEncoder();

    const transformed = res.body.pipeThrough(new TransformStream({
      async transform(chunk, ctrl) {
        // chunk 边界与 SSE 事件边界**无关**：一个 chunk 可能只有半个事件，也可能含
        // 三个事件加半个。分帧必须是引擎的事（`restore_stream_chunk` 按 stream_id
        // 持有半帧缓冲），这里只做字节→文本解码，**绝不自己切帧**。
        //
        // 这一层曾经把整段 SSE 原文直接送去还原，于是被事件边界切开的占位符
        // （`content:"{{EMAIL"` + `content:"_dsszcd}}"`）永远拼不回来，页面上留下
        // 裸 `{{EMAIL_dsszcd}}`。真机往返才暴露——mock 的 SSE 恰好把完整占位符
        // 放在单个事件里，绕过了这个缺陷。
        const text = dec.decode(chunk, { stream: true });
        const r = await bridge.call('restore', {
          sid, stream_id: streamId, text, final: false, content_type: ct,
        });
        ctrl.enqueue(enc.encode(r && r.ok ? r.text : text));   // 还原失败恒透传
      },
      async flush(ctrl) {
        const tail = dec.decode();
        const r = await bridge.call('restore', {
          sid, stream_id: streamId, text: tail, final: true, content_type: ct,
        });
        const out = r && r.ok ? r.text : tail;
        if (tail || out) ctrl.enqueue(enc.encode(out || ''));
      },
    }));

    // 还原后长度已变，原始 content-length 是错的；content-encoding（gzip/br）也不适用
    // 于已解码的流。两者都删，交给浏览器按 chunked 处理。
    const headers = new Headers(res.headers);
    headers.delete('content-length');
    headers.delete('content-encoding');
    let wrapped;
    try {
      wrapped = new Response(transformed, {
        status: res.status, statusText: res.statusText, headers,
      });
    } catch (e) {
      return res;                                      // 构造失败宁可原样返回，不阻断页面
    }
    // new Response() 会丢内部标志：url / type（变 "default"）/ redirected（变 false）。
    // 页面若依赖它们（如 res.redirected 判定登录跳转）会静默走错分支，按需补回。
    const restore = (prop, value) => {
      try {
        Object.defineProperty(wrapped, prop, { value, configurable: true });
      } catch (e) { /* ignore */ }
    };
    restore('url', res.url);
    restore('type', res.type);
    restore('redirected', res.redirected);
    return wrapped;
  };

  // ─── XMLHttpRequest hook ───
  //
  // 注：文本类 mask 的调用点都顺手记下引擎回的 sid（`if (r && r.ok && r.sid) ctx.sid = r.sid`）。
  // 响应侧还原必须用**同一个 sid**（映射挂在它下面），而这个 sid 只有 mask 响应里才有；
  // 文件类分支不记 —— 那是二进制响应，不走文本还原。
  // 桥要求阻断（引擎 413/503/400）时，给页面一个**完整**的失败事件链。
  //
  // ⚠️ 只派 `error` 是不够的：原生 XHR 在失败时**一定同时**派发 `loadend`，而 axios
  // 正是靠 `onloadend` 收尾的 —— 少这一个事件，axios 永远停在 pending（实测：页面卡满
  // 30s 超时，用户看到的是「转圈不停」，比报错更糟）。事件必须走 `dispatchEvent`
  // （MaskitXHR 已把它接到页面注册表上），不能直接调页面的 handler。
  const failXHR = (xhr) => {
    xhr.dispatchEvent(new ProgressEvent('error'));
    xhr.dispatchEvent(new ProgressEvent('loadend'));
  };

  const origXHROpen = window.XMLHttpRequest.prototype.open;
  const origXHRSend = window.XMLHttpRequest.prototype.send;
  const origXHRSetRequestHeader = window.XMLHttpRequest.prototype.setRequestHeader;
  const origXHRAbort = window.XMLHttpRequest.prototype.abort;

  window.XMLHttpRequest.prototype.open = function (method, url, async, user, password) {
    const isAsync = async !== false;
    this._maskit = {
      method: String(method || 'GET').toUpperCase(),
      url: String(url || ''),
      headers: {},
      isAsync: isAsync,
      aborted: false,
    };
    return origXHROpen.apply(this, arguments);
  };

  window.XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
    if (this._maskit && this._maskit.headers) {
      this._maskit.headers[String(name || '').toLowerCase()] = String(value || '');
    }
    return origXHRSetRequestHeader.apply(this, arguments);
  };

  window.XMLHttpRequest.prototype.abort = function () {
    if (this._maskit) {
      this._maskit.aborted = true;
    }
    return origXHRAbort.apply(this, arguments);
  };

  window.XMLHttpRequest.prototype.send = function (body) {
    const ctx = this._maskit;
    if (!ctx || (ctx.method !== 'POST' && ctx.method !== 'PUT' && ctx.method !== 'PATCH') || !body) {
      return origXHRSend.apply(this, arguments);
    }

    if (!ctx.isAsync) {
      // 同步 XHR 做不了脱敏：打码必须异步问引擎，而 sync XHR 不能用 await。
      // **但不能静默**：URL 命中对话/上传白名单时这就是一次无感知漏脱敏（正文明文出网），
      // 必须留痕。用窄模式判据（不依赖异步的 wideMode），宁可少报也不能一声不响。
      if (shouldMaskUrl(ctx.url, false) || isUploadOrStorageUrl(ctx.url)) {
        reportUnsupportedBody(ctx.url, (ctx.headers && ctx.headers['content-type']) || '');
      }
      return origXHRSend.apply(this, arguments);
    }

    const xhr = this;
    const isFormData = typeof FormData !== 'undefined' && body instanceof FormData;
    const isBlob = typeof Blob !== 'undefined' && body instanceof Blob;
    const isString = typeof body === 'string' && body.length > MIN_MASKABLE_LEN;
    const isArrayBuf = typeof ArrayBuffer !== 'undefined' && (body instanceof ArrayBuffer || ArrayBuffer.isView(body));
    // fetch 路径早就显式处理了 URLSearchParams，XHR 之前直接放行 → 这类表单编码 body
    // 会静默未脱敏（同样命中对话白名单时也一声不响）。
    const isUrlParams = typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams;

    if (!isFormData && !isBlob && !isString && !isArrayBuf && !isUrlParams) {
      // 没枚举到的 body 形态：原样放行，但命中白名单时留痕（与 fetch 路径同一条原则）。
      if (shouldMaskUrl(ctx.url, false) || isUploadOrStorageUrl(ctx.url)) {
        reportUnsupportedBody(ctx.url, (ctx.headers && ctx.headers['content-type']) || '');
      }
      return origXHRSend.apply(this, arguments);
    }

    const processAndSend = async () => {
      try {
        const cfg = await getWideMode();
        const isUrlMaskable = shouldMaskUrl(ctx.url, cfg.wideMode);
        const isFileUrlMaskable = shouldMaskFileUrl(ctx.url, cfg.wideMode);

        if (!isUrlMaskable && !isFileUrlMaskable) {
          if (!ctx.aborted) origXHRSend.call(xhr, body);
          return;
        }

        let sendBody = body;
        if (isFormData) {
          const m = await maskMultipart(body);
          if (ctx.aborted) return;
          if (m && m.blocking) {
            failXHR(xhr);
            return;
          }
          if (m && m.body) {
            sendBody = m.body;
          }
        } else if (isBlob && isFileUrlMaskable) {
          const m = await maskSingleFile(body, ctx.url);
          if (ctx.aborted) return;
          if (m && m.blocking) {
            failXHR(xhr);
            return;
          }
          if (m && m.masked) {
            sendBody = m.body;
          }
        } else if (isArrayBuf && (isUrlMaskable || isFileUrlMaskable)) {
          let isDoc = false;
          const bytes = body instanceof ArrayBuffer ? new Uint8Array(body) : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
          if (bytes.length > 4 && (isZipMagic(bytes) || isPdfMagic(bytes))) {
            isDoc = true;
          }
          if (isDoc && isFileUrlMaskable) {
            try {
              const b64 = arrayBufferToBase64(bytes.buffer);
              const r = await bridge.call('mask_file', { filename: 'attachment', base64: b64 }, HEAVY_CALL_TIMEOUT_MS);
              if (ctx.aborted) return;
              if (r && r.blocking) {
                failXHR(xhr);
                return;
              }
              if (r && r.ok && r.base64) {
                sendBody = base64ToUint8Array(r.base64);
              }
            } catch (e) { /* ignore */ }
          } else if (isUrlMaskable) {
            try {
              const dec = new TextDecoder();
              const rawText = dec.decode(body);
              if (rawText && rawText.length > MIN_MASKABLE_LEN) {
                const r = await callMask(rawText);
                if (ctx.aborted) return;
                if (r && r.blocking) {
                  failXHR(xhr);
                  return;
                }
                if (r && r.ok && r.sid) ctx.sid = r.sid;
                if (r && r.ok && r.masked_text && r.masked_text !== rawText) {
                  sendBody = new TextEncoder().encode(r.masked_text);
                }
              }
            } catch (e) { /* ignore */ }
          }
        } else if (isUrlParams && isUrlMaskable) {
          const textToMask = body.toString();
          if (textToMask.length > MIN_MASKABLE_LEN) {
            const r = await callMask(textToMask);
            if (ctx.aborted) return;
            if (r && r.blocking) {
              failXHR(xhr);
              return;
            }
            if (r && r.ok && r.sid) ctx.sid = r.sid;
            // 与 fetch 路径同一套做法：重新构造 URLSearchParams（不要拼字符串），
            // 否则编码可能与原文不一致（空格 / `+` 等）。
            if (r && r.ok && r.masked_text && r.masked_text !== textToMask) {
              sendBody = new URLSearchParams(r.masked_text);
            }
          }
        } else if (isString && isUrlMaskable) {
          const r = await callMask(body);
          if (ctx.aborted) return;
          if (r && r.blocking) {
            failXHR(xhr);
            return;
          }
          if (r && r.ok && r.sid) ctx.sid = r.sid;
          if (r && r.ok && r.masked_text) {
            sendBody = r.masked_text;
          }
        }

        if (ctx.aborted) return;
        // 响应侧还原：仅当拿到 sid、且响应是文本型时启用（见 MaskitXHR）。
        // 这里曾是「XHR 只脱敏不还原」的已知限制 —— 直接改原生实例确实做不到
        // （`responseText` 是同步 getter，而还原要异步问引擎），但换成**继承 +
        // 截获事件派发**就做得到：先还原完，再把事件交给页面。
        if (ctx.sid && typeof xhr.__mkSetupRestore === 'function') {
          xhr.__mkSetupRestore(ctx.sid);
        }
        origXHRSend.call(xhr, sendBody);
      } catch (err) {
        if (!ctx.aborted) {
          origXHRSend.call(xhr, body);
        }
      }
    };

    processAndSend();
  };

  // ─── XHR 响应侧还原（MaskitXHR）────────────────────────────────────────────
  //
  // 【为什么以前算「已知限制」】`responseText` / `response` 是**同步** getter，而还原
  // 必须异步问引擎（占位符→原文的映射只在引擎侧）。直接改原生实例的文本做不到。
  //
  // 【现在怎么做到】换个位置下手：**继承**原生 XHR，并把页面的 `addEventListener`
  // 与 `on*` 全部截获到自己的表里 —— 页面因此**根本没注册到原生实例**上，原生事件
  // 只有我们自己的内部监听收得到。于是「什么时候把事件交给页面」由我们决定：
  // 先异步还原，再派发。页面（axios 就是在 `onprogress` 里读 `responseText`）读到的
  // 已经是还原后的文本。
  //
  // 【安全边界不变】映射仍然只存在于引擎侧，MAIN world 拿到的只有还原结果，与 fetch
  // 路径完全一致。分帧同样交给引擎（`stream_id` + `final`，与 `wrapResponse` 共用同一套
  // `restore_stream_chunk`），这里只喂**新增**的原生文本增量，绝不自己切 SSE 帧 ——
  // 跨 chunk 被切开的占位符由引擎缓冲拼回来。
  //
  // 【绝不碰的场合】`responseType` 不是 text/'' 的、没拿到 sid 的，全部原样透传；
  // 还原失败/超时也恒透传（少还原一个 chunk，绝不能让用户的流卡住）。
  const RESTORE_TIMEOUT_MS = 2500;
  const XHR_EVENT_TYPES = [
    'readystatechange', 'progress', 'load', 'loadstart', 'loadend', 'error', 'abort', 'timeout',
  ];
  const OrigXHR = window.XMLHttpRequest;
  const nativeXHRAddEventListener = OrigXHR.prototype.addEventListener;
  const nativeXHRRemoveEventListener = OrigXHR.prototype.removeEventListener;
  const nativeXHRResponseTextGet = Object.getOwnPropertyDescriptor(OrigXHR.prototype, 'responseText').get;
  const nativeXHRResponseGet = Object.getOwnPropertyDescriptor(OrigXHR.prototype, 'response').get;

  class MaskitXHR extends OrigXHR {
    constructor() {
      super();
      this.__mkListeners = new Map();       // 页面注册的监听器：type -> [{fn, once}]
      this.__mkOn = Object.create(null);    // 页面的 on* 属性
      this.__mkRestore = null;              // 仅当本次请求需要还原时才有值
      // 用**原生** addEventListener 注册内部监听（绕过下面的重写），保证原生事件
      // 一定被我们收到、而页面永远拿不到「未还原」的那一份。
      for (const evType of XHR_EVENT_TYPES) {
        nativeXHRAddEventListener.call(this, evType, (ev) => { this.__mkOnNative(evType, ev); });
      }
    }

    // ── 页面注册面：全部截获，不落到原生实例上 ──
    addEventListener(type, fn, opts) {
      if (!fn || !this.__mkListeners) return nativeXHRAddEventListener.call(this, type, fn, opts);
      const t = String(type);
      const arr = this.__mkListeners.get(t) || [];
      arr.push({ fn, once: !!(opts && typeof opts === 'object' && opts.once) });
      this.__mkListeners.set(t, arr);
    }

    removeEventListener(type, fn) {
      if (!this.__mkListeners) return nativeXHRRemoveEventListener.call(this, type, fn);
      const t = String(type);
      const arr = this.__mkListeners.get(t);
      if (arr) this.__mkListeners.set(t, arr.filter((it) => it.fn !== fn));
    }

    // 我们在阻断分支里用的 `dispatchEvent(new ProgressEvent('error'))` 也必须走这张表
    // （否则页面注册的 onerror 收不到，阻断就成了静默失败）；页面主动派发同理。
    // 这里**不调** super：原生事件不经过本方法，不存在重复派发。
    dispatchEvent(ev) {
      if (!ev || !this.__mkListeners) return super.dispatchEvent(ev);
      this.__mkFire(String(ev.type), ev);
      return true;
    }

    __mkSetupRestore(sid) {
      if (this.__mkRestore) return;
      let rt = '';
      try { rt = String(this.responseType || ''); } catch (e) { return; }
      if (rt !== '' && rt !== 'text') return;      // json/blob/arraybuffer：不是文本，不碰
      this.__mkRestore = {
        sid,
        streamId: (crypto.randomUUID && crypto.randomUUID()) || String(Math.random()).slice(2),
        rawLen: 0,          // 已喂给引擎的**原生**文本长度（还原后长度会变，所以按原生算）
        restored: '',       // 累积的还原结果 —— 即页面读到的内容
        contentType: '',
        finalSent: false,
        failStreak: 0,      // 连续失败计数（成功即归零）
        degraded: false,    // 本次流已放弃还原，全部按原生文本透传
        chain: Promise.resolve(),
      };
    }

    __mkOnNative(evType, ev) {
      const st = this.__mkRestore;
      if (!st) { this.__mkFire(evType, ev); return; }   // 不还原：同步转发，零时序变化
      // 串行化：progress 会连着来，必须让还原按顺序完成，否则结果会错位。
      st.chain = st.chain.then(() => this.__mkHandle(evType, ev)).catch(() => { this.__mkFire(evType, ev); });
    }

    async __mkHandle(evType, ev) {
      const st = this.__mkRestore;
      if (!st) { this.__mkFire(evType, ev); return; }
      const isFinal = evType === 'loadend' || this.readyState === 4;
      try { await this.__mkPull(st, isFinal); } catch (e) { /* 还原失败恒透传 */ }
      this.__mkFire(evType, ev);
    }

    async __mkPull(st, isFinal) {
      let raw = '';
      // 直接调**原生** getter：我们自己的 getter 返回的是还原后的文本，不是引擎要的口径。
      try { raw = nativeXHRResponseTextGet.call(this) || ''; } catch (e) { return; }
      const delta = raw.length > st.rawLen ? raw.slice(st.rawLen) : '';
      if (!delta && !isFinal) return;
      if (isFinal && st.finalSent) return;
      if (isFinal) st.finalSent = true;
      st.rawLen = raw.length;
      if (!st.contentType) {
        try { st.contentType = (this.getResponseHeader('content-type') || '').toLowerCase(); } catch (e) { /* ignore */ }
      }
      // 引擎挂了 / 超时：**连续两次**失败就把本次流降级为纯透传。
      //
      // 只失败一次还可能是引擎忙（偶发），但若不降级，每个 chunk 都要等满
      // RESTORE_TIMEOUT_MS —— 一条 200 chunk 的流就是 500 秒，用户的流被我们拖死。
      // 那比少还原几个字严重得多（同 fetch 路径「宁可少还原，绝不卡住流」的口径）。
      // 失败一次也**不缓存失败结果**：下一 chunk 仍然试，只是不无限等。
      if (st.degraded) { st.restored += delta; return; }
      const r = await bridge.call('restore', {
        sid: st.sid, stream_id: st.streamId, text: delta, final: !!isFinal, content_type: st.contentType,
      }, RESTORE_TIMEOUT_MS);
      if (r && r.ok) {
        st.failStreak = 0;
        st.restored += (typeof r.text === 'string' ? r.text : delta);
        return;
      }
      st.failStreak += 1;
      if (st.failStreak >= 2) st.degraded = true;
      st.restored += delta;     // 还原失败恒透传（与 fetch 路径同口径）
    }

    __mkFire(evType, ev) {
      const list = this.__mkListeners && this.__mkListeners.get(evType);
      if (list && list.length) {
        for (const item of list.slice()) {
          if (item.once) this.removeEventListener(evType, item.fn);
          // 页面自己的异常不该吃掉同事件上的其它监听（原生行为也是这样）。
          try { item.fn.call(this, ev); } catch (e) { /* ignore */ }
        }
      }
      const on = this.__mkOn && this.__mkOn[evType];
      if (typeof on === 'function') {
        try { on.call(this, ev); } catch (e) { /* ignore */ }
      }
    }
  }

  // on* 属性：原生的是原型上的 setter/getter，直接覆盖成我们的表（含 get 回读）。
  for (const evType of XHR_EVENT_TYPES) {
    Object.defineProperty(MaskitXHR.prototype, 'on' + evType, {
      configurable: true,
      get() { return this.__mkOn ? this.__mkOn[evType] : null; },
      set(fn) {
        if (!this.__mkOn) return;
        if (typeof fn === 'function') this.__mkOn[evType] = fn;
        else delete this.__mkOn[evType];
      },
    });
  }

  Object.defineProperty(MaskitXHR.prototype, 'responseText', {
    configurable: true,
    get() {
      const st = this.__mkRestore;
      if (!st) return nativeXHRResponseTextGet.call(this);
      // 先过一遍原生 getter：readyState < 3 或 responseType 非 text 时它会按规范抛
      // InvalidStateError，这个语义必须保留（库靠它判断状态）。
      nativeXHRResponseTextGet.call(this);
      return st.restored;
    },
  });

  Object.defineProperty(MaskitXHR.prototype, 'response', {
    configurable: true,
    get() {
      const st = this.__mkRestore;
      if (!st) return nativeXHRResponseGet.call(this);
      let rt = '';
      try { rt = String(this.responseType || ''); } catch (e) { rt = 'x'; }
      if (rt === '' || rt === 'text') return st.restored;
      return nativeXHRResponseGet.call(this);
    },
  });

  // 替换全局构造器。bridge-main 是 document_start 注入，页面脚本必然在这之后解析，
  // 所以页面拿到的是 MaskitXHR；`instanceof XMLHttpRequest` 仍然成立（继承）。
  //
  // 【作用域收窄（2026-09-21 回归修复）】**只在 DeepSeek 替换**。
  // 原生 XHR 事件是**同步**派发的，而本构造器把页面监听全部截获、改成「先异步还原再派发」
  // —— 这对**每一个** XHR 请求都加了一层时序包装，任何依赖同步时序的页面代码都可能出错。
  // 实测：ChatGPT / Claude 这两个此前已验证可用的站点因此出现异常。
  // XHR 响应还原目前只为 DeepSeek（axios 在 onprogress 里读 responseText）落地，
  // 所以其余站点一律保持原生构造器，零副作用。以后要扩站点，先在那个站点真机验证。
  const XHR_RESTORE_HOSTS = /(^|\.)deepseek\.com$/i;
  if (XHR_RESTORE_HOSTS.test(location.hostname)) {
    window.XMLHttpRequest = MaskitXHR;
  }

  // ─── 桥失联 → 恢复原生（2026-09-21）────────────────────────────────────
  //
  // 【为什么需要】重载/更新扩展会**销毁已打开页面**里的 content script 上下文，
  // 新脚本只在下次导航时注入。而旧页面里的 fetch/XHR 仍被本脚本 patch 着，它们要
  // 调的后台（ISOLATED 侧与 SW）已经换新 —— 于是请求卡住或抛异常，页面进入「半死」
  // 状态：既不脱敏，也不能正常用。这比单纯「不脱敏」更糟（实测 ChatGPT/Claude 会这样）。
  //
  // 【怎么判断】扩展失联后 MAIN 侧的 postMessage 不再有人应答，bridge.call 必然
  // 一路超时返回 null。连续 BRIDGE_DOWN_STREAK 次拿不到结果就认定桥断了。阈值取 4
  // 而不是 1~2：mask 走 6s 超时且引擎侧有全局锁，偶发慢响应不该被当成失联。
  //
  // 【恢复成什么】恢复**原生** fetch/XHR，并从此不再干预本页。这与 SECURITY.md 里
  // 「(B) 直通 = 未脱敏」是同一个取向：项目红线是「绝不断网」，引擎/桥不可用时明文
  // 直连是刻意的默认。恢复原生只是把这种退化变得**干净、可预期**，并让用户知道
  // 「本页需要刷新」——而不是留一堆半死的 patch。
  //
  // ⚠️ 只动「注入与失联处置」，不碰任何打码/还原逻辑。
  const BRIDGE_DOWN_STREAK = 4;
  let bridgeDownStreak = 0;
  let nativeRestored = false;

  function restoreNativeAndStop(reason) {
    if (nativeRestored) return;
    nativeRestored = true;
    // 判断条件用「引用是否已变」而不是记一个标志位：页面可能自己包装过 fetch
    // （Sentry 这类 SDK 就会），那种包装是基于我们的版本的，一起换回原生会让它失效。
    // 两弊相权取其轻：半死的页面比「页面包装被拆掉」严重得多，而且下面 console 会
    // 明确提示「请刷新页面」。
    try {
      if (window.fetch !== origFetch) window.fetch = origFetch;
    } catch (_e) { /* 页面冻结了 window，放弃恢复 */ }
    try {
      if (window.XMLHttpRequest === MaskitXHR) window.XMLHttpRequest = OrigXHR;
    } catch (_e) { /* 同上 */ }
    try {
      console.warn('[Maskit] 与扩展后端失联（' + reason + '），已恢复原生网络行为：'
        + '本页将不再脱敏，请**刷新页面**以重新启用保护。');
    } catch (_e) { /* console 被页面接管 */ }
  }

  function noteBridgeCall(ok) {
    if (ok) { bridgeDownStreak = 0; return; }
    if (nativeRestored) return;
    bridgeDownStreak += 1;
    if (bridgeDownStreak >= BRIDGE_DOWN_STREAK) {
      restoreNativeAndStop(bridgeDownStreak + ' 次调用无响应');
    }
  }
})();
