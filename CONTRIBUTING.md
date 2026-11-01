# 贡献指南（Contributing）

欢迎贡献！本仓库遵循极简的双分支协作模型：`master` 为生产稳定分支，日常开发与功能迭代在 `dev` 分支进行。

## 分支与开发流程

1. **日常开发在 `dev` 分支**：所有功能开发、Bug 修复均基于 `dev` 分支进行；
2. **提交规范**：使用 Conventional Commits：`feat:` / `fix:` / `perf:` / `docs:` / `chore:`；
3. **本地全量门禁必须全绿**：合并前必须在本地跑通全量 24 项门禁（`python scripts/verify-all.py`）；
4. **合并至 `master`**：测试全通后合入 `master`，远端 CI 5 个 job 全绿后方可安排发版；
5. **正式发版仅在 `master`**：Release 与正式版 Tag 必须且只能在 `master` 分支打出。

分支保护规则见 [docs/BRANCH_PROTECTION.md](docs/BRANCH_PROTECTION.md)。

## 验证标准（合并前必须全过）

门禁清单的**唯一来源是 `scripts/verify-all.py`**（与 `ci.yml` 双向比对，漂移会在 PR 阶段报错），
本地跑这一条就等价于全量 CI：

```bash
# 0. Python 3.13 + pip install -r requirements.txt（其它版本未验证）
python -V   # 3.13.x

# 1. 全量门禁（python / frontend / rust / version 四组共 23 项）
python scripts/verify-all.py

# 只想跑某几组 / 看清单
python scripts/verify-all.py --only python,version
python scripts/verify-all.py --list
```

单独跑各组时（等价于上面的分组）：

```bash
# python：语法 + 单测 + 流式/出口冒烟（Windows pwsh 下单引号或遍历）
python -c "import py_compile, glob; [py_compile.compile(f) for f in glob.glob('engine/*.py')]"
python -m unittest discover -s tests
python tests/smoke_stream.py
python tests/smoke_egress.py

# frontend：类型检查 + 构建 + Lint + 中英文字典对齐 + .env 导入解析用例
cd frontend && npm ci && npm run build && npm run lint \
  && node ../scripts/check-i18n.mjs \
  && node --experimental-strip-types ../scripts/check-env-import.mjs \
  && node --experimental-strip-types ../scripts/check-release-notes.mjs && cd ..

# rust：壳编译与单测（先 mkdir src-tauri/resources/engine 占位）
cd src-tauri && cargo check && cargo test --lib && cd ..

# version：版本号 7 处一致（panel.py / tauri.conf.json / Cargo.toml / package.json
#          + Cargo.lock / package-lock.json / package-lock 根字段）
python scripts/check-version.py
python scripts/audit-public-release.py
python scripts/check-workflows.py   # 依赖 pyyaml；改动 .github/workflows 时必跑
python scripts/check-changelog.py   # 版本章节必须有「更新摘要 / Summary」
```

> 本地跑门禁前若 `frontend/dist` 已存在，某些带安全删除守卫的环境会拦截 vite 清空
> 输出目录（批量删除阈值）。先删掉 `frontend/dist` 即可，它是构建产物、已 gitignore。

首次运行源码态引擎：`python engine/panel.py` 会在 `engine/` 下生成 `config.json`（已 gitignore），
模板见 `engine/config.example.json`。

## 代码约定

### 后端（Python）

- 核心模块不 import mitmproxy 之外的重依赖；`audit_signals.py` 保持纯 stdlib（可单测）
- **fail-closed 红线**：脱敏管线异常必须 503 阻断，绝不放行原文上行
- **凭据红线**：API_KEY/TOKEN/SECRET 类事件只存 preview + sha256 摘要；导出恒剔除 `items[].original`
- **占位符红线**：新增"命中 → 替换"循环必须先 `dict.fromkeys()` 去重（防 O(命中×长度)）
- 业务规则/状态值/公式必须写注释（字面值来源、口径、修改影响）
- 新增规则（RULES）必须带正例 + 反例单测

### 前端（React + TS）

- 新增 UI 一律 Tailwind 类 + shadcn/ui 语义组件（pill/btn/card），禁止散乱手写样式
- 列表数据放 query cache（TanStack Query），组件只读 data，游标从 data 派生
- 暗色模式优先，对比度 ≥ 3.5:1；CANCEL/DNS_ERROR 不得标红
- 所有用户可见文案走 `lib/i18n.tsx` 的 `t()`/`tf()`，zh / en 同时补齐（CI 会检查两组 key 是否一致）

### Rust 壳（Tauri）

- 引擎进程管理改动后必须跑三轮启停验证
- 新 Tauri command 用 `async fn`（避免阻塞主线程）

## 敏感信息

- `.env*` / `proxy_token` / `engine/config.json` / 事件库已 gitignore；新增凭据类文件必须确认不入库
- 不要在代码、测试样例、提交信息、PR 中贴真实 API key、内网地址、个人数据；测试用的凭据形态串必须一眼可见是伪造的（如 `sk-test-0000…`）
- 本项目承诺零遥测：新增任何对外网络请求必须先在 SECURITY.md「出站清单」登记并默认关闭

## 更新日志（CHANGELOG）

`CHANGELOG.md` 不只是开发者日志：GitHub Release 正文、桌面端更新弹窗、Web/Docker 控制台的
「更新日志」卡片都直接读它。所以每个版本章节**开头**必须有一段给普通用户看的说明：

```md
## [0.11.1] - 2026-10-16

### 更新摘要 / Summary
- 面板上的「还原失败」不再把不属于你的占位符也算进去，那个数字现在可信了。
- The dashboard's "restore failures" no longer counts placeholders this machine never issued.

### 修复 / Fixed
- （技术细节写在这里，可以写文件名、函数名、状态码）
```

规则（由 `scripts/check-changelog.py` 在 CI 里强制）：

- 摘要必须是本版本**第一个**子节，1~3 条，中英各至少一条；
- 摘要里不写反引号代码、源码文件名、`文件:行号`、HTTP 状态码与硬技术术语
  （SSE / NDJSON / mitmproxy / NER / GIL / JSON / TLS / Content-Encoding …）；
  中文 ≤ 200 字、英文 ≤ 400 字符；
- 「占位符」「上游」「流式」「脱敏」「还原」「API」「URL」是产品概念，可以出现；
- 技术细节不受限制，写在摘要下面的分节里；
- `0.10.1` 之前的历史章节不回溯检查（已发布的 Release 页改不了）。

## 版本

- 版本唯一来源 `engine/panel.py:__version__`；`tauri.conf.json` / `Cargo.toml` / `frontend/package.json` 必须同步（`scripts/check-version.py`），发版用 `build.ps1`
- 纯文档改动不用升版本

## 测试约定

- 单测不允许真实扫端口/杀进程（曾把运行中的 Shield 真实 taskkill）——涉及启停/端口必须 mock
- 新增业务逻辑（规则/状态/统计/权限）必须补单测

## 开发者原创声明与许可（Developer Certificate of Origin）

为维护健康的开源社区生态并保障所有使用者的权益，所有向本仓库提交 Pull Request 的贡献者均遵循行业标准的 DCO 约定：

1. **原创性保证**：您保证所提交的代码、补丁或文档系您本人的原创作品，或您拥有将其以 AGPL-3.0 协议贡献给本项目的完整权利，不存在侵犯第三方专利、著作权或商业机密的情形。
2. **许可授予**：您授予本项目维护者与全球社区永久、非排他性、免版税的权利，允许将您的贡献内容按照本项目的开源许可证及项目正常维护演进进行使用、修改、集成与分发。
3. **署名保留**：您的贡献将在 Git 提交历史记录与开源 Contributors 列表中永久署名保留。
