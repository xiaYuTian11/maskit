# 贡献指南（Contributing）

欢迎贡献！本仓库使用 GitHub Flow：`master` 为稳定分支，功能开发走分支 + PR。

## 分支与 PR

1. 从 `master` 新建功能分支：`git checkout -b feat/<描述>`
2. 提交使用 Conventional Commits：`feat:` / `fix:` / `perf:` / `docs:` / `chore:`
3. 推送后创建 PR 到 `master`（使用 `.github/PULL_REQUEST_TEMPLATE.md` 模板）
4. CI 四个 job（`python` / `frontend` / `rust` / `version`）全绿 + 维护者审批后合并

分支保护规则见 [docs/BRANCH_PROTECTION.md](docs/BRANCH_PROTECTION.md)。

## 验证标准（合并前必须全过）

```bash
# 0. Python 3.13 + pip install -r requirements.txt（其它版本未验证）
python -V   # 3.13.x

# 1. 语法 + 单测 + 流式/出口冒烟（Windows pwsh 下单引号或遍历）
python -c "import py_compile, glob; [py_compile.compile(f) for f in glob.glob('engine/*.py')]"
python -m unittest discover -s tests
python tests/smoke_stream.py
python tests/smoke_egress.py

# 2. 前端类型检查 + 构建 + Lint + 中英文字典对齐
cd frontend && npm ci && npm run build && npm run lint && node ../scripts/check-i18n.mjs && cd ..

# 3. Rust 壳编译与单测（改了 src-tauri 时；先 mkdir src-tauri/resources/engine 占位）
cd src-tauri && cargo check && cargo test --lib && cd ..

# 4. 版本号四处一致
python scripts/check-version.py
```

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
