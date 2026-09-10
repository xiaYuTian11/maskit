### 改动说明 / What does this PR do?
<!-- 一两句话：解决什么问题、怎么解决 -->

Closes #

### 影响范围 / Scope
- [ ] 脱敏/还原引擎（`engine/transparent.py`）—— 已跑 `python tests/smoke_stream.py`
- [ ] 控制面 / API（`engine/panel.py`）
- [ ] 前端界面 —— 中英文文案都已补齐
- [ ] 桌面壳（`src-tauri/`）—— 已跑 `cargo test --lib`
- [ ] 打包 / Docker / CI
- [ ] 仅文档

### 自检 / Checklist
- [ ] 未提交任何真实密钥、内网地址、个人数据（含测试样例）
- [ ] 未新增任何对外网络请求（本项目承诺零遥测；如确需新增，已在 SECURITY.md「出站清单」登记）
- [ ] 提交信息符合 Conventional Commits（`feat:` / `fix:` / `docs:` …）
- [ ] 我确认所提交的代码为本人原创，并遵循本项目开源协议

> CI 会自动跑 Python 单测 + 冒烟、前端类型/Lint/i18n 对齐、Rust 编译与单测、版本号一致性。全绿后维护者审阅合并。
