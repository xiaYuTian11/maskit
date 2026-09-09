# 发布检查清单

每个版本在创建 tag 前完成以下检查，并把命令与结果附在发布记录或 PR 中。

## 代码与依赖

- [ ] 工作区没有运行时文件、诊断包、事件库、`.env` 或凭据。
- [ ] `python -m py_compile engine/*.py`。
- [ ] `python -m unittest discover -s tests`。
- [ ] `python tests/smoke_stream.py` 与 `python tests/smoke_egress.py`。
- [ ] `cd frontend; npm ci; npm run build; npm run lint; node ../scripts/check-i18n.mjs`。
- [ ] `python scripts/check-version.py`，四处版本号一致。
- [ ] 修改 `src-tauri/` 时再执行 `cargo check` 与 `cargo test --lib`。

## Docker

- [ ] `docker build --pull -t maskit:release-candidate .` 成功。
- [ ] `docker run --rm maskit:release-candidate` 使用非 root 用户启动。
- [ ] 容器 `/healthz` 返回 2xx，`/api/status` 无令牌返回 403，正确令牌返回 2xx。
- [ ] Compose 默认端口解析为 `127.0.0.1`；远程部署显式设置 `MASKIT_BIND_HOST`、固定 token/token file 和可信反代。
- [ ] 按目标架构验证 `linux/amd64` 和 `linux/arm64`，或记录未覆盖的架构。
- [ ] 命名卷/绑定目录可写，升级后配置和事件库仍存在。
- [ ] 只向可信网络暴露面板和反向代理端口，并设置 `MASKIT_PANEL_TOKEN`。

## Windows 桌面包

- [ ] `.\build.ps1 -ReleaseOnly` 成功，安装包和哈希已记录。
- [ ] 安装、启动、启动/停止代理、托盘菜单、卸载各走一遍。
- [ ] 在临时目录做一次覆盖安装/升级，确认现有 `%APPDATA%\\Maskit` 配置保留；测试过程不得终止另一份正在运行的 Maskit。
- [ ] 卸载后确认自启注册表项和本机捕获证书按预期清理。
- [ ] 更新器只在用户主动检查或确认安装时运行；版本号和 Release 资产一致。

## GitHub 发布设置

- [ ] `master` 分支保护仍要求 `python`、`frontend`、`rust`、`version` 四个 check、PR 和 Code Owner 审批。
- [ ] tag 使用 `vMAJOR.MINOR.PATCH`，Release 草稿由工作流创建后人工核对说明和资产。
- [ ] Secret scanning、Push protection、Dependabot alerts 和私密漏洞报告已开启。
- [ ] Release notes 明确列出支持平台、已知限制和升级/回滚方式。
- [ ] GitHub Secret Scanning 无未处理告警；若为测试样例误报，先改成运行时构造并在 GitHub 标记误报/已撤销。
