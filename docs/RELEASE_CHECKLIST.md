# 发布检查清单

每个版本在创建 tag 前完成以下检查，并把命令与结果附在发布记录或 PR 中。

## 代码与依赖

- [ ] 工作区没有运行时文件、诊断包、事件库、`.env` 或凭据。
- [ ] `python scripts/verify-all.py` 全绿（13 项，本地与 CI 同一份清单；分组见 AGENTS §4）。
      `build.ps1` / `release.ps1` 内部已调用它，无需手工重跑，但发版前要确认输出里没有
      `verify-all: FAIL`。
- [ ] `python scripts/check-version.py`，**7 处**版本号一致（`panel.py` / `tauri.conf.json` /
      `Cargo.toml` / `package.json` 四个主字段 + `Cargo.lock` / `package-lock.json` /
      `package-lock` 根字段）。
- [ ] 改动 `.github/workflows` 时额外确认 `python scripts/check-workflows.py` 通过
      （含 `verify-all.py` ↔ `ci.yml` 的门禁漂移比对）。

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

## macOS 桌面包（Apple Silicon）

- [ ] GitHub Actions `macos-arm64` 构建产物 `Maskit_<版本>_aarch64.dmg` 成功生成。
- [ ] 挂载 DMG 拖入 Applications，验证启动、系统托盘、代理启停与主窗口呼出。
- [ ] 验证开机自启动：在设置中开启后，检查 `~/Library/LaunchAgents/com.maskit.app.plist` 存在且生效。
- [ ] 首次打开若触发 Gatekeeper 拦截，验证使用右键打开或 `xattr -cr /Applications/Maskit.app` 解除隔离后正常使用。

## GitHub 发布设置

- [ ] `master` 分支保护仍要求 `python`、`frontend`、`rust`、`rust-macos`、`version` 五个 check、PR 和 Code Owner 审批（`rust-macos` 是 0.2.8 新增，需手工加到 Required status checks，否则它只跑不拦）。
- [ ] tag 使用 `vMAJOR.MINOR.PATCH`；工作流在**签名完整时自动转正** Release，签名缺失时保持草稿（需修好签名 secret 并手动发布）。发布后核对说明与资产。
- [ ] Secret scanning、Push protection、Dependabot alerts 和私密漏洞报告已开启。
- [ ] Release notes 明确列出支持平台、已知限制和升级/回滚方式。
- [ ] GitHub Secret Scanning 无未处理告警；若为测试样例误报，先改成运行时构造并在 GitHub 标记误报/已撤销。
