# 平台与部署支持

这份矩阵描述当前仓库的构建与验证边界。桌面包是否适合终端用户，以对应 Release 资产的签名、公证和安装测试结果为准。

| 形态 | 架构 | 状态 | 说明 |
| --- | --- | --- | --- |
| Windows 桌面安装包 | x86_64 | 主发行形态 | Tauri 2 + 内置 Python sidecar，NSIS 安装包；系统托盘、开机自启和自动恢复已针对 Windows 实现。 |
| Docker 无头服务 | linux/amd64 | 支持 | Web 控制台和反向代理端口，适合 Linux 服务器、NAS 或 Windows/macOS 上的 Docker Desktop。 |
| Docker 无头服务 | linux/arm64 | 支持 | 由 Release 工作流构建，多数 ARM64 NAS/服务器可用；请确认 Docker 主机支持对应架构。 |
| 源码引擎 + Web 控制台 | Windows / Linux / macOS | 可启动 | Python 3.13 + Flask；基础反向代理/Web 控制台可运行，系统代理/证书等平台特性请按目标系统单独验证。 |
| 原生 macOS 桌面安装包 | arm64 (Apple Silicon) | 支持 | 由 GitHub Actions Release 工作流自动编译生成 DMG 安装包；内置 Python 引擎 sidecar 与开机自启（LaunchAgent）。 |
| 原生 Linux 桌面安装包 | x86_64 | 暂未发布 | 官方桌面端目前只发布 Windows 与 macOS 两种原生包；Linux 建议使用 Docker 官方多架构镜像部署（源码引擎 + Web 控制台在 Linux 上可运行）。 |

## Docker 验证

在发布前至少验证本机架构与镜像健康状态：

```bash
docker compose build --pull
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:5801/healthz
docker compose down
```

远程访问必须设置 `MASKIT_PANEL_TOKEN` 或 `MASKIT_PANEL_TOKEN_FILE`（至少 16 位 ASCII），并只向可信网络暴露 `5801` 与 `187xx` 端口。Compose 默认将主机端口绑定到 `127.0.0.1`；需要远程访问时显式设置 `MASKIT_BIND_HOST` 并配置防火墙。`/healthz` 是唯一不需要令牌的存活探针；控制台登录和 `/api/*` 请求仍需要令牌。

## 低配设备与启动超时

代理进程冷启动时要加载 `transparent.py` 并绑定全部 upstream 端口，默认就绪等待上限为 60 秒。NAS、低配云主机或多 upstream 场景下可能超过该上限，面板会判定「启动失败」并回退到透明直连（网络不断，但不脱敏）。

若确认是启动慢而非崩溃（日志里能看到进程仍在运行），可放宽就绪等待上限（单位秒；只影响启动判定，不影响运行时性能）：

```bash
MASKIT_START_READY_TIMEOUT=120
```

Docker 用 `-e MASKIT_START_READY_TIMEOUT=120` 传入；桌面客户端需在系统环境变量中设置后重启应用。仍反复超时请先排查端口占用与 mitmdump 是否可执行，不要单纯加大该值。

## 桌面构建

Windows 安装包由根目录流水线生成：

```powershell
.\build.ps1 -ReleaseOnly
```

构建前请安装 Python 3.13、Node.js 20.19+ 或 22.12+（CI 用 22；`scripts/check-env-import.mjs`
依赖 `--experimental-strip-types`，需 ≥22.6）、Rust stable 和 WebView2。Windows 发布产物位于 `src-tauri/target/release/bundle/nsis/`；macOS 发布产物位于 `src-tauri/target/release/bundle/dmg/`（官方 GitHub Actions Release 工作流现已同时构建并发布 Windows x86_64 与 macOS Apple Silicon 原生桌面安装包）。没有配置更新签名密钥时，工作流会明确标记 `UNSIGNED.txt`，这类包只能手动安装，不能启用自动更新。

## 源码运行

跨平台只运行引擎和 Web 控制台时，使用：

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# POSIX:   source .venv/bin/activate
pip install -r requirements.txt
python engine/panel.py
```

前端开发服务器只用于开发联调；生产 Docker/源码面板由 Flask 同源托管构建后的 `frontend/dist`。
