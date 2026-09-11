# 平台与部署支持

这份矩阵描述当前仓库的构建与验证边界。桌面包是否适合终端用户，以对应 Release 资产的签名、公证和安装测试结果为准。

| 形态 | 架构 | 状态 | 说明 |
| --- | --- | --- | --- |
| Windows 桌面安装包 | x86_64 | 主发行形态 | Tauri 2 + 内置 Python sidecar，NSIS 安装包；系统托盘、开机自启和自动恢复已针对 Windows 实现。 |
| Docker 无头服务 | linux/amd64 | 支持 | Web 控制台和反向代理端口，适合 Linux 服务器、NAS 或 Windows/macOS 上的 Docker Desktop。 |
| Docker 无头服务 | linux/arm64 | 支持 | 由 Release 工作流构建，多数 ARM64 NAS/服务器可用；请确认 Docker 主机支持对应架构。 |
| 源码引擎 + Web 控制台 | Windows / Linux / macOS | 可启动 | Python 3.13 + Flask；基础反向代理/Web 控制台可运行，系统代理/证书等平台特性请按目标系统单独验证。 |
| 原生 macOS 桌面安装包 | arm64 | 暂未发布 | 官方桌面端目前仅支持 Windows；macOS 建议使用 Docker 镜像或源码形态。 |
| 原生 Linux 桌面安装包 | x86_64 | 暂未发布 | 官方桌面端目前仅支持 Windows；Linux 建议使用 Docker 官方多架构镜像部署。 |

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

## 桌面构建

Windows 安装包由根目录流水线生成：

```powershell
.\build.ps1 -ReleaseOnly
```

构建前请安装 Python 3.13、Node.js 20+、Rust stable 和 WebView2。Windows 发布产物位于 `src-tauri/target/release/bundle/nsis/`（目前官方 Release 工作流仅构建 Windows 桌面安装包；macOS/Linux 推荐使用 Docker 或源码形态）。没有配置更新签名密钥时，工作流会明确标记 `UNSIGNED.txt`，这类包只能手动安装，不能启用自动更新。

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
