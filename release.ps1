# Data Maskit 一键发版流水线：前置拉取 -> 构建打包 -> 自动提交流水线 -> 打 Tag -> 推送远程
# 用法：
#   .\release.ps1                     # 自动递增 patch 版本号并全流程发版
#   .\release.ps1 -Version "0.2.6"     # 指定版本号发版
#   .\release.ps1 -BuildOnly          # 只拉取和打包，不执行 git commit/push/tag
#   .\release.ps1 -Yes                # 静默模式，跳过最终推送确认
param(
    [string]$Version = "",
    [switch]$BuildOnly,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "       Data Maskit 发布流水线 (Release Pipeline)   " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# 0. 优先使用 PowerShell 7 (pwsh)
$psExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }

# 1. 检查分支与 Git 环境
$currentBranch = (git branch --show-current).Trim()
if ($currentBranch -ne "master" -and $currentBranch -ne "main") {
    Write-Warning "当前分支为 [$currentBranch]，非 master/main。确定要在此分支发布吗？"
    if (-not $Yes) {
        $confirm = Read-Host "按 Y 继续，其他键退出"
        if ($confirm -notmatch '^[Yy]$') { exit 0 }
    }
}

# 2. 前置拉取：与远程对齐，杜绝推送冲突
Write-Host "`n[1/4] 正在拉取远程最新提交 (git pull origin $currentBranch)..." -ForegroundColor Cyan
try {
    git pull origin $currentBranch
    Write-Host "远程分支已同步。" -ForegroundColor Green
} catch {
    Write-Error "Git pull 失败，请先手动处理冲突或网络问题后再发版！"
    exit 1
}

# 3. 执行核心构建 (build.ps1 -ReleaseOnly)
Write-Host "`n[2/4] 调用 build.ps1 执行打包与四道门禁验证..." -ForegroundColor Cyan
$buildArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $Root "build.ps1"), "-ReleaseOnly")
if ($Version) {
    $buildArgs += @("-Version", $Version)
}

& $psExe @buildArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "构建或门禁验证失败 (ExitCode: $LASTEXITCODE)，已中止发版流程！未产生任何 Git 提交。"
    exit $LASTEXITCODE
}

# 读取构建出的最新版本号
$panelPath = "engine\panel.py"
$verLine = Select-String -Path $panelPath -Pattern "__version__ = '(\d+\.\d+\.\d+)'" | Select-Object -First 1
if (-not $verLine) { Write-Error "无法读取构建后的版本号"; exit 1 }
$targetVer = $verLine.Matches[0].Groups[1].Value
$tag = "v$targetVer"

Write-Host "`n[3/4] 构建成功！目标版本: $targetVer (Tag: $tag)" -ForegroundColor Green

if ($BuildOnly) {
    Write-Host "`n已指定 -BuildOnly，跳过 Git 提交与远程推送。" -ForegroundColor Yellow
    Write-Host "安装包已就绪于: src-tauri\target\release\bundle\nsis\Maskit_${targetVer}_x64-setup.exe" -ForegroundColor Cyan
    exit 0
}

# 3.5 CHANGELOG 章节预检（放在 -BuildOnly 之后：只打包测试时不需要章节）
#     release.yml 的 release-draft job 会用 scripts/render-release-notes.py 从 CHANGELOG.md
#     切出 `## [<version>]` 章节作为 Release body（中英双语）。章节缺失时该脚本 SystemExit(1)，
#     发版 job 直接失败 —— 但那时 tag 已经推到远端了，清理起来很麻烦。
#     所以在 commit/tag 之前就拦住，让失败点留在本地。
$changelogPath = Join-Path $Root "CHANGELOG.md"
if (-not (Test-Path $changelogPath)) {
    Write-Error "找不到 CHANGELOG.md ($changelogPath)。Release body 需要它，请先创建。"
    exit 1
}
$changelogHeading = "## [$targetVer]"
if (-not (Select-String -Path $changelogPath -Pattern $changelogHeading -SimpleMatch -Quiet)) {
    Write-Host ""
    Write-Host "CHANGELOG.md 里找不到章节: $changelogHeading" -ForegroundColor Red
    Write-Host "GitHub Release 的双语说明是从该章节提取的，缺失会让云端发版 job 失败。" -ForegroundColor Yellow
    Write-Host "请按 AGENTS.md「CHANGELOG 维护工作流」补好后重跑：" -ForegroundColor Yellow
    Write-Host "    1) 把开发期间累积的 `## [Unreleased]` 条目改名为 $changelogHeading - <日期>" -ForegroundColor Yellow
    Write-Host "    2) 或直接新建该章节并写入中英双语条目" -ForegroundColor Yellow
    Write-Error "CHANGELOG 章节缺失，已中止发版（未产生任何 Git 提交或 Tag）。"
    exit 1
}
Write-Host "CHANGELOG.md 已包含 $changelogHeading 章节。" -ForegroundColor Green

# 4. 检查是否有需要提交的改动
$status = (git status --porcelain)
if (-not $status) {
    Write-Host "工作区没有可提交的改动。" -ForegroundColor Yellow
} else {
    Write-Host "`n待提交的改动清单:" -ForegroundColor DarkGray
    git status -s

    if (-not $Yes) {
        Write-Host ""
        $confirm = Read-Host "确认提交以上改动并推送至远程 (含 Tag $tag)？[y/N]"
        if ($confirm -notmatch '^[Yy]$') {
            Write-Host "已取消 Git 提交与推送。本地构建产物依然有效。" -ForegroundColor Yellow
            exit 0
        }
    }

    Write-Host "`n[4/4] 正在执行 Git 提交、打 Tag 与推送到 GitHub..." -ForegroundColor Cyan
    
    # 安全暂存：更新已跟踪文件，补入合规的新增文档与脚本
    git add -u
    if (Test-Path "docs\architecture-en.png") { git add docs\architecture-en.png docs\architecture-zh.png }
    if (Test-Path "release.ps1") { git add release.ps1 }

    # 提交
    $commitMsg = "chore(release): 发布 v$targetVer"
    git commit -m $commitMsg
    Write-Host "已提交: $commitMsg" -ForegroundColor Green

    # 推送主分支
    Write-Host "正在推送分支到 origin $currentBranch..." -ForegroundColor Cyan
    git push origin $currentBranch
    Write-Host "分支推送完成。" -ForegroundColor Green

    # 创建并推送 tag
    Write-Host "正在打 Tag 并推送: $tag..." -ForegroundColor Cyan
    git tag $tag
    git push origin $tag
    Write-Host "Tag $tag 推送完成！" -ForegroundColor Green

    Write-Host "`n=================================================" -ForegroundColor Green
    Write-Host "🎉 发布完成！v$targetVer 已成功推送！" -ForegroundColor Green
    Write-Host "GitHub Release Actions 正在云端自动构建多架构 Docker 镜像与发布页面。" -ForegroundColor Green
    Write-Host "查看进度: https://github.com/xiaYuTian11/maskit/actions" -ForegroundColor Cyan
    Write-Host "=================================================" -ForegroundColor Green
}
