# Data Maskit 一键发版流水线：前置拉取 -> 构建打包 -> 自动提交流水线 -> 打 Tag -> 推送远程
# 用法：
#   .\release.ps1                     # 自动递增 patch 版本号并全流程发版
#   .\release.ps1 -Version "0.2.6"     # 指定版本号发版
#   .\release.ps1 -BuildOnly          # 只拉取和打包，不执行 git commit/push/tag
#   .\release.ps1 -Yes                # 静默模式，跳过最终推送确认
param(
    [string]$Version = "",
    [switch]$BuildOnly,
    [switch]$Yes,
    # 附加到发版提交说明（追加在标题行之后）。按项目约定，模型版本核验结论必须
    # 带日期锚点进 commit message（形如「模型核验 2026-11-10：上游无更新」）——
    # 核验是人对上游发布的事实判断，仓库里没有别的痕迹可复核。
    # 不传时行为与改动前完全一致（只有标题行）。
    [string]$Note = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

# 原生命令（git / pwsh）失败**不会**触发 try/catch：$ErrorActionPreference 只约束
# cmdlet，外部进程要靠 $LASTEXITCODE 判断。早先只在 build.ps1 那一步查了退出码，
# pull / add / commit / push / tag 全部「跑了就算成功」—— pull 冲突时脚本照样一路
# 走到最后打印「🎉 发布完成」，而远端其实什么都没推上去。
function Assert-LastExit([string]$What) {
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "$What 失败 (ExitCode: $LASTEXITCODE)，已中止发版流程。" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "       Data Maskit 发布流水线 (Release Pipeline)   " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# 0. 优先使用 PowerShell 7 (pwsh)
$psExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }

# 1. 检查分支与 Git 环境
$currentBranch = (git branch --show-current)
Assert-LastExit "git branch --show-current（当前目录不是 Git 仓库？）"
$currentBranch = $currentBranch.Trim()
if (-not $currentBranch) {
    Write-Host "无法确定当前分支（可能处于 detached HEAD），已中止发版。" -ForegroundColor Red
    exit 1
}
if ($currentBranch -ne "master" -and $currentBranch -ne "main") {
    Write-Warning "当前分支为 [$currentBranch]，非 master/main。确定要在此分支发布吗？"
    if (-not $Yes) {
        $confirm = Read-Host "按 Y 继续，其他键退出"
        if ($confirm -notmatch '^[Yy]$') { exit 0 }
    }
}

# 2. 前置拉取：与远程对齐，杜绝推送冲突
Write-Host "`n[1/4] 正在拉取远程最新提交 (git pull origin $currentBranch)..." -ForegroundColor Cyan
git pull origin $currentBranch
Assert-LastExit "git pull origin $currentBranch（请先手动处理冲突或网络问题）"
Write-Host "远程分支已同步。" -ForegroundColor Green

# 2.5 模型就绪前置检查 (Model Preflight Check)
$nerDir = Join-Path $Root "engine\models\ner_mini_zh"
$nerFiles = @("model_quantized.onnx", "tokenizer.json", "config.json")
$nerMissing = $nerFiles | Where-Object { -not (Test-Path (Join-Path $nerDir $_)) }
if ($nerMissing.Count -eq 0) {
    $onnxSize = (Get-Item (Join-Path $nerDir "model_quantized.onnx")).Length
    if ($onnxSize -gt 50MB) {
        Write-Host "✓ NER 本地语义模型检查通过 ($([math]::Round($onnxSize/1MB, 1))MB)，将构建【全功能一体化发布包 (All-in-One)】" -ForegroundColor Green
    } else {
        Write-Warning "⚠️ engine\models\ner_mini_zh\model_quantized.onnx 体积过小 ($([math]::Round($onnxSize/1MB, 1))MB < 50MB)，文件可能损坏！"
        if (-not $Yes) {
            $confirm = Read-Host "模型可能损坏，是否仍要继续？[y/N]"
            if ($confirm -notmatch '^[Yy]$') { exit 1 }
        }
    }
} else {
    Write-Host ""
    Write-Warning "⚠️ 未检测到完整的 NER 本地语义模型（缺 $($nerMissing -join ', ')）！"
    Write-Host "v0.3.0+ 核心特性包含 NER 实体识别。缺少模型将导致本次发布包退化为【轻量规则包】。" -ForegroundColor Yellow
    if (-not $Yes) {
        $confirm = Read-Host "确定要继续以【轻量规则包（不含 NER 模型）】发版吗？[y/N]"
        if ($confirm -notmatch '^[Yy]$') {
            Write-Host "已取消发版。请将模型三件套放置于 engine\models\ner_mini_zh\ 后重试。" -ForegroundColor Yellow
            exit 0
        }
    }
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
# 正则必须放行 prerelease（X.Y.Z-beta.N），与 build.ps1 的 $verRe 同口径：
# 这里读不出值会直接中止发版（即使包已经打好了）。
$verLine = Select-String -Path $panelPath -Pattern "__version__ = '(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)'" | Select-Object -First 1
if (-not $verLine) { Write-Error "无法读取构建后的版本号"; exit 1 }
$targetVer = $verLine.Matches[0].Groups[1].Value
$tag = "v$targetVer"

Write-Host "`n[3/4] 构建成功！目标版本: $targetVer (Tag: $tag)" -ForegroundColor Green

$nsisPath = "src-tauri\target\release\bundle\nsis\Maskit_${targetVer}_x64-setup.exe"
# 注：prerelease 产物命名已实测（2026-09-22）：0.5.0-beta.1 的产物为
# bundle/nsis/Maskit_0.5.0-beta.1_x64-setup.exe，`-` 原样保留，并同时产出 .sig 更新签名
# （即 Tauri 打包器未对 `-` 做净化）。此处找不到文件只是跳过打印体积，不中止发版。
if (Test-Path $nsisPath) {
    $nsisSize = [math]::Round((Get-Item $nsisPath).Length / 1MB, 1)
    $pkgType = if ($nsisSize -gt 60) { "全功能一体包 (All-in-One)" } else { "轻量规则包" }
    Write-Host "安装包产物: $nsisPath ($nsisSize MB) [$pkgType]" -ForegroundColor Cyan
}

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
    Write-Host "请先按下面的步骤补好 CHANGELOG 该版本章节后重跑：" -ForegroundColor Yellow
    Write-Host "    1) 把开发期间累积的 `## [Unreleased]` 条目改名为 $changelogHeading - <日期>" -ForegroundColor Yellow
    Write-Host "    2) 或直接新建该章节并写入中英双语条目" -ForegroundColor Yellow
    Write-Error "CHANGELOG 章节缺失，已中止发版（未产生任何 Git 提交或 Tag）。"
    exit 1
}
Write-Host "CHANGELOG.md 已包含 $changelogHeading 章节。" -ForegroundColor Green

# 4. 检查是否有需要提交的改动
$status = (git status --porcelain)
Assert-LastExit "git status"
if (-not $status) {
    # 没有改动意味着版本号已在更早的一次运行里改过。此时**不能**静默收场：
    # 用户会以为发版成功，而 tag 与 Release 其实都不存在。
    Write-Host "工作区没有可提交的改动——版本号可能已在此前运行中改过。" -ForegroundColor Yellow
    Write-Host "本次不会产生新提交。若 $tag 尚未推送，确认后手动执行：" -ForegroundColor Yellow
    Write-Host "    git tag $tag; git push origin $tag" -ForegroundColor Yellow
    exit 0
}

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

# 安全暂存：更新已跟踪文件，补入合规的新增文档与脚本。
# `git add -u` 只暂存已跟踪文件的修改，新文件（引擎单源常量、门禁脚本、回归测试等）
# 必须显式补入，否则会在提交中被漏掉 —— 发版后 CI 或打包可能因此失败。
git add -u
Assert-LastExit "git add -u"
if (Test-Path "docs\architecture-en.png") { git add docs\architecture-en.png docs\architecture-zh.png; Assert-LastExit "git add 架构图" }
if (Test-Path "release.ps1") { git add release.ps1; Assert-LastExit "git add release.ps1" }
# 列出全部新文件：`git add -A` 会把构建产物/临时文件一并暂存，这里按路径精确添加。
# 改成**动态列举**：硬编码白名单会在发版前新增源文件时静默漏掉（0.6.0 前置里
# 新增的整批 tests/、scripts/ 与 engine/selfcheck.py 都不在旧列表里）。
# `--exclude-standard` 会排除 .gitignore 覆盖的构建产物与临时文件。
$newFiles = @(git ls-files --others --exclude-standard)
foreach ($f in $newFiles) {
  if (Test-Path $f) { git add -- $f; Assert-LastExit "git add $f" }
}

# 提交
#
# ⚠️ 必须先判断有没有暂存内容。当版本号**已被提前改成目标值**时（典型场景：先按
# CHANGELOG 定好 0.4.0 再发版），`build.ps1` 执行的是 `0.4.0 -> 0.4.0` 替换，
# 文件内容一字不变，`git add -u` 自然暂存不到任何东西。此时无条件 commit 会以
# “nothing to commit” 返回非零，被 Assert-LastExit 中止——而且是**在完整构建
# （前端 + PyInstaller + Tauri，约 10 分钟）跑完之后**才炸，白跑一次打包。
# “没有内容可提交”本身就是合法状态，跳过 commit 直接打 Tag 即可。
$staged = @(git diff --cached --name-only)
if ($staged.Count -gt 0) {
  $commitMsg = "chore(release): 发布 v$targetVer"
  if ($Note) { $commitMsg = $commitMsg + "`n`n" + $Note }
  git commit -m $commitMsg
  Assert-LastExit "git commit"
  Write-Host "已提交: $commitMsg" -ForegroundColor Green
} else {
  Write-Host "无文件改动需要提交（版本号已是 v$targetVer），跳过 commit，直接打 Tag。" -ForegroundColor Yellow
}

# 推送主分支
Write-Host "正在推送分支到 origin $currentBranch..." -ForegroundColor Cyan
git push origin $currentBranch
Assert-LastExit "git push origin $currentBranch"
Write-Host "分支推送完成。" -ForegroundColor Green

# 创建并推送 tag。同名 tag 已存在时 git tag 会失败 —— 必须在这里中止，
# 绝不能让「tag 没打上」被静默略过、脚本继续打印发布完成。
Write-Host "正在打 Tag 并推送: $tag..." -ForegroundColor Cyan
git tag $tag
Assert-LastExit "git tag $tag（同名 Tag 可能已存在）"
git push origin $tag
Assert-LastExit "git push origin $tag"
Write-Host "Tag $tag 推送完成！" -ForegroundColor Green

Write-Host "`n=================================================" -ForegroundColor Green
Write-Host "🎉 发布完成！v$targetVer 已成功推送！" -ForegroundColor Green
Write-Host "GitHub Release Actions 正在云端自动构建多架构 Docker 镜像与发布页面。" -ForegroundColor Green
Write-Host "查看进度: https://github.com/xiaYuTian11/maskit/actions" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Green
