# Data Maskit 一键打包（Tauri 版）：版本自增 -> 单测 -> 前端构建 -> 引擎 sidecar -> Tauri bundle -> 部署验证
# 用法：.\build.ps1
# 说明：版本唯一来源是 panel.py 的 __version__；每次打包 patch+1（1.5.65 -> 1.5.66）。
#       前端/引擎/壳三产物统一由本脚本编排，禁止手动 pyinstaller / cargo tauri build。
#
# 打包流程红线（用户反复强调）：
#   先构建完，再杀进程替换——不要先杀进程再构建。
#   前端构建 + 引擎打包 + tauri build 都不碰运行中进程；
#   只有 tauri build 覆盖 llm-shield.exe 失败（文件锁）时才杀进程重试；
#   tauri build 成功后，杀进程 + 替换 resources + 启动验证（几秒内完成）。
#
# 升级流程红线（2026-08-16 起，用户已开始稳定使用）：
#   用 -ReleaseOnly 打**要发给用户**的包。该模式下脚本绝不碰用户已安装的实例：
#   只清理构建树里残留的进程（按 ExecutablePath 在仓库内判定），不启动、不验证、
#   不更新快捷方式与自启。用户在软件内点更新升级，不由脚本替他装。
#   不带该开关 = 开发机自测模式（会杀进程并拉起构建产物验证），别对着在用的机器跑。
param([switch]$ReleaseOnly, [string]$Version = "", [switch]$Unsigned)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

# 只终止本项目进程（Maskit.exe 壳 / MaskitEngine.exe 引擎 / 旧版同名 / 其 mitmdump 子进程树）
function Stop-ShieldProcesses {
    # -ReleaseOnly：只清理**构建树里**残留的实例（ExecutablePath 在仓库内），
    # 用户安装目录（如 C:\Program Files\Maskit）的实例一律不碰——他正在用它
    # 代理全部 LLM 流量，杀掉就是中断他手上的工作。
    if ($ReleaseOnly) {
        $repo = $Root.TrimEnd('\')
        $mine = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                  Where-Object {
                      ($_.Name -like "*Maskit*" -or $_.Name -like "*LLMShield*" -or $_.Name -eq "llm-shield.exe") -and
                      $_.ExecutablePath -and $_.ExecutablePath.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)
                  })
        foreach ($p in $mine) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
        if ($mine.Count -gt 0) { Start-Sleep 3 }
        Write-Host "[ReleaseOnly] 仅清理构建树实例 $($mine.Count) 个，未触碰已安装实例" -ForegroundColor DarkGray
        return
    }
    foreach ($name in @("Maskit", "MaskitEngine", "LLMShield", "llm-shield", "LLMShieldEngine")) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    # 取命令行一起判：孤儿 mitmdump 认不出来会导致引擎目录被占、Move-Item 失败
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
             Select-Object ProcessId, ParentProcessId, Name, CommandLine)
    $killPids = New-Object System.Collections.Generic.HashSet[int]
    foreach ($p in $all) {
        if ($p.Name -like "*Maskit*" -or $p.Name -like "*LLMShield*" -or $p.Name -eq "llm-shield.exe") { [void]$killPids.Add([int]$p.ProcessId) }
    }
    # 孤儿 mitmdump：引擎被杀后它的 mitmdump 子进程会挂到 pid 1 之外的已消失父进程上，
    # 靠父进程树永远收不到，却仍持有 resources\engine\_internal 的句柄 →
    # 第 7 步 Move-Item 报「being used by another process」（2026-08-15 实测）。
    # 按命令行里是否加载了本仓库的 transparent.py 判定，不会误杀别的项目的 mitmproxy。
    $marker = (Join-Path $Root "").TrimEnd('\')
    foreach ($p in $all) {
        $cl = $p.CommandLine
        if ($cl -and $cl -like "*transparent.py*" -and $cl -like "*$marker*") {
            [void]$killPids.Add([int]$p.ProcessId)
        }
    }
    # 递归收集子进程
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($p in $all) {
            if ($killPids.Contains([int]$p.ParentProcessId) -and -not $killPids.Contains([int]$p.ProcessId)) {
                [void]$killPids.Add([int]$p.ProcessId)
                $changed = $true
            }
        }
    }
    # 不能用 $pid：它是 PowerShell 只读自动变量（当前进程 ID），赋值直接抛
    # 「Cannot overwrite variable PID because it is read-only or constant」。
    # 此前 killPids 恒为空所以没暴露，加了孤儿 mitmdump 识别后必触发。
    foreach ($procId in $killPids) {
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
    # 等文件锁释放（Windows 句柄延迟）
    Start-Sleep 3
}

# 目录替换前的最后一道闸：句柄释放有延迟，杀完立刻 Move 仍可能失败。
# 重试 + 每轮再杀一次，比一次性 Sleep 更长更稳（不盲目拉长每次打包的耗时）。
function Move-WithRetry {
    param([string]$From, [string]$To, [int]$Tries = 5)
    for ($i = 1; $i -le $Tries; $i++) {
        try {
            Move-Item $From $To -ErrorAction Stop
            return $true
        } catch {
            if ($i -eq $Tries) { return $false }
            Write-Host "  目录被占用，重试 $i/$Tries..." -ForegroundColor DarkGray
            Stop-ShieldProcesses
        }
    }
    return $false
}

# 1. 读取当前版本并计算新版本号
$panelPath = "engine\panel.py"
$confPath = "src-tauri\tauri.conf.json"
$cargoPath = "src-tauri\Cargo.toml"
$cargoLockPath = "src-tauri\Cargo.lock"
$pkgJsonPath = "frontend\package.json"
$pkgLockPath = "frontend\package-lock.json"
$verLine = Select-String -Path $panelPath -Pattern "__version__ = '(\d+)\.(\d+)\.(\d+)'" | Select-Object -First 1
if (-not $verLine) { Write-Error "$panelPath 里找不到 __version__"; exit 1 }
$m = [regex]::Match($verLine.Line, "__version__ = '(\d+)\.(\d+)\.(\d+)'")
$major, $minor, $patch = [int]$m.Groups[1].Value, [int]$m.Groups[2].Value, [int]$m.Groups[3].Value
$origVer = "$major.$minor.$patch"

# 在任何写入前保存版本文件的原始字节。失败回滚不能依赖正则猜测旧值：
# package-lock 里同一个版本字符串可能出现数百次，误替换或漏恢复都会让工作区
# 处在「四处看似一致、锁文件实际已脏」的状态。
$versionBackups = @{}
foreach ($versionPath in @($panelPath, $confPath, $cargoPath, $cargoLockPath, $pkgJsonPath, $pkgLockPath)) {
    $resolvedVersionPath = (Resolve-Path $versionPath -ErrorAction Stop).Path
    $versionBackups[$resolvedVersionPath] = [IO.File]::ReadAllBytes($resolvedVersionPath)
}

if ($Version -and $Version.StartsWith("v", [StringComparison]::OrdinalIgnoreCase)) {
    $Version = $Version.Substring(1)
}
if ($Version) {
    if ($Version -notmatch '^\d+\.\d+\.\d+$') {
        Write-Error "版本号必须是 X.Y.Z（收到: $Version）"; exit 1
    }
    $newVer = $Version
    Write-Host "指定版本构建: $origVer -> $newVer" -ForegroundColor Cyan
} else {
    $newVer = "$major.$minor.$($patch + 1)"
    Write-Host "版本升级: $origVer -> $newVer" -ForegroundColor Cyan
}

# 同一版本 tag 已存在时禁止覆盖构建，避免生成无法区分的更新包。
$existingTag = @(git tag --list "v$newVer")
if ($existingTag.Count -gt 0) {
    Write-Error "Git tag v$newVer 已存在；请使用新的版本号，不覆盖已有发布"; exit 1
}

# 2. 写回 panel.py（唯一来源）+ 同步 tauri.conf.json / Cargo.toml 的 version
$panelSrc = (Get-Content $panelPath -Raw -Encoding UTF8) -replace "__version__ = '$origVer'", "__version__ = '$newVer'"
[IO.File]::WriteAllText((Resolve-Path $panelPath), $panelSrc, (New-Object Text.UTF8Encoding $false))
$confSrc = (Get-Content $confPath -Raw -Encoding UTF8) -replace '"version": "\d+\.\d+\.\d+"', "`"version`": `"$newVer`""
[IO.File]::WriteAllText((Resolve-Path $confPath), $confSrc, (New-Object Text.UTF8Encoding $false))
# 只替第一处 version（[package] 段）：依赖项的 version 不能动，所以限定行首锚点。
$cargoSrc = (Get-Content $cargoPath -Raw -Encoding UTF8) -replace '(?m)^version = "\d+\.\d+\.\d+"', "version = `"$newVer`""
[IO.File]::WriteAllText((Resolve-Path $cargoPath), $cargoSrc, (New-Object Text.UTF8Encoding $false))
# Cargo.lock 的根 package 版本不会在每次早期失败前自动更新；显式同步，确保
# 版本检查和 release tag 在未运行 cargo build 的情况下也保持一致。
$cargoLockSrc = Get-Content $cargoLockPath -Raw -Encoding UTF8
$cargoLockSrc = [regex]::Replace(
    $cargoLockSrc,
    '(?ms)(\[\[package\]\]\s*\r?\nname = "maskit"\s*\r?\nversion = )"\d+\.\d+\.\d+"',
    "`${1}`"$newVer`"",
    1
)
[IO.File]::WriteAllText((Resolve-Path $cargoLockPath), $cargoLockSrc, (New-Object Text.UTF8Encoding $false))
# frontend/package.json + package-lock.json 顶层 version（关于页/npm 元数据；只替顶层第一处）
foreach ($pkgPath in @($pkgJsonPath, $pkgLockPath)) {
    $pkgSrc = Get-Content $pkgPath -Raw -Encoding UTF8
    $pkgSrc = [regex]::new('"version": "\d+\.\d+\.\d+"').Replace($pkgSrc, "`"version`": `"$newVer`"", 2)
    [IO.File]::WriteAllText((Resolve-Path $pkgPath), $pkgSrc, (New-Object Text.UTF8Encoding $false))
}
$check = Select-String -Path $panelPath -Pattern "__version__ = '$newVer'"
if (-not $check) { Write-Error "版本写回失败"; exit 1 }

# package-lock 必须同时更新根对象和 packages[""]，否则 npm ci 会继续使用旧元数据。
try {
    # -AsHashtable 保留 package-lock `packages[""]` 这个合法但特殊的空键，
    # 避免 PowerShell 把它当成无效属性访问。
    $pkgObj = Get-Content $pkgJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable
    $lockObj = Get-Content $pkgLockPath -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable
    $rootLock = $lockObj["packages"][""]
    if ($pkgObj["version"] -ne $newVer -or $lockObj["version"] -ne $newVer -or
        $null -eq $rootLock -or $rootLock["version"] -ne $newVer -or
        $pkgObj["name"] -ne $lockObj["name"] -or $pkgObj["name"] -ne $rootLock["name"]) {
        throw "package.json / package-lock.json 根版本或名称不一致"
    }
} catch {
    Write-Error "package-lock 一致性校验失败: $($_.Exception.Message)"; exit 1
}

# 2b. 三方版本硬校验：任何一处对不上立即失败，绝不打出版本分叉的包。
$vPanel = ([regex]::Match((Get-Content $panelPath -Raw -Encoding UTF8), "__version__ = '(\d+\.\d+\.\d+)'")).Groups[1].Value
$vConf  = ([regex]::Match((Get-Content $confPath -Raw -Encoding UTF8), '"version": "(\d+\.\d+\.\d+)"')).Groups[1].Value
$vCargo = ([regex]::Match((Get-Content $cargoPath -Raw -Encoding UTF8), '(?m)^version = "(\d+\.\d+\.\d+)"')).Groups[1].Value
$vPkg   = ([regex]::Match((Get-Content "frontend\package.json" -Raw -Encoding UTF8), '"version": "(\d+\.\d+\.\d+)"')).Groups[1].Value
$vCargoLock = ([regex]::Match((Get-Content "src-tauri\Cargo.lock" -Raw -Encoding UTF8), '(?ms)^\[\[package\]\]\s*\nname = "maskit"\s*\nversion = "(\d+\.\d+\.\d+)"')).Groups[1].Value
if (($vPanel -ne $newVer) -or ($vConf -ne $newVer) -or ($vCargo -ne $newVer) -or ($vPkg -ne $newVer) -or ($vCargoLock -ne $newVer)) {
    Write-Host "版本不一致：panel=$vPanel tauri.conf=$vConf Cargo=$vCargo Cargo.lock=$vCargoLock package.json=$vPkg 期望=$newVer" -ForegroundColor Red
    Write-Error "版本分叉，打包中止"
    exit 1
}
Write-Host "版本一致性校验通过: panel/tauri.conf/Cargo/package.json 均为 $newVer" -ForegroundColor Green

function Restore-Version {
    foreach ($entry in $versionBackups.GetEnumerator()) {
        [IO.File]::WriteAllBytes($entry.Key, [byte[]]$entry.Value)
    }
    Write-Host "打包失败，已恢复所有版本文件（含 package-lock）" -ForegroundColor Yellow
}

# 3. Python 语法 + 单测（不碰运行中进程）
# 解释器必须显式指定：裸 `python` 会解析到系统 PATH 上的任意版本（实测 3.14，
# 无 flask/mitmproxy）→ 测试模块 import 失败被算成 2 个 error、只跑了 54 项就
# FAILED，打包在第 3 步永远过不去。这里优先用带依赖的测试虚拟环境。
Write-Host "Python 语法检查 + 单测..." -ForegroundColor Cyan
# 候选顺序：$env:MASKIT_PYTHON（显式指定）→ 仓库内 .venv-test → py 启动器的 3.13
$pyTest = $null
$pyCands = @()
if ($env:MASKIT_PYTHON) { $pyCands += $env:MASKIT_PYTHON }
$pyCands += ".venv-test\Scripts\python.exe"
$py313FromLauncher = try { (& py -3.13 -c "import sys; print(sys.executable)" 2>$null) } catch { $null }
if ($py313FromLauncher) { $pyCands += $py313FromLauncher.Trim() }
foreach ($cand in $pyCands) {
    $full = Join-Path $Root $cand
    if (-not (Test-Path $full)) { $full = $cand }
    if (Test-Path $full) {
        & $full -c "import flask, mitmproxy" 2>$null
        if ($LASTEXITCODE -eq 0) { $pyTest = $full; break }
    }
}
if (-not $pyTest) {
    Restore-Version
    Write-Error "找不到装齐依赖的 Python 3.13（需 flask + mitmproxy + pyinstaller）。设置 `$env:MASKIT_PYTHON 指向解释器，或 py -3.13 -m venv .venv-test 后 pip install -r requirements.txt -r requirements-dev.txt"
    exit 1
}
Write-Host "测试解释器: $pyTest" -ForegroundColor DarkGray
$engineFiles = Get-ChildItem -Path "engine\*.py" | Select-Object -ExpandProperty FullName
& $pyTest -m py_compile $engineFiles
if ($LASTEXITCODE -ne 0) { Restore-Version; Write-Error "py_compile 失败"; exit 1 }
$oldEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"   # stderr 日志行不当错误中断（NativeCommandError）
$testOut = & $pyTest -m unittest discover -s tests 2>&1
$testExit = $LASTEXITCODE
$ErrorActionPreference = $oldEAP
if ($testExit -ne 0) {
    Write-Host $testOut -ForegroundColor Red
    Restore-Version
    Write-Error "单测失败（见上完整输出），终止打包"; exit 1
}
$testOut | Select-Object -Last 2 | Write-Host

# 4. 前端构建（类型检查 + vite build，不碰运行中进程）
# EAP=Continue 的理由与上面单测那段相同，而且这里是**实际踩过的**：
# vite 的「chunk 超过 500 kB」警告走 stderr，$ErrorActionPreference="Stop" 下
# PowerShell 把原生命令的 stderr 当成终止性错误抛 NativeCommandError，
# 整个脚本在这里直接死——连 Restore-Version 都跑不到，版本号停在半路
# （2026-08-16 发布 0.1.3 时实测）。成败一律只看 $LASTEXITCODE。
Write-Host "前端构建..." -ForegroundColor Cyan
Push-Location frontend
$oldEAP3 = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    npm run build 2>&1 | Write-Host
    $feExit = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $oldEAP3
    Pop-Location
}
if ($feExit -ne 0) { Restore-Version; Write-Error "前端构建失败（exit $feExit）"; exit 1 }

# 5. 引擎 sidecar（PyInstaller，Python 3.13 打包环境，不碰运行中进程）
Write-Host "引擎 sidecar 打包（3.13）..." -ForegroundColor Cyan
# 打包解释器与测试解释器同一个（必须 3.13，与引擎依赖锁定版本一致）
$py313 = $pyTest
& $py313 -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) { Restore-Version; Write-Error "打包解释器缺少 PyInstaller: $py313（pip install -r requirements-dev.txt）"; exit 1 }
# 打包前清掉 engine/ 下的运行时产物：事件库/配置/token 是开发者本机数据，绝不能随 sidecar 分发
Get-ChildItem -Path "engine" -Include "*.sqlite3*", "*.jsonl", "config.json", "config.json.bak-*", "proxy_token", "*.log", "shield.pid", "shield-env-backup.json", "model_prices_cache.json", "diagnostics-*.json" -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force
if (Test-Path "dist_engine") { Remove-Item -Recurse -Force "dist_engine" }
if (Test-Path "build_engine") { Remove-Item -Recurse -Force "build_engine" }
# PyInstaller 的进度与告警同样走 stderr（同上）
$oldEAP4 = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $py313 -m PyInstaller engine\maskit-engine.spec --noconfirm --distpath dist_engine --workpath build_engine 2>&1 | Write-Host
$pyiExit = $LASTEXITCODE
$ErrorActionPreference = $oldEAP4
if ($pyiExit -ne 0) { Restore-Version; Write-Error "引擎打包失败（exit $pyiExit）"; exit 1 }
if (-not (Test-Path "dist_engine\MaskitEngine\MaskitEngine.exe")) {
    Restore-Version; Write-Error "引擎产物缺失"; exit 1
}

# 5.5 把新引擎同步到 Tauri 打包源目录（必须在 tauri build 之前！）
# tauri.conf.json 的 bundle.resources 指向 src-tauri/resources/engine/，
# tauri build 会把这个目录原样打进 NSIS 安装包。此前这一步放在第 7 步（打包之后），
# 结果安装包里装的一直是上一次构建的旧引擎——本机跑 target\release 是新的，
# 装出去给别人的是旧的，实测 08-14 20:44 的安装包里是 00:09 的引擎。
# 复制到源目录不需要杀进程：运行中的应用占用的是 target\release\resources\engine，
# 不是这里，所以不违反「先构建完再杀进程替换」红线。
Write-Host "同步引擎到打包源目录..." -ForegroundColor Cyan
$srcEngine = "src-tauri\resources\engine"
if (Test-Path $srcEngine) { Remove-Item -Recurse -Force $srcEngine }
New-Item -ItemType Directory -Force -Path $srcEngine | Out-Null
Copy-Item -Recurse "dist_engine\MaskitEngine\_internal" "$srcEngine\_internal"
Copy-Item "dist_engine\MaskitEngine\MaskitEngine.exe" "$srcEngine\MaskitEngine.exe"
$srcCount = (Get-ChildItem "$srcEngine\_internal" -Recurse -File | Measure-Object).Count
if (-not (Test-Path "$srcEngine\MaskitEngine.exe") -or $srcCount -lt 100) {
    Restore-Version; Write-Error "打包源目录引擎同步失败（$srcCount 文件）"; exit 1
}
Write-Host "打包源目录引擎已同步: $srcCount 文件" -ForegroundColor Yellow

# 6. Tauri bundle（尝试构建，exe 文件锁时才杀进程——打包红线：构建不碰运行进程）
Write-Host "Tauri 打包（先尝试不杀进程）..." -ForegroundColor Cyan
# NSIS / WebView2 引导工具从 GitHub 下载；网络不通时可设 $env:MASKIT_GH_MIRROR（如 https://gh-proxy.com/），默认直连
if ($env:MASKIT_GH_MIRROR) { $env:TAURI_BUNDLER_TOOLS_GITHUB_MIRROR = $env:MASKIT_GH_MIRROR }
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
# 更新包签名：私钥在仓库外（~/.tauri/maskit-updater.key，永不入库），公钥在 tauri.conf.json。
# 正式 signed 构建必须提供私钥；显式 -Unsigned 构建会临时关闭 updater artifacts，
# 产物只能作为手工安装包发布，绝不能被标记为可自动更新。
$signKey = Join-Path $env:USERPROFILE ".tauri\maskit-updater.key"
# CI 可直接注入 TAURI_SIGNING_PRIVATE_KEY；本机才回退到仓库外的 key 文件。
# 私钥只保存在当前 PowerShell 变量中，并仅通过 ProcessStartInfo 传给 tauri 子进程，
# 不写入项目、不落盘到日志，也不污染父进程环境。
$signKeyContent = $env:TAURI_SIGNING_PRIVATE_KEY
$signKeyPassword = $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD
if ([string]::IsNullOrWhiteSpace($signKeyContent)) {
    if (-not (Test-Path $signKey) -and -not $Unsigned) {
        Restore-Version
        Write-Error "缺少更新签名私钥: $signKey`n生成: frontend\node_modules\.bin\tauri.cmd signer generate -w `"$signKey`" -p `"`""
        exit 1
    }
    if (Test-Path $signKey) {
        $signKeyContent = (Get-Content $signKey -Raw -Encoding UTF8).Trim()
    }
}
if ([string]::IsNullOrWhiteSpace($signKeyContent) -and -not $Unsigned) {
    Restore-Version
    Write-Error "更新签名私钥为空"; exit 1
}
$unsignedBuild = [bool]$Unsigned -or [string]::IsNullOrWhiteSpace($signKeyContent)

# unsigned 模式只在当前 tauri build 生命周期内关闭更新产物，成功/失败都会恢复为 true，
# 避免本机下一次正式打包悄悄变成无签名包。
$updaterOverrideApplied = $false
if ($unsignedBuild) {
    $confText = Get-Content $confPath -Raw -Encoding UTF8
    if ($confText -notmatch '"createUpdaterArtifacts"\s*:\s*true') {
        Restore-Version
        Write-Error "无法在 tauri.conf.json 找到 createUpdaterArtifacts=true"; exit 1
    }
    $confText = $confText -replace '"createUpdaterArtifacts"\s*:\s*true', '"createUpdaterArtifacts": false'
    [IO.File]::WriteAllText((Resolve-Path $confPath), $confText, (New-Object Text.UTF8Encoding $false))
    $updaterOverrideApplied = $true
    Write-Host "未提供更新签名私钥：构建 UNSIGNED 安装包（不生成 updater .sig/latest.json）" -ForegroundColor Yellow
}

function Restore-UpdaterConfig {
    if (-not $script:updaterOverrideApplied) { return }
    try {
        $current = Get-Content $confPath -Raw -Encoding UTF8
        $current = $current -replace '"createUpdaterArtifacts"\s*:\s*false', '"createUpdaterArtifacts": true'
        [IO.File]::WriteAllText((Resolve-Path $confPath), $current, (New-Object Text.UTF8Encoding $false))
    } finally {
        $script:updaterOverrideApplied = $false
    }
}

function Start-WithoutSigningEnvironment {
    param([Parameter(Mandatory = $true)][string]$Path)
    # 构建签名私钥即使来自调用方环境，也不应被本机启动的产品进程继承。
    $oldKey = [Environment]::GetEnvironmentVariable("TAURI_SIGNING_PRIVATE_KEY", "Process")
    $oldPassword = [Environment]::GetEnvironmentVariable("TAURI_SIGNING_PRIVATE_KEY_PASSWORD", "Process")
    try {
        [Environment]::SetEnvironmentVariable("TAURI_SIGNING_PRIVATE_KEY", $null, "Process")
        [Environment]::SetEnvironmentVariable("TAURI_SIGNING_PRIVATE_KEY_PASSWORD", $null, "Process")
        return Start-Process -FilePath $Path -PassThru
    } finally {
        [Environment]::SetEnvironmentVariable("TAURI_SIGNING_PRIVATE_KEY", $oldKey, "Process")
        [Environment]::SetEnvironmentVariable("TAURI_SIGNING_PRIVATE_KEY_PASSWORD", $oldPassword, "Process")
    }
}

# tauri build 必须用 ProcessStartInfo 起，不能直接 `& $tauriCli build`。
#
# 更新签名私钥是**空口令**，而 PowerShell 和 cmd 都无法设置「空值」环境变量：
# `$env:X = ""` 等于**删除**该变量（实测 `$env:X=""; cmd /c "set X"` → not defined），
# cmd 的 `set X=` 同理。变量一缺，tauri 就打印
#   Info Decrypting updater signing key, expect a prompt for password
# 然后转去**读控制台设备**要口令（rpassword，不是读 stdin —— 所以
# `echo.| tauri build` 这种管道喂空行也没用），非交互运行时永久阻塞，
# 而且此后再无任何输出，极难归因（2026-08-16 连挂四次，每次都停在同一行）。
#
# .NET 的 ProcessStartInfo.EnvironmentVariables 允许空值项，实测子进程能收到
# `TAURI_SIGNING_PRIVATE_KEY_PASSWORD=`，于是不再走 prompt。
# AGENTS.md 里曾写「$env:X = "" 仍会把空串传给子进程」，那条结论是错的，已更正。
function Invoke-TauriBuild {
    param([string]$Cli, [string]$WorkDir, [string]$KeyContent, [string]$KeyPassword)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "cmd.exe"
    $psi.Arguments = '/c "' + $Cli + '" build'
    $psi.WorkingDirectory = $WorkDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    if ([string]::IsNullOrWhiteSpace($KeyContent)) {
        [void]$psi.EnvironmentVariables.Remove("TAURI_SIGNING_PRIVATE_KEY")
    } else {
        $psi.EnvironmentVariables["TAURI_SIGNING_PRIVATE_KEY"] = $KeyContent
    }
    # 空口令也要显式传给子进程，避免 Tauri 进入交互式 rpassword 提示；
    # 有口令时只从环境变量读取，绝不把口令写入项目或日志。
    $psi.EnvironmentVariables["TAURI_SIGNING_PRIVATE_KEY_PASSWORD"] = if ($null -eq $KeyPassword) { "" } else { $KeyPassword }
    $proc = [System.Diagnostics.Process]::Start($psi)
    # 两个流都要异步读：只读一个的话，另一个管道写满就死锁（tauri 输出量很大）
    $so = $proc.StandardOutput.ReadToEndAsync()
    $se = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    $text = $so.Result + "`n" + $se.Result
    Write-Host $text
    return @{ Exit = $proc.ExitCode; Output = $text }
}
try {
    Push-Location $Root
    try {
        # 必须在仓库根目录跑：tauri CLI 靠「当前目录或其子目录里有 tauri.conf.json」
        # 定位工程。此前 Push-Location frontend 后再跑，src-tauri 是 frontend 的兄弟
        # 目录而非子目录 → panic「Couldn't recognize the current folder as a Tauri project」。
        # CLI 本体装在 frontend/node_modules，所以用显式路径调用而不是 npx。
        $tauriCli = Join-Path $Root "frontend\node_modules\.bin\tauri.cmd"
        if (-not (Test-Path $tauriCli)) {
            Restore-Version
            Write-Error "找不到 tauri CLI: $tauriCli（先在 frontend 下 npm install）"; exit 1
        }
        $oldEAP2 = $ErrorActionPreference
        $ErrorActionPreference = "Continue"   # tauri CLI 的 Info 日志走 stderr，Stop 下会误判失败
        $buildKey = if ($unsignedBuild) { "" } else { $signKeyContent }
        $r1 = Invoke-TauriBuild -Cli $tauriCli -WorkDir $Root -KeyContent $buildKey -KeyPassword $signKeyPassword
        $tauriExit = $r1.Exit
        $tauriOut = $r1.Output
        $ErrorActionPreference = $oldEAP2
        if ($tauriExit -ne 0) {
            # 判断是否 exe 文件锁。匹配串必须覆盖中文系统的报错：实测 Windows 中文版
            # 报的是「另一个程序正在使用此文件，进程无法访问」(os error 32)，
            # 原来只匹配英文 failed to remove / Access denied，中文机器上直接被当成
            # 「非文件锁原因」而放弃重试，整次打包白跑。
            # 触发场景很常见：上一轮构建产物被直接运行（进程镜像就在 target\release 下），
            # 于是新一轮 tauri build 覆盖 resources\engine\MaskitEngine.exe 时必然撞锁。
            if ($tauriOut -match "failed to remove.*(Maskit|llm-shield)\.exe|拒绝访问|Access denied|os error 32|另一个程序正在使用此文件|being used by another process") {
                Write-Host "exe 文件被占用，杀进程后重试 tauri build..." -ForegroundColor Yellow
                Stop-ShieldProcesses
                $oldEAPr = $ErrorActionPreference
                $ErrorActionPreference = "Continue"
                $r2 = Invoke-TauriBuild -Cli $tauriCli -WorkDir $Root -KeyContent $buildKey -KeyPassword $signKeyPassword
                $tauriExit2 = $r2.Exit
                $ErrorActionPreference = $oldEAPr
                if ($tauriExit2 -ne 0) { Restore-Version; Write-Error "Tauri 打包失败（重试后仍失败）"; exit 1 }
            } else {
                Restore-Version; Write-Error "Tauri 打包失败（非文件锁原因）"; exit 1
            }
        }
    } finally { Pop-Location }
    Write-Host "Tauri 打包完成" -ForegroundColor Green
} finally {
    Restore-UpdaterConfig
    # 无论 tauri 成功、失败还是中途 exit，尽快丢弃内存中的私钥副本。
    $signKeyContent = $null
    $signKeyPassword = $null
    $buildKey = $null
    Remove-Variable -Name signKeyContent -ErrorAction SilentlyContinue
    Remove-Variable -Name signKeyPassword -ErrorAction SilentlyContinue
    Remove-Variable -Name buildKey -ErrorAction SilentlyContinue
}

# unsigned 覆盖只应存在于 tauri build 生命周期内；后续资源替换/验证失败时
# 也不能把 createUpdaterArtifacts=false 留在工作区。
Restore-UpdaterConfig

# 7. 杀进程 + 替换引擎资源（构建已全部完成，现在几秒内完成替换）
Write-Host "停旧进程，更新引擎资源..." -ForegroundColor Cyan
Stop-ShieldProcesses
$relEngine = "src-tauri\target\release\resources\engine"
# 覆盖前先把旧引擎挪走而不是直接删：验证失败时要能原样放回去（见第 8 步回滚）
$engineBackup = "src-tauri\target\release\resources\engine.prev"
if (Test-Path $engineBackup) { Remove-Item -Recurse -Force $engineBackup }
if (Test-Path $relEngine) {
    if (-not (Move-WithRetry -From $relEngine -To $engineBackup)) {
        Restore-Version
        Write-Error "引擎目录被占用，重试后仍无法挪走: $relEngine（残留 mitmdump/引擎进程未清干净）"
        exit 1
    }
}
Copy-Item -Recurse "dist_engine\MaskitEngine\_internal" "$relEngine\_internal"
Copy-Item "dist_engine\MaskitEngine\MaskitEngine.exe" "$relEngine\MaskitEngine.exe"
if (-not (Test-Path "$relEngine\MaskitEngine.exe")) {
    Restore-Version; Write-Error "引擎资源复制失败"; exit 1
}
$engineCount = (Get-ChildItem "$relEngine\_internal" -Recurse -File | Measure-Object).Count
Write-Host "引擎资源完整覆盖: $engineCount 文件" -ForegroundColor Yellow
if ($engineCount -lt 100) { Restore-Version; Write-Error "引擎资源不完整（$engineCount 文件），终止"; exit 1 }

# 8. 启动验证：exe 起来 -> 引擎自动拉起 -> 端口监听 -> token API
#
# -ReleaseOnly 到此为止。这一步会拉起构建产物、抢 5801 与 187xx 端口、
# 读写 %APPDATA%\Maskit——在用户正在使用的机器上跑就是把他的代理顶掉。
# 发布包的正确验证方式是在隔离的干净机器/虚拟机上安装并走一遍启停。
if ($ReleaseOnly) {
    $bundle = "src-tauri\target\release\bundle\nsis\Maskit_${newVer}_x64-setup.exe"
    if (-not (Test-Path $bundle)) { Restore-Version; Write-Error "安装包未生成: $bundle"; exit 1 }
    $sig = "$bundle.sig"
    if (-not $unsignedBuild -and -not (Test-Path $sig)) {
        Restore-Version; Write-Error "更新签名未生成: $sig（signed 包不能缺少 updater 签名）"; exit 1
    }
    if ($unsignedBuild -and (Test-Path $sig)) {
        Restore-Version; Write-Error "unsigned 构建意外生成了 updater 签名: $sig"; exit 1
    }
    $modeLabel = if ($unsignedBuild) { "UNSIGNED（仅手工安装，无自动更新）" } else { "SIGNED" }
    Write-Host "`n完成: 数据面具 Maskit v$newVer [$modeLabel] 已构建（未安装、未启动、未触碰运行中的实例）" -ForegroundColor Cyan
    Write-Host "安装包: $bundle" -ForegroundColor Cyan

    # 自动组装 latest.json 更新元数据
    $latestJsonPath = "src-tauri\target\release\bundle\nsis\latest.json"
    if (-not $unsignedBuild -and (Test-Path $sig)) {
        $sigContent = (Get-Content $sig -Raw -Encoding UTF8).Trim()
        $pubDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $latestObj = @{
            version = "v$newVer"
            notes = "Data Maskit v$newVer 发布更新。"
            pub_date = $pubDate
            platforms = @{
                "windows-x86_64" = @{
                    signature = $sigContent
                    url = "https://github.com/xiaYuTian11/maskit/releases/download/v$newVer/Maskit_${newVer}_x64-setup.exe"
                }
            }
        }
        $latestJsonStr = $latestObj | ConvertTo-Json -Depth 5
        [IO.File]::WriteAllText((Join-Path (Split-Path -Parent $bundle) "latest.json"), $latestJsonStr, (New-Object Text.UTF8Encoding $false))
        Write-Host "已自动组装更新元数据: $latestJsonPath" -ForegroundColor Green
    }

    Write-Host "下一步: git tag v$newVer && git push --tags（CI 自动编译多架构 Docker 镜像并建 Release）→ 发布" -ForegroundColor Yellow
    exit 0
}

Write-Host "启动验证 v$newVer..." -ForegroundColor Cyan
$verifyOk = $true
$verifyErr = ""
$exe = "src-tauri\target\release\Maskit.exe"
$p = Start-Process -FilePath (Join-Path $Root $exe) -PassThru
Start-Sleep 20
try {
    $tokPath = "$env:APPDATA\Maskit\proxy_token"
    $tok = (Get-Content $tokPath -Raw).Trim()
    $st = Invoke-RestMethod "http://127.0.0.1:5801/api/status" -Headers @{ "X-Shield-Token" = $tok }
    Write-Host "引擎版本: $($st.version)  代理运行: $($st.proxy_running)" -ForegroundColor Green
    $upstreamPorts = @($st.upstreams | ForEach-Object { $_.port })
    $listening = @((Get-NetTCPConnection -LocalPort $upstreamPorts -State Listen -ErrorAction SilentlyContinue).LocalPort | Sort-Object -Unique)
    $missing = @($upstreamPorts | Where-Object { $_ -notin $listening })
    Write-Host "端口监听: $($listening.Count)/$($upstreamPorts.Count)" -ForegroundColor Green
    if ($missing.Count -gt 0) { $verifyOk = $false; Write-Host "未监听端口: $($missing -join ', ')" -ForegroundColor Red }
    if (-not $st.proxy_running) { $verifyOk = $false; Write-Host "代理未运行" -ForegroundColor Red }
} catch {
    $verifyOk = $false
    $verifyErr = $_
}

if (-not $verifyOk) {
    Write-Host "启动验证失败: $verifyErr" -ForegroundColor Red
    Stop-ShieldProcesses
    Restore-Version
    # 回滚到上一个可用版本：此前只杀新进程 + 回滚版本号，旧引擎资源已经被第 7 步
    # 覆盖掉、旧实例也被杀了，用户从「有一个能跑的」变成「什么都没有」（2026-08-14 实测）。
    # 这里把第 7 步备份的旧 resources 放回去，并重新拉起，保证失败不致停摆。
    if (Test-Path $engineBackup) {
        Write-Host "回滚引擎资源到上一个可用版本..." -ForegroundColor Yellow
        if (Test-Path $relEngine) { Remove-Item -Recurse -Force $relEngine }
        Move-Item $engineBackup $relEngine
        try {
            # 用独立进程组启动：不挂在本脚本的进程树上，脚本退出后实例继续存活
            Start-WithoutSigningEnvironment -Path (Join-Path $Root $exe) | Out-Null
            Write-Host "已重新拉起上一个版本（未验证，请手动确认）" -ForegroundColor Yellow
        } catch {
            Write-Host "旧版本拉起失败，请手动启动: $exe" -ForegroundColor Red
        }
    } else {
        Write-Host "无引擎资源备份，旧版本未恢复，请手动启动: $exe" -ForegroundColor Red
    }
    Write-Error "启动验证失败，已回滚版本号并尝试恢复上一个可用版本"
    exit 1
}

# 验证通过：备份可以丢了；实例改用独立进程组重启，避免脚本退出时被进程树回收
if (Test-Path $engineBackup) { Remove-Item -Recurse -Force $engineBackup }
if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; Start-Sleep 2 }
Start-WithoutSigningEnvironment -Path (Join-Path $Root $exe) | Out-Null
Write-Host "已以独立进程启动 v$newVer（脚本退出后继续运行）" -ForegroundColor Green

Write-Host "`n完成: 数据面具 Maskit v$newVer（Tauri 壳 + 引擎 sidecar）已构建" -ForegroundColor Cyan
Write-Host "安装包: src-tauri\target\release\bundle\nsis\Maskit_${newVer}_x64-setup.exe" -ForegroundColor Cyan
Write-Host "提交时把版本号写进 commit message（如 feat: v$newVer ...）" -ForegroundColor Yellow
