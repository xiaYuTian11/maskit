@echo off
chcp 65001 >nul
set "HOSTS_FILE=C:\Windows\System32\drivers\etc\hosts"
set "MARKER=# LLM-Shield"
set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

if /i not "%~1"=="silent" (
    echo.
    echo  ╔══════════════════════════════════════════╗
    echo  ║     紧急恢复 - 停止代理并清理旧标记       ║
    echo  ╚══════════════════════════════════════════╝
    echo.
)

:: 杀进程
:: 1) 桌面壳与引擎：必须一起杀。只杀 mitmdump 的话，壳的 watchdog 会在几秒内
::    把代理重新拉起来，「紧急恢复」等于没做。
::    LLMShieldEngine.exe 是更名前的旧名字，一起带上以覆盖升级未清理的场景。
:: 2) mitmdump / mitmproxy：注意这会把本机**所有**同名进程一起杀掉，包括你另外
::    安装的 mitmproxy。这正是「紧急恢复」要的确定性，但如果你在用别的 mitmproxy
::    工具，请改用 `Get-NetTCPConnection -LocalPort 5802` 找占用者再 taskkill /T。
taskkill /F /IM Maskit.exe >nul 2>&1
taskkill /F /IM MaskitEngine.exe >nul 2>&1
taskkill /F /IM LLMShieldEngine.exe >nul 2>&1
taskkill /F /IM mitmdump.exe >nul 2>&1
taskkill /F /IM mitmproxy.exe >nul 2>&1

:: 只清理本工具 marker 行，不覆盖 hosts 中的其他改动
:: ⚠️ MARKER 必须与 engine/panel.py 的 `MARKER` 常量逐字一致，否则这里的清理
::    会匹配不到面板写入的行（历史上曾出现两处不同步 → 残留死映射）。
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$p=$env:HOSTS_FILE; $m=$env:MARKER; $lines=[System.IO.File]::ReadAllLines($p); $new=$lines | Where-Object { $_ -notlike ('*' + $m + '*') }; [System.IO.File]::WriteAllLines($p, [string[]]$new)" >nul 2>&1

:: 刷新 DNS
ipconfig /flushdns >nul 2>&1

if /i not "%~1"=="silent" (
    echo.
    echo  所有站点网络已恢复正常。
    echo.
    pause
)
