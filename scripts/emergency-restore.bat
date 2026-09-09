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
taskkill /F /IM mitmdump.exe >nul 2>&1
taskkill /F /IM mitmproxy.exe >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq LLM-Shield-Watchdog*" >nul 2>&1

:: 只清理本工具 marker 行，不覆盖 hosts 中的其他改动
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
