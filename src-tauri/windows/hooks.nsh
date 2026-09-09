; Data Maskit — NSIS 安装钩子
;
; 为什么需要这个文件：
;   Tauri 的 NSIS 模板用 productName 命名快捷方式与"应用和功能"里的显示名。
;   productName 必须保持 ASCII（Maskit）——它同时决定安装目录，中文安装路径对
;   PyInstaller 打包的引擎与 mitmproxy 有踩坑风险。所以安装目录走 ASCII，
;   用户看得见的地方（桌面 / 开始菜单 / 应用和功能）在这里改回中文。
;
; 幂等：先 Delete 再 CreateShortcut。模板若已建过同名英文快捷方式，这里一并清掉，
; 避免桌面出现两个图标。

!macro NSIS_HOOK_PREINSTALL
  ; 安装/覆盖安装前，强制终止正在运行的 Maskit 壳和引擎进程，防止文件被锁导致"无法打开要写入的文件"
  nsExec::Exec 'taskkill /F /IM Maskit.exe'
  Pop $0
  nsExec::Exec 'taskkill /F /IM MaskitEngine.exe'
  Pop $0
  nsExec::Exec 'taskkill /F /IM mitmdump.exe'
  Pop $0
  Sleep 500
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; 清掉历史版本可能遗留的各种英文名/旧快捷方式，防止桌面出现两个图标
  Delete "$DESKTOP\Maskit.lnk"
  Delete "$DESKTOP\${PRODUCTNAME}.lnk"
  Delete "$DESKTOP\LLMShield.lnk"
  Delete "$SMPROGRAMS\Maskit.lnk"
  Delete "$SMPROGRAMS\${PRODUCTNAME}.lnk"
  Delete "$SMPROGRAMS\LLMShield.lnk"

  ; 统一创建中文名快捷方式（幂等覆盖）
  !ifdef MAINBINARYNAME
    !define _EXE_NAME "${MAINBINARYNAME}"
  !else
    !define _EXE_NAME "${PRODUCTNAME}"
  !endif
  CreateShortcut "$DESKTOP\Data Maskit.lnk" "$INSTDIR\${_EXE_NAME}.exe"
  ; 开始菜单
  CreateShortcut "$SMPROGRAMS\Data Maskit.lnk" "$INSTDIR\${_EXE_NAME}.exe"
  !undef _EXE_NAME

  ; "应用和功能"列表里的显示名改成中文（默认是 productName=Maskit，中文用户搜不到）
  ; SHCTX 由模板按 perMachine/currentUser 设好，跟随安装模式写 HKLM 或 HKCU
  !ifdef UNINSTKEY
    WriteRegStr SHCTX "${UNINSTKEY}" "DisplayName" "Data Maskit"
  !endif
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; 卸载前同样强制终止运行中的进程，释放文件锁
  nsExec::Exec 'taskkill /F /IM Maskit.exe'
  Pop $0
  nsExec::Exec 'taskkill /F /IM MaskitEngine.exe'
  Pop $0
  nsExec::Exec 'taskkill /F /IM mitmdump.exe'
  Pop $0
  Sleep 500

  Delete "$DESKTOP\Data Maskit.lnk"
  Delete "$SMPROGRAMS\Data Maskit.lnk"
  Delete "$DESKTOP\${PRODUCTNAME}.lnk"
  Delete "$SMPROGRAMS\${PRODUCTNAME}.lnk"

  ; 清掉开机自启项（新旧两个值名，与 lib.rs AUTOSTART_VALUE / panel.py AUTOSTART_VALUE_NAME 一致），
  ; 否则卸载后每次开机弹「找不到 Maskit.exe」。
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Maskit"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "LLMShield"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; 清理安装目录残留。
  ; 引擎是 PyInstaller onedir，运行时会在 resources\engine 下产生安装清单里没有的
  ; 文件（__pycache__、临时解包产物等）。NSIS 只删清单内的文件，于是卸载后
  ; resources\engine 整个目录还留在盘上（实测确认），用户会觉得"卸载没卸干净"。
  RMDir /r "$INSTDIR\resources\engine"
  RMDir /r "$INSTDIR\resources"
  RMDir "$INSTDIR"

  ; 用户数据目录（%APPDATA%\Maskit：配置、词库、事件库、授权凭证）一律不动。
  ; 那是用户自己的数据，卸载程序不等于授权我们替他删数据；重装后还能接着用，
  ; 真要清理由用户自己删——静默删掉别人几个月的日志是不可接受的。
!macroend
