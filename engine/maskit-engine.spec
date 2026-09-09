# -*- mode: python ; coding: utf-8 -*-
"""数据面具 Maskit 引擎 sidecar PyInstaller spec（Tauri 版）。

入口 engine_entry.py（复刻 app.py 的自启/fallback 逻辑，方案 §4.11）。
产物：dist_engine/MaskitEngine/（onedir，exe + _internal），整体携带进
Tauri resources/engine/。

与旧 shield.spec（app.py 入口，pywebview 壳）的区别：
- 排除 webview/pystray/templates（前端资产与托盘由 Tauri 壳承担）
- console=False：无控制台窗口；mitmdump 子进程黑框由 panel.py:1508 的
  CREATE_NO_WINDOW 保证（已核查）
"""
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

import os
import sys
from pathlib import Path

spec_dir = Path(globals().get("SPECPATH") or globals().get("__file__") or (Path.cwd() / "engine")).resolve()
ENGINE_DIR = spec_dir if spec_dir.name == "engine" else (spec_dir / "engine")
ROOT_DIR = ENGINE_DIR.parent

# mitmproxy 动态 import 较多，必须收集全部子模块
mitmproxy_hidden = collect_submodules('mitmproxy')
mitmproxy_data = collect_data_files('mitmproxy')

hiddenimports = (
    mitmproxy_hidden
    + [
        'flask',
        'shield_defaults',
        'event_store',
        'transparent',
        'panel',
        'audit_signals',
        'audit_engine',
        # mitmdump 命令行入口：安装包不含 mitmdump.exe，引擎要自己当 mitmdump 跑
        # （engine_entry._run_as_mitmdump）。漏了它 = 干净机器上代理永远起不来。
        'mitmproxy.tools.main',
        'mitmproxy.tools.dump',
    ]
)

# PyInstaller expects the native icon format for each host. Linux does not need an
# application icon for the sidecar; passing the Windows ICO there causes a noisy
# conversion warning and can fail on builders without Pillow image plugins.
if sys.platform == "win32":
    bundle_icon = str(ROOT_DIR / "src-tauri/icons/icon.ico")
elif sys.platform == "darwin":
    bundle_icon = str(ROOT_DIR / "src-tauri/icons/icon.icns")
else:
    bundle_icon = None

datas = (
    mitmproxy_data
    # 这几个必须以**明文源文件**随包分发：transparent.py 是被 mitmdump 当脚本加载的，
    # 它在自己的模块空间里 import 下面几个，靠 PYTHONPATH 指向 _BUNDLE_ROOT 才找得到，
    # 打进 PYZ 它够不着。代价是引擎规则对用户可见——这是架构决定的，改不了。
    + [(str(ENGINE_DIR / 'transparent.py'), '.')
       , (str(ENGINE_DIR / 'shield_defaults.py'), '.')
       , (str(ENGINE_DIR / 'event_store.py'), '.')
       , (str(ENGINE_DIR / 'audit_signals.py'), '.')
       , (str(ENGINE_DIR / 'audit_engine.py'), '.')
       , (str(ENGINE_DIR / 'config.example.json'), '.')]
)

a = Analysis(
    [str(ENGINE_DIR / 'engine_entry.py')],
    pathex=[str(ENGINE_DIR), str(ROOT_DIR)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'pytest', 'unittest', 'webview', 'pystray',
              'matplotlib', 'PyQt6', 'PyQt6.QtCore', 'PyQt6.QtGui', 'PyQt6.QtWidgets',
              # PyInstaller 的 excludes 是**大小写敏感**的模块名。
              # 原来只写了小写 'ipython'，而实际包名是 IPython —— 排除项形同虚设。
              # 实测 0.1.5 正式包里 IPython 90K、numpy 6.9M、numpy.libs 21M 全都在，
              # 45MB 安装包里有 28MB 是产品一行都不调用的科学计算库
              #（构建环境装了 langchain/transformers/numba 那一堆，它们把 numpy 拖了进来）。
              # 引擎只用 mitmproxy + flask + stdlib，这些一个都不需要。
              'IPython', 'ipython', 'jedi', 'parso', 'PIL.ImageQt',
              'numpy', 'numpy.libs', 'pandas', 'scipy', 'numba', 'llvmlite',
              'transformers', 'torch', 'huggingface_hub', 'tokenizers',
              'sklearn', 'sympy', 'notebook', 'jupyter_core', 'zmq'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='MaskitEngine',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=sys.platform == "win32",
    console=False,  # --windowed：sidecar 无窗口
    icon=bundle_icon,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=sys.platform == "win32",
    upx_exclude=[],
    name='MaskitEngine',
)
