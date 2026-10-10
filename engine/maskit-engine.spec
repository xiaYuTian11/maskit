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
        'connection_policy',
        'mitm_transport_adapter',
        'panel',
        'credential_labels',
        'onboarding',
        # 与 datas 同步：transparent.py（被 mitmdump 当脚本加载）在模块级 import 它们，
        # 而它靠 PYTHONPATH 指向 _BUNDLE_ROOT 找文件，打进 PYZ 的 import 未必够得着。
        # 两者必须同进 datas：漏了 datas 但只有 hiddenimports 时，产物里没有明文文件，
        # 而 release.yml 的「Assert packaged engine contents」会因此把发版拦下（已实测）。
        'inspection',
        'protocol_contracts',
        'audit_signals',
        'audit_engine',
        'ner_engine',
        # 0.6.0 新增（一键自检）：panel.py 里是**函数内**懒加载 `import selfcheck`，
        # 且三处调用点都包在 try 里 —— 万一打包态缺它，表现是“点了自检没反应”
        # 而不是报错（分析器的运气不能当保证）。tests/test_engine_packaging.py 锁这条。
        'selfcheck',
        'body_buffer',
        # C1 上游传输接管：transparent.py 在模块级 import upstream_retry，又在
        # `_c1_ensure_started()` 里懒加载 upstream_sidecar。两者原先都不在 spec 里
        # （全靠分析器捞），datas 也缺——打包态一旦捞不到，症状是「takeover 开了却
        # 从不生效」，日志里只留一行被吞掉的 ImportError。
        'upstream_retry',
        'upstream_sidecar',
        'credential_labels',
        'onnxruntime',
        'tokenizers',
        # mitmdump 命令行入口：安装包不含 mitmdump.exe，引擎要自己当 mitmdump 跑
        # （engine_entry._run_as_mitmdump）。漏了它 = 干净机器上代理永远起不来。
        'mitmproxy.tools.main',
        'mitmproxy.tools.dump',
        # mitmproxy 某些运行路径动态依赖 unittest（截图报错 No module named 'unittest'）
        # PyInstaller 分析遗漏时会在打包机正常、用户机启动代理失败。
        'unittest',
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

def _model_resources(engine_dir):
    model_dir = engine_dir / 'models' / 'ner_mini_zh'
    required = ('model_quantized.onnx', 'tokenizer.json', 'config.json')
    if not any((model_dir / name).exists() for name in required):
        return []
    missing = [name for name in required
               if not (model_dir / name).is_file() or (model_dir / name).stat().st_size == 0]
    if missing:
        raise SystemExit('Incomplete NER model bundle: ' + ', '.join(missing))
    return [(str(model_dir), 'models/ner_mini_zh')]


def _skill_bundle(root_dir):
    """占位符 Skill 包（agent-bundle/maskit-placeholders）随引擎分发。

    面板的 `GET /api/skill/bundle` 直接把它打成 zip 给用户下载，所以它必须在产物里：
    装到 Program Files 的用户拿不到仓库文件，而这份契约是「模型看到占位符怎么用」的
    唯一来源（缺了它，模型会自己发明规则）。

    与 `_model_resources` 的「可选模型」不同：本目录已入库，缺它就是打包事故，
    必须让构建当场失败而不是出一个「面板下载按钮 500」的包。
    """
    bundle = root_dir / 'agent-bundle' / 'maskit-placeholders'
    for name in ('contract.md', 'SKILL.md', 'templates/AGENTS.snippet.md'):
        if not (bundle / name).is_file():
            raise SystemExit('Missing placeholder skill bundle file: %s' % (bundle / name))
    return [(str(bundle), 'skill_bundle')]


datas = (
    mitmproxy_data
    # 这几个必须以**明文源文件**随包分发：transparent.py 是被 mitmdump 当脚本加载的，
    # 它在自己的模块空间里 import 下面几个，靠 PYTHONPATH 指向 _BUNDLE_ROOT 才找得到，
    # 打进 PYZ 它够不着。代价是引擎规则对用户可见——这是架构决定的，改不了。
    + [(str(ENGINE_DIR / 'transparent.py'), '.')
       , (str(ENGINE_DIR / 'connection_policy.py'), '.')
       , (str(ENGINE_DIR / 'body_buffer.py'), '.')
       , (str(ENGINE_DIR / 'mitm_transport_adapter.py'), '.')
       , (str(ENGINE_DIR / 'shield_defaults.py'), '.')
       , (str(ENGINE_DIR / 'credential_labels.py'), '.')
       , (str(ENGINE_DIR / 'upstream_retry.py'), '.')
       , (str(ENGINE_DIR / 'upstream_sidecar.py'), '.')
       , (str(ENGINE_DIR / 'event_store.py'), '.')
       , (str(ENGINE_DIR / 'onboarding.py'), '.')
       , (str(ENGINE_DIR / 'inspection.py'), '.')
       , (str(ENGINE_DIR / 'protocol_contracts.py'), '.')
       , (str(ENGINE_DIR / 'audit_signals.py'), '.')
       , (str(ENGINE_DIR / 'audit_engine.py'), '.')
       , (str(ENGINE_DIR / 'ner_engine.py'), '.')
       , (str(ENGINE_DIR / 'config.example.json'), '.')]
    # 本地 NER 模型（可选）：只在构建机确实有模型时才随包分发。
    # 该目录被 .gitignore 排除（98MB 二进制不入库），CI/干净克隆上根本不存在——
    # 无条件写进 datas 会让 PyInstaller 直接 SystemExit，把整个发版构建搞挂。
    # 缺模型时引擎照常工作，只是语义实体识别不可用（UI 与 /api/health 会明确报出）。
    + _model_resources(ENGINE_DIR)
    # 打包前端静态构建产物（若存在），支持在浏览器直接访问引擎端口展现 WebUI/登录页
    + ([(str(ROOT_DIR / 'frontend' / 'dist'), 'web_dist')] if (ROOT_DIR / 'frontend' / 'dist').exists() else [])
    # 占位符 Skill 包：面板 /api/skill/bundle 的数据源（见 _skill_bundle）
    + _skill_bundle(ROOT_DIR)
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
    excludes=['tkinter', 'pytest', 'webview', 'pystray',
              'matplotlib', 'PyQt6', 'PyQt6.QtCore', 'PyQt6.QtGui', 'PyQt6.QtWidgets',
              # PyInstaller 的 excludes 是**大小写敏感**的模块名。
              # 原来只写了小写 'ipython'，而实际包名是 IPython —— 排除项形同虚设。
              # 实测 0.1.5 正式包里 IPython 90K、numpy 6.9M、numpy.libs 21M 全都在，
              # 45MB 安装包里有 28MB 是产品一行都不调用的科学计算库
              #（构建环境装了 langchain/transformers/numba 那一堆，它们把 numpy 拖了进来）。
              # 引擎只用 mitmproxy + flask + stdlib。
              # ⚠️ 例外：numpy / tokenizers **不能排除**——本地 NER 引擎依赖
              # onnxruntime（自身强依赖 numpy）与 tokenizers。PyInstaller 的 excludes
              # 优先于 hiddenimports，两者同时存在时正式包会缺依赖，
              # 表现为「装了包、开了 NER，却什么都没识别到」。
              'IPython', 'ipython', 'jedi', 'parso', 'PIL.ImageQt',
              'pandas', 'scipy', 'numba', 'llvmlite',
              'transformers', 'torch', 'huggingface_hub',
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
