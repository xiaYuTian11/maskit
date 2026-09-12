"""Data Maskit 引擎 sidecar 入口（Tauri 版）。

PyInstaller 入口不能带参数，本文件包装 panel 启动逻辑，复刻 `run_panel()` 的
步骤 0（ACL 收紧）+ 1（Flask 主线程）+ 1.5（代理自启/fallback 兜底），仅去掉
窗口/托盘（由 Tauri 壳承担）。

⚠️ 不能只调 start_panel_server()：代理自启与 fallback 兜底逻辑在 `run_panel()`
步骤 1.5（v1.5.65 实测确认），不在 start_panel_server 内——漏掉会导致「面板
起了但上游端口无人监听，客户端连接被拒」。

退出路径：Rust 壳三段式（HTTP /api/proxy/stop 优雅停 → 超时 taskkill /T /F），
本进程主线程跑 Flask 时已注册 SIGINT/SIGTERM + console handler（shutdown 收尾）。
"""
# Data Maskit — 本地 LLM 敏感信息脱敏代理
# Copyright (C) 2026 TMW
#
# 本程序是自由软件：你可以依据自由软件基金会发布的 GNU Affero 通用公共许可证
# （版本 3）条款重新分发和/或修改它。
# 本程序基于「希望有用」的目的分发，但不附带任何担保；亦无对适销性或特定用途
# 适用性的默示担保。详见 GNU Affero 通用公共许可证。
# 你应已随本程序收到一份 GNU AGPL 副本；若无，见 <https://www.gnu.org/licenses/>。
import os
import sys

# PyInstaller 在 Windows GUI 模式（console=False / windowed）下，若无依附控制台，
# sys.stdin / sys.stdout / sys.stderr 会被操作系统与运行时置为 None。
# mitmproxy 的 TermLogHandler 会读取 sys.stdout 并无判空直接调用
# vt_codes.ensure_supported(file) -> file.isatty()，当为 None 时必抛
# AttributeError: 'NoneType' object has no attribute 'isatty'，
# 导致点击启动代理时直接弹窗崩溃挂起（Windows MessageBox 阻塞）。
# 此处在导入任何三方库前，确保标准流始终非空且具备完整 TextIO 行为（isatty() -> False）。
for _stream_name, _stream_mode in (("stdin", "r"), ("stdout", "w"), ("stderr", "w")):
    _stream = getattr(sys, _stream_name, None)
    if _stream is None or not hasattr(_stream, "isatty"):
        try:
            setattr(sys, _stream_name, open(os.devnull, _stream_mode, encoding="utf-8"))
        except Exception:
            pass

import threading

import panel


def _run_as_mitmdump() -> int:
    """把本 exe 当 mitmdump 用（打包态唯一可行的代理运行方式）。

    为什么必须有这个分支：panel 原来直接 spawn 裸命令 `mitmdump`，靠系统 PATH 解析。
    开发机装了 mitmproxy 所以一直正常，但**安装包里不含 mitmdump.exe**——
    干净的 Windows 上那条命令根本解析不到，代理永远起不来，客户端只能落到
    503 占位兜底（SHIELD-NO-MITMDUMP-001，2026-08-15 外部审计发现，实测确认）。

    mitmproxy 这个库本身已经打进 bundle，缺的只是命令行入口，所以让引擎自己
    以子进程形式跑 mitmproxy.tools.main.mitmdump 即可，不需要额外分发解释器。
    """
    from mitmproxy.tools.main import mitmdump
    return mitmdump(sys.argv[2:]) or 0


def _autostart() -> None:
    """按配置自启代理；未开自启也要挂 fallback 兜底（端口有人监听）。"""
    try:
        if panel.load_config().get("auto_start_proxy"):
            ok, err = panel.start_proxy()
            if not ok:
                panel._emit_log(f"[panel] 代理自启失败: {err}")
                panel._start_fallback("代理自启失败")
        else:
            panel._start_fallback("未开启代理自启")
    except Exception as e:  # noqa: BLE001 —— 自启失败绝不能让引擎进程退出
        panel._emit_log(f"[panel] 代理自启异常: {e}")


def main() -> None:
    # -1. mitmdump 子进程模式：必须在任何 panel 初始化之前判断并接管，
    #     否则会在代理子进程里又起一个 Flask 面板、抢同一个端口。
    if len(sys.argv) > 1 and sys.argv[1] == "--mitmdump":
        sys.exit(_run_as_mitmdump())

    # 0. 数据目录 ACL 收紧（对齐 run_panel 步骤 0；幂等，失败不阻断）
    try:
        panel._harden_data_dir_acl()
    except Exception:  # noqa: BLE001
        pass

    # 0.5 更名后的一次性清理：删掉指向已卸载旧 exe 的自启项（开机弹「找不到文件」）。
    # panel.py 的 __main__ 分支在打包态不会执行，这里是引擎唯一入口，必须补上。
    try:
        panel._purge_stale_legacy_autostart()
    except Exception:  # noqa: BLE001
        pass

    # 1.5 代理自启/fallback：Flask 主线程阻塞期间由后台线程触发
    threading.Thread(target=_autostart, daemon=True).start()

    # 1. Flask 主线程阻塞运行（注册信号/console handler → Rust 杀进程时能走 shutdown）
    panel.start_panel_server(open_browser_on_start=False)


if __name__ == "__main__":
    main()
