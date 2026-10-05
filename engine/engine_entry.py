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
import threading
import time

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
        # 异常同样要挂兜底：对比上面的失败分支，这里漏掉的话所有 upstream
        # 端口无人监听，客户端连接被拒且引擎不会自愈（审计 P2）。
        try:
            panel._start_fallback("代理自启异常")
        except Exception:  # noqa: BLE001 —— 兜底失败也不让线程带栈退出
            pass


def _warn_if_ner_unavailable() -> None:
    """启动时检查「语义识别已开启但模型不可用」，命中就打印醒目告警。

    只告警、不阻断：脱敏主链路的规则扫描不依赖 NER，缺模型只是能力降级，
    把它当成致命错误让引擎起不来反而是更大的事故（AGENTS.md：可用性优先的兜底姿态）。
    """
    try:
        import ner_engine
        cfg = panel.load_config()
        if not cfg.get("ner_enabled"):
            return
        if ner_engine.is_ner_available():
            return
        panel._emit_log(
            "[engine] ⚠️ 语义识别（NER）已开启，但模型文件缺失 —— 实体识别不会生效。"
            f"期望路径：{ner_engine.MODEL_DIR}（需要 config.json / tokenizer.json / "
            "model_quantized.onnx 三个文件）。自建镜像请把模型拷进 engine/models/ner_mini_zh/，"
            "或在设置页关闭语义识别。")
    except Exception:  # noqa: BLE001
        pass          # 预检失败绝不阻断启动


def _warmup_ner_async() -> None:
    """后台预热语义模型（只在配置开启且模型就绪时）。

    为什么放后台线程：模型加载 + 首窗推理要数秒，放在主线程会拖晚面板可用；
    而懒加载会把这份钱记在**第一个用户请求**的 `mask_ms` 上（长会话下还会直接
    撞 `CALL_BUDGET_S` → 刚启动那几轮漏码）。预热失败不影响任何功能，
    请求侧仍会懒加载重试。
    """
    def _run() -> None:
        try:
            import ner_engine
            cfg = panel.load_config()
            if not cfg.get("ner_enabled"):
                return
            if not ner_engine.is_ner_available():
                return
            started = time.monotonic()
            ok = ner_engine.warmup()
            panel._emit_log("[engine] 语义识别预热%s（%.1fs）"
                            % ("完成" if ok else "未生效", time.monotonic() - started))
        except Exception:  # noqa: BLE001 —— 预热失败绝不影响引擎可用性
            pass

    threading.Thread(target=_run, daemon=True, name="maskit-ner-warmup").start()


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

    # 0.7 语义识别可用性预检（C-3）：模型缺失时**显式告警**。
    # 为什么放在启动而不是等用户触发：ner 开关打开但模型不在（自建镜像忘了拷
    # models/、容器挂载漏了）时，功能会静默降级成"开了但没做"，用户只能靠
    # 结果反推 —— 启动日志 + 自检 S21 两处同时说清楚。
    _warn_if_ner_unavailable()

    # 0.8 语义识别预热（批次 8）：开了 NER 才做，后台线程，不阻塞面板启动。
    _warmup_ner_async()

    # 1.5 代理自启/fallback：Flask 主线程阻塞期间由后台线程触发
    threading.Thread(target=_autostart, daemon=True).start()

    # 1. Flask 主线程阻塞运行（注册信号/console handler → Rust 杀进程时能走 shutdown）
    panel.start_panel_server(open_browser_on_start=False)


if __name__ == "__main__":
    main()
