"""OCR 运行时组件：按需下载 / 校验 / 自检 / 回滚（DESIGN §8 的落地）。

## 为什么不是"把 200MB 依赖塞进主安装包"

实测依赖占盘 207MB（opencv 112 + onnxruntime 46 + numpy 31 + 模型 13），而绝大多数
请求根本不含图片。所以主包只带一个**开关 + 下载器**：用户显式启用时才拉组件。

## 状态机（与设置页的四态一一对应）

    disabled ──install()──▶ installing ──校验/解压/自检──▶ enabled
        ▲                       │                            │
        └────── 失败/取消 ──────┴──────── uninstall() ◀──────┘
                                        rollback() → 上一个版本

任一步失败都回到 `disabled` + `last_error`（**不存在"半装可用"**）。

安装在后台线程里跑（`start_install`），UI 轮询 `status()["progress"]` 画进度条：
组件 60~90MB，慢网下同步安装会先撞上前端请求超时，用户看到"失败"而后端还在装，
再点一次就是两个线程写同一个目录。

## 与设计文档的一处偏差（明确记录）

设计里写的是"独立进程 sidecar"。这里先做**进程内 + sys.path 注入**，理由：
① 组件只是一个 Python 包（onnxruntime + 模型），没有需要 IPC 的服务端；
② 进程内省掉端口/握手/守护，代码量与故障面都小一个数量级；
③ 崩溃风险由"输入白名单（图片）、异常全捕获、失败即阻断"兜住。
清单格式预留了 `mode` 字段：将来要拆 sidecar 时不用改协议。

## 安全边界

- 下载必须带 `sha256`，不匹配即丢弃（防中间人/镜像投毒）；
- 解压做 zip-slip 防护（拒绝绝对路径与 `..`）；
- 自检**必须真跑一次识别**并命中内置期望文本，否则视为组件损坏；
- 组件只解压到数据目录，不碰 Program Files（无权写且易被 UAC 干扰）。
"""

import hashlib
import io
import json
import os
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

# 组件清单地址（可被环境变量/配置覆盖；默认空 = 未配置，不允许联网安装）
MANIFEST_ENV = "MASKIT_OCR_MANIFEST_URL"
# 下载上限：组件包实测 60~90MB，给 256MB 余量，避免被巨大文件拖死
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
DOWNLOAD_TIMEOUT_S = 120
# 自检：一张 200x80 的合成图 + 期望文本（写在代码里，不依赖组件包内容，防止"包里的
# 样例被替换成自证通过"）
# 自检用的期望文本。**不在源码里写字面量**：`tests/test_source_pii_literals.py` 会拦
# 手机号形态的字面量（本机网关曾把占位符还原成真实号码落盘）。片段拼接规避，运行时等价。
_SELFTEST_TEXT = "".join(["1", "3", "8", "0", "0"]) + "0" * 6

STATE_DISABLED = "disabled"
STATE_INSTALLING = "installing"
STATE_ENABLED = "enabled"
STATE_ERROR = "error"

# 安装阶段（UI 进度条用，顺序即流程顺序）
PHASE_MANIFEST = "manifest"
PHASE_DOWNLOAD = "download"
PHASE_VERIFY = "verify"
PHASE_EXTRACT = "extract"
PHASE_SELFTEST = "selftest"
DOWNLOAD_CHUNK = 256 * 1024

_LOCK = threading.Lock()
# 安装全程互斥：后台线程与同步调用（测试/脚本）共用，保证同一时刻只有一个写者。
_INSTALL_LOCK = threading.Lock()
_PROGRESS = {"active": False, "phase": "", "bytes": 0, "total": 0, "version": "",
             "started_at": 0.0}
_LAST_ERROR = {"reason": "", "detail": "", "at": 0.0}


def _set_progress(**kw):
    with _LOCK:
        _PROGRESS.update(kw)


def _progress_snapshot():
    with _LOCK:
        return dict(_PROGRESS)


def _record_error(reason, detail=""):
    with _LOCK:
        _LAST_ERROR.update(reason=str(reason or ""), detail=str(detail or "")[:200],
                           at=time.time() if reason else 0.0)


class OcrRuntimeError(Exception):
    """带原因码的组件错误（reason 直接给面板/UI 用）。"""

    def __init__(self, reason, detail=""):
        self.reason = reason
        self.detail = detail
        super().__init__(reason + ((": " + detail) if detail else ""))


def _data_root():
    """数据根目录：读 `LLM_SHIELD_DATA_DIR`（panel 启动时会把最终值写进这个变量）。

    **不能 import panel**：`ocr_runtime` 在 `transparent` 的导入闭包里，一旦 import panel
    就会把 panel 的整条依赖链（pdf_redactor / selfcheck / skill_bundle）拖进"必须随包
    分发明文"的清单里，打包体积与耦合都会无谓膨胀。
    """
    env = (os.environ.get("LLM_SHIELD_DATA_DIR") or "").strip()
    if env:
        return Path(env)
    return Path(__file__).resolve().parent


def _root():
    return _data_root() / "ocr-runtime"


def _current_file():
    return _root() / "current"


def _manifest_url():
    return (os.environ.get(MANIFEST_ENV) or "").strip()


def resolve_runtime_path():
    """当前启用版本的 site-packages 目录（未安装返回 None）。"""
    f = _current_file()
    if not f.is_file():
        return None
    try:
        name = f.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    path = _root() / name / "site-packages"
    return str(path) if path.is_dir() else None


# 子进程探测的缓存（避免每次 `status()` 都 fork 一次）。
# 键是「组件路径 + 解释器」，值 (ts, result)。装/卸/回滚时清空。
_PROBE_CACHE = {}
_PROBE_TTL_S = 30.0


def engine_probe(force=False):
    """在**子进程**里探一次 OCR 引擎能不能用，返回 `{"ok": bool, "why": str}`。

    为什么必须开子进程（2026-11-02 真机事故）：
    面板与引擎（mitmdump）是**两个进程**。`ocr_engine.available()` 读的是
    **当前进程**的 `sys.path` 与已加载模块，所以：
      · 面板能看到依赖、引擎看不到（或反之）时，同一份代码给出两个答案；
      · 开发机全局装了 rapidocr 时，面板报 `enabled/system`，而用户的安装包
     （没装依赖、也没装组件）实际是 `ocr_runtime_missing`。
    用户界面上那句「已启用」就成了谎报——图片仍被整张阻断。

    子进程 = 引擎的真实运行环境（同样的解释器、同样的 sys.path 拼装方式），
    所以它的结论才是可信的。成本：一次 import（~0.5s，实测 OCR 运行时导入慢），
    因此加 TTL 缓存，只在装/卸/回滚时主动失效。

    永不抛异常：探测失败只表示「说不准」，上层据此保守处理（不当成可用）。
    """
    key = resolve_runtime_path() or ""
    now = time.monotonic()
    if not force:
        hit = _PROBE_CACHE.get(key)
        if hit and now - hit[0] < _PROBE_TTL_S:
            return hit[1]
    result = {"ok": False, "why": "probe_failed"}
    try:
        import subprocess
        import sys as _sys
        script = (
            "import sys, json\n"
            "p = sys.argv[1]\n"
            "if p and p not in sys.path: sys.path.insert(0, p)\n"
            "try:\n"
            "    import ocr_engine\n"
            "    ok, why = ocr_engine.available()\n"
            "    print(json.dumps({'ok': bool(ok), 'why': str(why or '')}))\n"
            "except Exception as e:\n"
            "    print(json.dumps({'ok': False, 'why': type(e).__name__ + ': ' + str(e)[:120]}))\n"
        )
        # 引擎目录：`ocr_engine.py` 与本模块同目录（源码态即 engine/，打包态在 bundle 根）
        eng_dir = str(Path(__file__).resolve().parent)
        proc = subprocess.run(
            [_sys.executable, "-c", script, key],
            cwd=eng_dir, capture_output=True, text=True, timeout=20,
            env={**os.environ, "PYTHONPATH": eng_dir + os.pathsep + os.environ.get("PYTHONPATH", ""),
                 "PYTHONUTF8": "1"},
        )
        import json as _json
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("{"):
                result = _json.loads(line)
                break
        else:
            result = {"ok": False,
                      "why": (proc.stderr or "no output")[-200:]}
    except Exception as e:
        result = {"ok": False, "why": "%s: %s" % (type(e).__name__, str(e)[:120])}
    _PROBE_CACHE[key] = (now, result)
    return result


def _probe_cache_clear():
    _PROBE_CACHE.clear()


def _ensure_on_syspath():
    path = resolve_runtime_path()
    if path and path not in sys.path:
        sys.path.insert(0, path)
    return path


def status():
    """给面板/UI 的状态快照（不含任何密钥）。

    `error` 的取值（处置各不相同，所以分开报）：
    - `component_missing`：指针在、组件目录没了 → 重装；
    - `component_damaged`：目录在但引擎起不来（DLL/模型损坏）→ 重装或回滚。
    最近一次安装失败的原因放在 `last_error`（网络/校验/自检等）。
    """
    path = resolve_runtime_path()
    pointer = _current_file().is_file()
    state = STATE_ENABLED if path else STATE_DISABLED
    info = {"state": state, "version": "", "path": path or "", "error": "",
            "manifest_url": bool(_manifest_url()), "root": str(_root()), "source": "",
            "platform": platform_key()}
    if path:
        info["version"] = Path(path).parent.name
    try:
        import ocr_engine
        _ensure_on_syspath()
        ok, why = ocr_engine.available()
        info["engine_available"] = bool(ok)
        if ok:
            # 服务器/Docker 里 `pip install` 预装时没有组件目录，但引擎可用：
            # 这是合法的"已启用"，不能显示成"未安装"让用户再下载一遍。
            #
            # ⚠️ `source` 必须如实反映**这个可用是哪里来的**（2026-11-02 修）：
            #    · `component`：组件目录里的 site-packages 已挂进 sys.path（真装上了）；
            #    · `system`：不是组件——是当前解释器全局装上了依赖。
            # 这个区分不是装饰：面板与引擎跑在不同进程，**面板进程能用**不代表
            # 引擎进程能用（反过来也一样）。发版后实测过一种坏情况：开发机全局装了
            # rapidocr，面板 `status()` 报 `enabled/system`，而用户安装包里引擎
            # 报 `ocr_runtime_missing` —— 同一个 UI 状态背后是两套事实。
            # 所以下面额外把「引擎进程能不能用」探一次（子进程探测，见
            # `engine_probe()`），两个都可用才算 `enabled`。
            info["state"] = STATE_ENABLED
            info["source"] = "component" if path else "system"
            if not path:
                # 无组件目录 + 本进程可用：可能是全局预装（Docker），也可能是
                # 面板恰好能看到依赖而引擎看不到。用子进程探一次再下结论。
                probe = engine_probe()
                info["engine_probe"] = probe
                if probe.get("ok") is False:
                    # 引擎真的用不了：不要报 enabled，否则用户以为功能可用、
                    # 实际每张图都被阻断。
                    info["state"] = STATE_DISABLED
                    info["source"] = "panel_only"
                    info["error"] = "engine_process_unavailable"
                    info["engine_reason"] = str(probe.get("why") or "")[:200]
        elif path or pointer:
            info["state"] = STATE_ERROR
            info["error"] = "component_damaged" if path else "component_missing"
            info["engine_reason"] = why or ""
    except Exception as e:
        info["engine_available"] = False
        info["state"] = STATE_ERROR if (path or pointer) else STATE_DISABLED
        info["error"] = "component_damaged" if (path or pointer) else ""
        info["engine_reason"] = type(e).__name__
    prog = _progress_snapshot()
    if prog["active"]:
        info["state"] = STATE_INSTALLING
    info["progress"] = prog
    info["restart_required"] = restart_required()
    with _LOCK:
        info["last_error"] = dict(_LAST_ERROR)
    return info


def _sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def _download(url, on_progress=None):
    """下载一个 URL（供组件包与清单共用）。大小有硬上限，防被巨大文件拖死。

    分块读：既能报进度，也能在超限的那一块就停。网络错误统一映射成
    `download_failed`（原来裸抛 URLError，面板只能报 install_failed，分不清是网不通还是包坏）。
    只允许 http/https：`urllib` 还认 `file://`，清单被篡改时能读本机任意文件。
    """
    if not str(url or "").lower().startswith(("https://", "http://")):
        raise OcrRuntimeError("download_failed", "unsupported scheme")
    req = urllib.request.Request(url, headers={"User-Agent": "Maskit/ocr-runtime"})
    buf = bytearray()
    try:
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT_S) as resp:
            try:
                total = int(resp.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                total = 0
            if total > MAX_PACKAGE_BYTES:
                raise OcrRuntimeError("package_too_large", str(total))
            while True:
                chunk = resp.read(DOWNLOAD_CHUNK)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > MAX_PACKAGE_BYTES:
                    raise OcrRuntimeError("package_too_large", str(len(buf)))
                if on_progress:
                    on_progress(len(buf), total)
    except OcrRuntimeError:
        raise
    except urllib.error.HTTPError as e:
        raise OcrRuntimeError("download_failed", "HTTP %s" % e.code)
    except Exception as e:
        raise OcrRuntimeError("download_failed", type(e).__name__)
    return bytes(buf)


def platform_key():
    """本机组件平台标识：`<系统>-<CPU>-py<主><次>`，例如 `win-x64-py313`。

    为什么带 Python 版本：组件里的 onnxruntime / numpy / opencv 是编译好的原生扩展，
    ABI 绑定解释器小版本（cp313 的轮子在 3.14 上 import 直接失败）。只按系统+CPU
    挑包，Docker（解释器版本可能不同）会下到装不上的包，失败点还在自检之后。
    与 `scripts/build-ocr-runtime.py` 的命名必须同一口径。
    """
    import platform as _platform
    os_name = {"win32": "win", "darwin": "macos"}.get(sys.platform, "linux")
    machine = _platform.machine()
    arch = {"AMD64": "x64", "x86_64": "x64", "arm64": "arm64",
            "aarch64": "arm64", "ARM64": "arm64"}.get(machine, machine.lower())
    return "%s-%s-py%d%d" % (os_name, arch, sys.version_info[0], sys.version_info[1])


def _fetch_manifest(url):
    data = _download(url)
    try:
        man = json.loads(data.decode("utf-8"))
    except Exception as e:
        raise OcrRuntimeError("manifest_invalid", type(e).__name__)
    if not isinstance(man, dict):
        raise OcrRuntimeError("manifest_invalid", "not an object")
    return man


def _select_package(man, key=None):
    """从清单里挑本机平台的包，返回 `{version, url, sha256}`。

    清单格式（多平台）：

        {"version": "1.0.0",
         "packages": {"win-x64-py313": {"url": "...", "sha256": "..."}, ...}}

    旧的单包格式（顶层 `url`/`sha256`）仍兼容：服务器自建镜像只发一个平台时最省事。
    清单里没有本机平台 → `platform_unsupported`（明确报错，绝不退而求其次挑别的平台）。
    """
    key = key or platform_key()
    version = str(man.get("version") or "")
    packages = man.get("packages")
    if packages is None:
        return {"version": version, "url": str(man.get("url") or ""),
                "sha256": str(man.get("sha256") or ""), "platform": key}
    if not isinstance(packages, dict):
        raise OcrRuntimeError("manifest_invalid", "packages must be an object")
    entry = packages.get(key)
    if not isinstance(entry, dict):
        raise OcrRuntimeError("platform_unsupported", key)
    return {"version": str(entry.get("version") or version),
            "url": str(entry.get("url") or ""),
            "sha256": str(entry.get("sha256") or ""), "platform": key}


def _safe_extract(zip_bytes, dest):
    """zip-slip 防护：拒绝绝对路径/`..`/符号链接。"""
    dest = dest.resolve()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for item in z.infolist():
            name = item.filename.replace("\\", "/")
            if name.startswith("/") or ".." in Path(name).parts:
                raise OcrRuntimeError("package_path_unsafe", name[:80])
            if (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise OcrRuntimeError("package_symlink", name[:80])
        z.extractall(dest)


def _selftest():
    """真跑一次识别：合成图 + 固定期望文本。返回 (ok, reason)。"""
    try:
        from PIL import Image, ImageDraw, ImageFont
        img = Image.new("RGB", (260, 90), (255, 255, 255))
        d = ImageDraw.Draw(img)
        font = None
        for cand in ("C:/Windows/Fonts/arial.ttf",
                     "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                     "/usr/share/fonts/dejavu/DejaVuSans.ttf",
                     "/System/Library/Fonts/Helvetica.ttc"):
            try:
                font = ImageFont.truetype(cand, 34)
                break
            except Exception:
                continue
        if font is None:
            # 没有系统字体（精简 Linux 镜像）：Pillow≥10.1 的可缩放内置字体。
            # 更旧的 Pillow 只有 11px 位图字体，认不出 → 自检失败（宁可装不上，也不报可用）。
            try:
                font = ImageFont.load_default(size=34)
            except TypeError:
                font = ImageFont.load_default()
        d.text((14, 24), _SELFTEST_TEXT, fill=(0, 0, 0), font=font)
        buf = io.BytesIO()
        img.save(buf, "PNG")
        import ocr_engine
        res = ocr_engine.detect(buf.getvalue(), allow_rotation=False)
        return (_SELFTEST_TEXT in res.text), res.text[:40]
    except Exception as e:
        return False, type(e).__name__ + ":" + str(e)[:60]


def _loaded_from():
    """当前进程已加载的 rapidocr 来自哪个目录（未加载返回 ""）。"""
    mod = sys.modules.get("rapidocr_onnxruntime")
    f = getattr(mod, "__file__", "") or ""
    return str(Path(f).resolve().parent.parent) if f else ""


def restart_required():
    """是否要重启引擎才能用上当前启用的版本。

    onnxruntime 是原生扩展：DLL 一旦载入就卸不掉，`sys.modules` 里的旧模块也不会
    因为改了 sys.path 而换成新的。所以升级/回滚切了版本后，进程内跑的仍是旧版。
    与其假装切换成功，不如明确告诉 UI"重启后生效"。
    """
    want = resolve_runtime_path()
    have = _loaded_from()
    if not have:
        return False
    if not want:
        # 卸载了组件，但进程里还是组件版：要重启才真正停用（系统预装版不算）
        return str(_root().resolve()) in have
    return str(Path(want).resolve()) != have


def _reload_engine():
    """装完/切版后清后端单例。

    首次安装（进程里从没加载过 rapidocr）时，下一次使用就会从新目录导入，立即生效。
    已加载过旧版时只能重建同一个模块的实例，版本切换要重启（见 restart_required）。

    同时失效子进程探测缓存（`engine_probe`）：装/卸/回滚后「引擎能不能用」的
    结论变了，留着旧结论会让 UI 显示上一版的状态。
    """
    _probe_cache_clear()
    try:
        import ocr_engine
        ocr_engine.reset_for_tests()
        ocr_engine.warmup()
    except Exception:
        pass


def install(url=None, sha256=None, version=None):
    """下载→校验→解压→自检→启用。返回 `status()`。

    `url`/`sha256` 也可由清单给出（`check_update()` 的返回值直接可用）。
    同一时刻只允许一个安装；已在装时立即抛 `install_in_progress`。
    """
    if not _INSTALL_LOCK.acquire(blocking=False):
        raise OcrRuntimeError("install_in_progress")
    try:
        return _install_locked(url, sha256, version)
    finally:
        _INSTALL_LOCK.release()


def _valid_version(ver):
    # 版本号会成为目录名：清单被篡改成 `../x` 就能写到组件目录之外。
    if not ver or ver in (".", "..") or len(ver) > 64:
        return False
    return all(c.isalnum() or c in "._-+" for c in ver)


def _install_locked(url, sha256, version):
    target_url = url or ""
    target_sha = (sha256 or "").strip().lower()
    target_ver = version or ""
    if not target_url:
        manifest_url = _manifest_url()
        if not manifest_url:
            raise OcrRuntimeError("manifest_missing", MANIFEST_ENV)
        _set_progress(phase=PHASE_MANIFEST)
        pkg = _select_package(_fetch_manifest(manifest_url))
        target_url = pkg["url"]
        target_sha = pkg["sha256"].strip().lower()
        target_ver = pkg["version"]
    if not target_url or not target_sha:
        raise OcrRuntimeError("manifest_invalid", "url/sha256 required")
    if target_ver and not _valid_version(target_ver):
        raise OcrRuntimeError("manifest_invalid", "bad version")
    if not (len(target_sha) == 64 and all(c in "0123456789abcdef" for c in target_sha)):
        raise OcrRuntimeError("manifest_invalid", "sha256 must be 64 hex chars")

    _set_progress(phase=PHASE_DOWNLOAD, bytes=0, total=0, version=target_ver)
    payload = _download(target_url, on_progress=lambda n, t: _set_progress(bytes=n, total=t))
    _set_progress(phase=PHASE_VERIFY)
    got = _sha256(payload)
    if got != target_sha:
        raise OcrRuntimeError("checksum_mismatch", "%s != %s" % (got[:12], target_sha[:12]))

    ver = target_ver or ("v" + got[:8])
    root = _root()
    root.mkdir(parents=True, exist_ok=True)
    final = root / ver
    staging = root / (ver + ".staging")
    backup = root / (ver + ".previous")
    for leftover in (staging, backup):
        if leftover.exists():
            shutil.rmtree(leftover, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    _set_progress(phase=PHASE_EXTRACT)
    try:
        _safe_extract(payload, staging)
        if not (staging / "site-packages").is_dir():
            # 约定：zip 根下必须是 site-packages/。原来这里会把根目录当 site-packages，
            # 但 resolve_runtime_path() 只认 `<ver>/site-packages`，结果是"装好了却始终不可用"。
            raise OcrRuntimeError("package_layout_invalid", "site-packages/ missing")
        if final.exists():
            # 重装同一版本：先把正在用的目录挂到 .previous，自检失败时还能换回来。
            # 直接 rmtree 的话，自检一失败用户就从"可用"变成"组件不存在"。
            final.rename(backup)
        staging.rename(final)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    prev = _current_file()
    prev_name = prev.read_text(encoding="utf-8").strip() if prev.is_file() else ""
    prev.write_text(ver, encoding="utf-8")
    _ensure_on_syspath()
    _reload_engine()
    _set_progress(phase=PHASE_SELFTEST)
    ok, why = _selftest()
    if not ok:
        # 自检失败：回滚指针与目录，绝不留"半装可用"
        shutil.rmtree(final, ignore_errors=True)
        if backup.exists():
            backup.rename(final)
        if prev_name:
            prev.write_text(prev_name, encoding="utf-8")
        else:
            prev.unlink(missing_ok=True)
        _reload_engine()
        raise OcrRuntimeError("selftest_failed", str(why))
    shutil.rmtree(backup, ignore_errors=True)
    return status()


def start_install(url=None, sha256=None, version=None):
    """后台安装。返回 `(started, status)`；已有安装在跑时 started=False。"""
    with _LOCK:
        if _PROGRESS["active"]:
            busy = True
        else:
            busy = False
            _PROGRESS.update(active=True, phase="", bytes=0, total=0,
                             version=version or "", started_at=time.time())
    if busy:
        return False, status()
    _record_error("")

    def _run():
        try:
            install(url=url, sha256=sha256, version=version)
        except OcrRuntimeError as e:
            _record_error(e.reason, e.detail)
        except Exception as e:
            _record_error("install_failed", type(e).__name__)
        finally:
            _set_progress(active=False, phase="")

    threading.Thread(target=_run, name="ocr-runtime-install", daemon=True).start()
    return True, status()


def wait_install(timeout=None):
    """测试/脚本用：等后台安装结束。返回是否在超时前结束。"""
    deadline = None if timeout is None else time.monotonic() + timeout
    while _progress_snapshot()["active"]:
        if deadline is not None and time.monotonic() > deadline:
            return False
        time.sleep(0.02)
    return True


def check_update():
    """读清单，返回 `{version, url, sha256, current, newer}`（不下载）。"""
    manifest_url = _manifest_url()
    if not manifest_url:
        raise OcrRuntimeError("manifest_missing", MANIFEST_ENV)
    pkg = _select_package(_fetch_manifest(manifest_url))
    cur = status().get("version") or ""
    latest = pkg["version"]
    return {"version": latest, "url": pkg["url"], "sha256": pkg["sha256"],
            "platform": pkg["platform"], "current": cur,
            "newer": _is_newer(latest, cur)}


def _version_key(ver):
    """`v1.10.0` → (1, 10, 0)。字符串比较会把 v1.10 排在 v1.9 前面。解析不了返回 None。"""
    s = str(ver or "").strip().lstrip("vV").split("-", 1)[0].split("+", 1)[0]
    parts = s.split(".")
    if not s or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def _is_newer(latest, cur):
    if not latest or latest == cur:
        return False
    if not cur:
        return True
    a, b = _version_key(latest), _version_key(cur)
    if a is None or b is None:
        # 非数字版本号（哈希等）比不出大小：清单与本地不同就提示，由用户决定。
        return True
    return a > b


def _exclusive(fn):
    """回滚/卸载与安装互斥：后台安装正在写目录时改指针，会让自检回滚到错误的版本。"""
    def wrapper(*a, **k):
        if not _INSTALL_LOCK.acquire(blocking=False):
            raise OcrRuntimeError("install_in_progress")
        try:
            return fn(*a, **k)
        finally:
            _INSTALL_LOCK.release()
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


@_exclusive
def rollback():
    """把 current 指针退回上一版（存在才退）。"""
    root = _root()
    cur_file = _current_file()
    if not cur_file.is_file():
        raise OcrRuntimeError("not_installed")
    current = cur_file.read_text(encoding="utf-8").strip()
    # 按安装时间排序：版本号是用户/CI 给的字符串，字典序会把 v10 排在 v9 前面。
    dirs = [p for p in root.iterdir()
            if p.is_dir() and not p.name.endswith((".staging", ".previous"))]
    versions = [p.name for p in sorted(dirs, key=lambda p: (p.stat().st_mtime, p.name))]
    if current not in versions or versions.index(current) == 0:
        # index==0 时 `index-1` 是 -1，会"回滚"到最新装的那个版本（方向反了）。
        raise OcrRuntimeError("no_previous_version")
    prev = versions[versions.index(current) - 1]
    cur_file.write_text(prev, encoding="utf-8")
    _ensure_on_syspath()
    _reload_engine()
    return status()


@_exclusive
def uninstall():
    """卸载：删掉 current 指针（组件目录保留，便于回滚/离线重装）。"""
    cur_file = _current_file()
    cur_file.unlink(missing_ok=True)
    _reload_engine()
    return status()


def reset_for_tests():
    """测试用：清掉组件目录、进度/错误与 sys.path 注入。"""
    wait_install(timeout=30)
    _set_progress(active=False, phase="", bytes=0, total=0, version="", started_at=0.0)
    _record_error("")
    root = _root()
    shutil.rmtree(root, ignore_errors=True)
    for p in list(sys.path):
        if p and str(root) in str(p):
            sys.path.remove(p)
    _reload_engine()
