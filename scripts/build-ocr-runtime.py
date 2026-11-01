"""构建「OCR 组件」发布包（可选运行时，见 DESIGN §8）。

## 为什么需要它

主安装包刻意**不带** 200MB 的 OCR 依赖（实测 207MB），用户启用图片脱敏时下载组件。
组件必须能被独立构建与发布，否则"下载器"就是一个指向 404 的按钮。

## 产物

- `dist_ocr/MaskitOCR-<ver>-<platform>.zip`，`<platform>` 形如 `win-x64-py313`
  （与 `engine/ocr_runtime.platform_key()` 同一口径，客户端据此自动挑包）。
  zip 根下是 `site-packages/`（rapidocr_onnxruntime + onnxruntime + numpy + cv2 +
  shapely + pyclipper + 模型文件），解压后直接挂进 `sys.path` 即可 import。
- `dist_ocr/MaskitOCR-<ver>-<platform>.json`：本平台的清单片段。

## 多平台清单

每个平台在各自的构建机上跑一次本脚本，再把所有片段合并成一份清单：

    python scripts/build-ocr-runtime.py --merge dist_ocr/*.json --out-manifest latest-ocr.json

合并后的格式：`{"version": ..., "packages": {"win-x64-py313": {"url", "sha256", "size"}, ...}}`。
客户端只读属于自己的那一项；清单里没有本机平台时报 `platform_unsupported`。

## 用法

    python scripts/build-ocr-runtime.py --version 1.2.3
    python scripts/build-ocr-runtime.py --version 1.2.3 --url-prefix https://example.com/ocr

要求：当前解释器里已经装好 `requirements-ocr.txt`（构建机 = 目标平台）。
"""

import argparse
import glob
import hashlib
import re
import json
import platform
import shutil
import sys

# Windows 控制台默认 cp1252（charmap）：脚本里的中文提示/报错（如「没有可合并的片段」
# 和末尾的构建说明）在 CI 的 Windows runner 上直接 UnicodeEncodeError 把构建搞挂
# （2026-11-01 实测 win-x64 job，zip 已打好、死在最后一行 print）。统一改 UTF-8，
# 编不了的字符降级为替换符 —— 构建日志不能因为打印挂掉。
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import sysconfig
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist_ocr"
sys.path.insert(0, str(ROOT / "engine"))

# 根依赖。**其余依赖由元数据闭包自动带出**——硬编码清单会漏（实测漏过 PyYAML，
# 症状是组件装完 import 就报 No module named 'yaml'，而安装流程本身是"成功"的）。
ROOTS = (
    "rapidocr-onnxruntime",
    "onnxruntime",
    "numpy",
    "opencv-python",      # 或 opencv-python-headless
    "pillow",             # 组件自带图片解码，服务器可能没装
)
# 明确排除：调试符号/测试/头文件
SKIP_SUFFIXES = (".pdb", ".pyc", ".pyo", ".c", ".h", ".hpp", ".lib", ".exp")
SKIP_DIRS = {"tests", "test", "__pycache__", "include", "include2"}


def _site_packages():
    for key in ("purelib", "platlib"):
        p = Path(sysconfig.get_paths()[key])
        if p.is_dir():
            return p
    raise SystemExit("找不到 site-packages")


def _should_skip(path: Path):
    if path.suffix.lower() in SKIP_SUFFIXES:
        return True
    return any(part in SKIP_DIRS for part in path.parts)


def _dep_closure(roots):
    """按已安装元数据算依赖闭包（跳过 extra 与 dev 标记）。"""
    from importlib.metadata import PackageNotFoundError, distribution

    seen, todo, missing = set(), list(roots), []
    while todo:
        raw = todo.pop()
        name = raw.strip()
        if not name:
            continue
        key = name.lower().replace("_", "-")
        if key in seen:
            continue
        seen.add(key)
        try:
            dist = distribution(name)
        except PackageNotFoundError:
            missing.append(name)
            continue
        for req in (dist.requires or []):
            marker = req.split(";", 1)[1] if ";" in req else ""
            if "extra" in marker:
                continue
            # 只取开头的包名：`Shapely (>=2.0)` / `numpy>=2` / `protobuf>=4.25.8` 都要能认
            m = re.match(r"[A-Za-z0-9_.\-]+", req.strip())
            if m:
                todo.append(m.group(0))
    return seen, missing


def _top_level_dirs(closure):
    """发行包名 → 顶层可导入目录。

    `packages_distributions()` 的方向是 **模块名 → [发行包名]**，所以必须遍历它去
    反查（早期写成 `mapping.get(dist)` 直接查表，结果 cv2 / yaml / PIL 全漏，
    组件装上却 import 失败）。
    """
    from importlib.metadata import packages_distributions

    want = {c.lower().replace("-", "_") for c in closure}
    tops = set()
    for mod, dists in packages_distributions().items():
        for d in dists:
            if d.lower().replace("-", "_") in want:
                tops.add(mod)
    return sorted(tops)


def _collect(sp):
    files = []
    closure, missing = _dep_closure(ROOTS)
    tops = _top_level_dirs(closure)
    if not tops:
        raise SystemExit("解析不到依赖的顶层模块（元数据缺失？构建机没装依赖？）")
    for name in tops:
        pkg = sp / name
        if pkg.is_dir():
            for f in pkg.rglob("*"):
                if f.is_file() and not _should_skip(f.relative_to(sp)):
                    files.append((f, "site-packages/" + str(f.relative_to(sp)).replace("\\", "/")))
            continue
        # 单文件模块（`six.py` 这种）：早期只处理目录，导致 six 漏打，
        # 症状是 import 通过、**构造 RapidOCR 时才**报 No module named 'six'
        # （所以"装完能 import"不等于"能用"）。
        single = sp / (name + ".py")
        if single.is_file():
            files.append((single, "site-packages/" + single.name))
    # **同级的 `*.libs` 目录必须一起打**：numpy 的 C 扩展要靠 `numpy.libs/` 里的
    # OpenBLAS DLL（Windows 上 DLL 搜索路径按包所在目录推导）。漏了它的症状是
    # "装完能 import 名字、一 import 就 ImportError: numpy C-extensions failed"——
    # 实测就是漏了这一层，组件装上了但用不了。
    for libs in sorted([sp / (n + ".libs") for n in tops if (sp / (n + ".libs")).is_dir()]):
        for f in libs.rglob("*"):
            if f.is_file() and not _should_skip(f.relative_to(sp)):
                files.append((f, "site-packages/" + str(f.relative_to(sp)).replace("\\", "/")))
    # 顶层 dist-info（保留许可证信息，便于合规审计）
    for di in sp.glob("*.dist-info"):
        for f in (di / "LICENSE", di / "METADATA"):
            if f.is_file():
                files.append((f, "site-packages/" + str(f.relative_to(sp)).replace("\\", "/")))
    return files


# cv2/__init__.py 的 numpy 探测补丁（2026-11-01 实测踩坑）：
# 它第 12 行 `import numpy.core.multiarray` 是 numpy 1.x 时代的写法。宿主是
# PyInstaller 冻结引擎时，引擎自带的 numpy（给 NER 用，不能排除）没有
# `numpy/core` 兼容垫片——分析器只收集被静态引用的模块，垫片没人引用就不进包。
# 组件自己的 numpy 带垫片，但只要面板进程先导入了冻结 numpy，cv2 拿到的就是
# 没垫片的那个 → ModuleNotFoundError → 自检失败回滚。退到 `numpy._core`
# （numpy≥2 的真实位置，探测等价）即可。
_CV2_LEGACY = b"import numpy.core.multiarray"
_CV2_FALLBACK = (
    b"try:\n"
    b"        import numpy.core.multiarray\n"
    b"    except ImportError:\n"
    b"        import numpy._core.multiarray  # numpy>=2 host without the core shim\n"
)


def _patch_stream(name, data):
    """写入 zip 前的按文件补丁钩子。目前只有 cv2 一处。"""
    if name == "site-packages/cv2/__init__.py" and _CV2_LEGACY in data:
        return data.replace(_CV2_LEGACY, _CV2_FALLBACK, 1)
    return data


def _expand_merge_args(patterns):
    """展开 --merge 参数里的通配符。

    bash 会自行展开 `dist_ocr/*.json`，但 **PowerShell 不会**（原样传字面量，
    脚本内 Path() 直接报错）——文档里的示例命令在 Windows 上必须也能跑。
    含通配符且没被 shell 展开时，这里自己 glob；已是具体路径则原样返回。
    """
    out = []
    for p in patterns:
        if any(ch in p for ch in "*?["):
            hits = sorted(glob.glob(p))
            if not hits:
                raise SystemExit("没有匹配到任何清单片段：%s" % p)
            out.extend(hits)
        else:
            out.append(p)
    return out


def merge_fragments(paths):
    """把各平台的清单片段合并成多平台清单。版本号不一致直接报错。"""
    version, packages = None, {}
    for p in paths:
        frag = json.loads(Path(p).read_text(encoding="utf-8"))
        if version is None:
            version = frag["version"]
        elif frag["version"] != version:
            raise SystemExit("版本不一致：%s 是 %s，其它是 %s" % (p, frag["version"], version))
        key = frag["platform"]
        if key in packages:
            raise SystemExit("平台重复：%s" % key)
        packages[key] = {k: frag[k] for k in ("url", "sha256", "size")}
    if not packages:
        raise SystemExit("没有可合并的片段")
    return {"version": version, "packages": dict(sorted(packages.items()))}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", help="组件版本号，例如 1.2.3")
    ap.add_argument("--url-prefix", default="", help="清单里的下载前缀（默认留空由发布方填）")
    ap.add_argument("--out", default=str(DIST))
    ap.add_argument("--merge", nargs="+", help="合并各平台的 .json 片段")
    ap.add_argument("--out-manifest", default="latest-ocr.json")
    args = ap.parse_args(argv)

    if args.merge:
        man = merge_fragments(_expand_merge_args(args.merge))
        Path(args.out_manifest).write_text(json.dumps(man, ensure_ascii=False, indent=2) + "\n",
                                           encoding="utf-8")
        print("merged %d platform(s) -> %s" % (len(man["packages"]), args.out_manifest))
        return 0
    if not args.version:
        ap.error("--version is required unless --merge is given")

    sp = _site_packages()
    files = _collect(sp)
    if not files:
        raise SystemExit("没收集到任何文件（构建机先 pip install -r requirements-ocr.txt）")

    import ocr_runtime
    plat = ocr_runtime.platform_key()
    name = "MaskitOCR-%s-%s.zip" % (args.version, plat)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / name

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for src, arc in files:
            # 只有需要补丁的小文本文件走内存改写，其余直接落盘（87MB 里六道门
            # 是二进制，逐个 read_bytes 纯浪费）。
            if arc == "site-packages/cv2/__init__.py":
                z.writestr(arc, _patch_stream(arc, Path(src).read_bytes()))
            else:
                z.write(src, arc)

    payload = out.read_bytes()
    manifest = {
        "version": args.version,
        "url": (args.url_prefix.rstrip("/") + "/" + name) if args.url_prefix else name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "platform": plat,
    }
    frag = out.with_suffix(".json")
    frag.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("built: %s (%.1f MB, %d files)" % (out, len(payload) / 1048576, len(files)))
    print("fragment: %s" % frag)
    print("各平台构建完后用 --merge 合并成 latest-ocr.json。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
