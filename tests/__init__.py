import atexit
import shutil
import sys
import tempfile
import threading
from pathlib import Path

engine_dir = Path(__file__).resolve().parent.parent / "engine"
if str(engine_dir) not in sys.path:
    sys.path.insert(0, str(engine_dir))

# ── 测试临时目录统一回收（2026-11） ──────────────────────────────────────
# 为什么在这里、而不是逐个 TestCase 的 tearDown：38 个测试文件、81 处
# `tempfile.mkdtemp()`，逐个补清理不现实 —— 漏一处就在 %TEMP% 留下**一份
# 事件库副本**，而那是脱敏记录，不该躺在 ACL 保护目录之外。实测 2403 个
# 目录 / 275 份事件库，且每次跑门禁仍在新增。
#
# 只接管本进程通过 `tempfile.mkdtemp()` 新建的目录（这类目录的语义就是
# 「用完即弃」），退出时删除登记过的；其它进程、其它方式建的目录一概不碰。
# 删除用 `ignore_errors=True`：测试自己已清理过的目录不会因此报错。
_created = []
_created_lock = threading.Lock()
_orig_mkdtemp = tempfile.mkdtemp


def _tracked_mkdtemp(*args, **kwargs):
    path = _orig_mkdtemp(*args, **kwargs)
    with _created_lock:
        _created.append(path)
    return path


@atexit.register
def _cleanup_created_tempdirs():
    with _created_lock:
        paths = list(_created)
        _created.clear()
    for path in paths:
        shutil.rmtree(path, ignore_errors=True)


tempfile.mkdtemp = _tracked_mkdtemp
