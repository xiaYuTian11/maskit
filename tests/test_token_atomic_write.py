"""`proxy_token` 必须**原子替换**写入（2026-11-03）。

## 为什么

引擎每次启动生成新的随机 `API_TOKEN` 并写 `proxy_token` 文件，壳层
（`src-tauri/src/lib.rs` 的 `read_token`）读它注入 WebView。原实现是
`O_TRUNC` 原地覆盖：

```python
fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, API_TOKEN)      # truncate 与 write 之间存在「文件存在且为空」的窗口
```

壳层落在这个窗口里会读到空串，前端随即带空 token 请求面板 → 全是 403
`invalid_token`。真机 `engine.log` 里每次启动后紧接着 7~19 条这种拒绝，
就是它留下的痕迹。前端虽有重读重试（`frontend/src/lib/shield-fetch.ts`），
但那是补偿而非消除。

改为「写临时文件 + `os.replace`」后，读端只可能看到**旧 token 或新 token**，
不存在空/半截的中间态。

## 本文件守住什么

1. **动态**：并发读写时，读到的内容只能是两个完整 token 之一，永不为空/半途。
2. **静态**：`panel.py` 的 token 写入路径必须仍用 `os.replace`——防止有人
   后来「顺手简化」回原地覆盖（那个改动在单线程测试里完全看不出问题）。
"""
import os
import sys
import time
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 明显伪造的样例（AGENTS.md §3 第 9 条：不得写凭据字面量）
TOKEN_A = "test" + "-token" + "-AAAA" + "0001"
TOKEN_B = "test" + "-token" + "-BBBB" + "0002"


def _atomic_write(path: Path, value: str) -> None:
    """与 `engine/panel.py` 中 token 落盘同一写法（含 Windows 句柄重试）。"""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, value.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, 0o600)
    last_err: Exception | None = None
    for _ in range(20):
        try:
            os.replace(str(tmp), str(path))
            return
        except PermissionError as exc:  # Windows: 读端持有句柄时 WinError 5
            last_err = exc
            time.sleep(0.05)
    raise last_err if last_err else RuntimeError("replace failed")


class TokenAtomicWriteTests(unittest.TestCase):
    def test_concurrent_reader_never_sees_empty_or_partial(self):
        """写端持续替换，读端持续读：只允许读到两个完整值之一。"""
        with tempfile.TemporaryDirectory(prefix="maskit-token-") as d:
            path = Path(d) / "proxy_token"
            _atomic_write(path, TOKEN_A)

            stop = threading.Event()
            bad: list[str] = []

            def reader():
                while not stop.is_set():
                    try:
                        got = path.read_text(encoding="utf-8")
                    except (FileNotFoundError, PermissionError):
                        # 读不到不算「读到脏数据」：生产里 Rust `read_to_string` 失败
                        # 会走「无 token」分支（前端等 400ms 重读），不是拿空串去请求。
                        # 这里只断言「成功读到的时候，内容必须是完整的两个值之一」。
                        continue
                    if got not in (TOKEN_A, TOKEN_B):
                        bad.append(repr(got))

            t = threading.Thread(target=reader, daemon=True)
            t.start()
            try:
                for i in range(80):
                    _atomic_write(path, TOKEN_B if i % 2 else TOKEN_A)
            finally:
                stop.set()
                t.join(timeout=5)

            self.assertEqual(bad, [], f"读端看到了非完整 token（前 3 条）：{bad[:3]}")
            self.assertIn(path.read_text(encoding="utf-8"), (TOKEN_A, TOKEN_B))

    def test_no_tmp_file_left_behind(self):
        """成功后不得留下 .tmp 残留（否则数据目录里多一个含真 token 的副本）。"""
        with tempfile.TemporaryDirectory(prefix="maskit-token-") as d:
            path = Path(d) / "proxy_token"
            _atomic_write(path, TOKEN_A)
            leftovers = [p.name for p in Path(d).iterdir() if p.name.endswith(".tmp")]
            self.assertEqual(leftovers, [])

    def test_token_file_is_not_world_readable(self):
        """0600：同机其他本地用户不能读到面板令牌。"""
        if sys.platform == "win32":
            self.skipTest("Windows 上 mode 只影响只读位，ACL 由数据目录单独收紧")
        with tempfile.TemporaryDirectory(prefix="maskit-token-") as d:
            path = Path(d) / "proxy_token"
            _atomic_write(path, TOKEN_A)
            self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")


class PanelUsesAtomicReplaceTests(unittest.TestCase):
    """静态守门：`panel.py` 里 token 落盘必须是 os.replace，不能退回原地覆盖。"""

    def test_panel_writes_token_via_replace(self):
        src = (ROOT / "engine" / "panel.py").read_text(encoding="utf-8")
        # 定位 token 写入块：从 `proxy_token` 变量赋值到 atexit.register 之间
        start = src.find('token_path = ROOT / "proxy_token"')
        self.assertGreater(start, -1, "找不到 token 落盘代码块（被重写了？）")
        end = src.find("atexit.register(shutdown)", start)
        self.assertGreater(end, start, "找不到 token 落盘代码块结尾")
        block = src[start:end]
        self.assertIn("os.replace(", block,
                      "token 落盘必须用 os.replace 原子替换，不能退回 O_TRUNC 原地覆盖")
        # 直接以写模式打开目标文件 = 回到旧的原地覆盖写法（truncate/write 之间有窗口）。
        self.assertNotIn("os.open(str(token_path)", block,
                         "token 落盘不得直接以写模式打开 token_path（会造出空文件窗口）")


if __name__ == "__main__":
    unittest.main()
