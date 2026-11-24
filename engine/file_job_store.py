"""文件脱敏工作台 · 任务历史摘要（file-workbench-kernel，2026-11-24）。

最近 200 条任务摘要，原子写（临时文件 + os.replace）。**只存打码文件名与计数**
（G750）：不存真实文件名、原文、命中列表。落 DATA_ROOT/file-jobs.json。
"""

import os
import json
import threading
from pathlib import Path

MAX_ENTRIES = 200


class HistoryStore:
    def __init__(self, data_root):
        self.path = Path(data_root) / "file-jobs.json"
        self._lock = threading.Lock()
        self._entries = self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def append(self, summary):
        with self._lock:
            self._entries.append(summary)
            self._entries = self._entries[-MAX_ENTRIES:]
            self._atomic_write()

    def entries(self):
        with self._lock:
            return list(self._entries)

    def _atomic_write(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._entries, f, ensure_ascii=False)
        os.replace(tmp, self.path)