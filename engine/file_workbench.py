"""文件脱敏工作台 · 任务内核（file-workbench-kernel，2026-11-24）。

职责：任务存储、状态机、队列与并发、进度、取消、TTL 清理、命中注册表、载体分发接口。
载体扫描/应用引擎（OOXML/PDF/图片）由后续任务注册进来；本模块只守内核纪律：

  · 状态机跃迁合法性（G741）；
  · 队列与并发 admission（G742）；
  · TTL 与孤儿清理（G749）；
  · fail-closed 与隐私（G750）：未注册/扫不了的载体一律失败，绝不产出原文件冒充成品；
    不写 shield-events；命中注册表只在内存；历史不存真实文件名/原文。

引擎隔离（G745/G746）在 transparent.file_store_scope 内实现，本模块经它执行扫描，
并在任务结束/取消时调 transparent.file_suffix_unregister 精确清理本任务后缀。

任务态在内存（引擎重启即失，未完成任务标失败）；磁盘只落 src.bin/staged/页图/成品，
原名仅存 meta.json 供展示。历史摘要落 file_job_store（DATA_ROOT/file-jobs.json）。
"""

import os
import time
import secrets
import hashlib
import threading
from dataclasses import dataclass, field
from pathlib import Path

# ── 状态枚举（G741：取值固定，不得自由发挥）──────────────────────────────────
ST_CREATED = "created"
ST_PROBING = "probing"
ST_READY = "ready"
ST_QUEUED = "queued"
ST_SCANNING = "scanning"
ST_REVIEW = "awaiting_review"
ST_APPLYING = "applying"
ST_DONE = "done"
ST_FAILED = "failed"
ST_CANCELED = "canceled"
ST_EXPIRED = "expired"

STATES = frozenset({
    ST_CREATED, ST_PROBING, ST_READY, ST_QUEUED, ST_SCANNING, ST_REVIEW,
    ST_APPLYING, ST_DONE, ST_FAILED, ST_CANCELED, ST_EXPIRED,
})
_TERMINAL = frozenset({ST_DONE, ST_FAILED, ST_CANCELED, ST_EXPIRED})
# 正在干活的状态：TTL 不打断进行中的扫描/应用（G749）。
_ACTIVE = frozenset({ST_QUEUED, ST_SCANNING, ST_APPLYING})
# TTL 档位（分钟）：待确认 60（可配）/ 完成 30 / 失败 10（G749）。
DONE_TTL_MIN = 30
FAILED_TTL_MIN = 10

# 操作允许态（G741）。其余组合一律 409。
OP_STATES = {
    "scan": frozenset({ST_READY, ST_REVIEW, ST_DONE}),
    "apply": frozenset({ST_REVIEW}),
    "cancel": frozenset({ST_QUEUED, ST_SCANNING, ST_APPLYING}),
    "download": frozenset({ST_DONE}),
}

# ── 错误码（FILE_74xx，与规约守卫矩阵一一对应）──────────────────────────────
E_STATE = "FILE_7401"        # job_state_conflict / 409
E_QUEUE_FULL = "FILE_7402"   # job_queue_full / 429
E_TOO_LARGE = "FILE_7403"    # file_too_large / 413
E_SPOOL = "FILE_7404"        # 上传落盘位置违规
E_ISOLATION = "FILE_7405"    # 隔离零污染
E_SUFFIX = "FILE_7406"       # 后缀互避
E_NONCE = "FILE_7407"        # nonce_invalid / 403
E_SAVE_DEST = "FILE_7408"    # save_dest_invalid / 400
E_CLEANUP = "FILE_7409"      # TTL/孤儿清理
E_FAILCLOSED = "FILE_7410"   # fail-closed/隐私
E_PATH_MODE = "FILE_7411"    # path 门控 / 400
E_CONFIG = "FILE_7412"       # 配置键归一
E_NOT_FOUND = "job_not_found"
E_UNSUPPORTED = "file_type_unsupported"


class FileWorkbenchError(Exception):
    """带错误码与 HTTP 状态的工作台异常。panel 路由据此回 JSON。"""

    def __init__(self, code, http=400, message=""):
        super().__init__(message or code)
        self.code = code
        self.http = http
        self.message = message or code


@dataclass
class FileJob:
    id: str
    status: str = ST_CREATED
    carrier: str = ""
    filename: str = ""          # 展示用原名（仅内存/meta，不进历史）
    size: int = 0
    page_count: object = None
    mode: str = "auto"
    progress: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    hit_count: int = 0
    position: object = None     # 排队排位
    error: str = ""
    created_at: float = 0.0
    expires_at: float = 0.0
    source_path: str = ""       # 桌面 path 模式的源文件（save 守卫用）

    def snapshot(self):
        return {
            "id": self.id, "status": self.status, "carrier": self.carrier,
            "filename": self.filename, "size": self.size, "page_count": self.page_count,
            "mode": self.mode, "progress": self.progress, "coverage": self.coverage,
            "warnings": self.warnings, "hit_count": self.hit_count, "position": self.position,
            "error": self.error, "created_at": self.created_at, "expires_at": self.expires_at,
        }


@dataclass
class FileHit:
    hit_id: str
    token: str
    label: str
    source: str = "builtin"     # builtin | custom | ner
    original: object = None     # 凭据类 API 不返回
    preview: str = ""
    digest: str = ""
    count: int = 1
    locations: list = field(default_factory=list)
    editable: bool = True
    can_keep: bool = True
    credential: bool = False

    def api_view(self):
        d = {
            "hit_id": self.hit_id, "token": self.token, "label": self.label,
            "source": self.source, "count": self.count, "locations": self.locations,
            "editable": self.editable, "can_keep": self.can_keep,
        }
        if self.credential:
            d["preview"] = self.preview
            d["digest"] = self.digest
        else:
            d["original"] = self.original
        return d


def name_preview(filename):
    """历史只存打码文件名：`***.ext`（G750：不存真实文件名）。

    刻意**不保留**任何真实字符：旧实现留前 2 字（「工资***.xlsx」），
    对「工资单-2026.docx」这类文件名已足够推断出原文件，与 G750 的声明对不上。
    扩展名保留是为了让历史列表还能看出载体类型。
    """
    name = os.path.basename(filename or "")
    ext = os.path.splitext(name)[1].lstrip(".")
    return ("***." + ext) if ext else "***"


def file_digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class JobManager:
    """任务内核。线程安全：任务态由 _lock 保护；扫描重活在工作线程，不持任务锁。"""

    def __init__(self, data_root, cfg=None, history=None, concurrency=1, queue_max=8,
                 review_ttl_min=60, executor=None, cfg_loader=None):
        self._lock = threading.RLock()
        self._jobs = {}
        self._registries = {}      # job_id -> {orig: FileHit}（内存，不落盘）
        self._carriers = {}        # carrier -> {"scan": fn, "apply": fn}
        self._queue = []           # 等待扫描的 job_id
        self._active = 0
        self._cancel_flags = {}    # job_id -> threading.Event
        self.data_root = Path(data_root)
        self.jobs_dir = self.data_root / "file-jobs"
        self.cfg = cfg or {}
        self._cfg_loader = cfg_loader
        self.history = history
        self.concurrency = max(1, min(2, int(concurrency)))   # G742 钳制 [1,2]
        self.queue_max = int(queue_max)
        self.review_ttl_min = int(review_ttl_min)
        # executor(fn)：生产用线程；测试可注入同步执行器以便确定性验收。
        self._executor = executor or (lambda fn: threading.Thread(target=fn, daemon=True).start())
        # 周期清扫（G749）：daemon 线程每 60s 清到期目录；stop 事件供关闭/测试用。
        self._sweep_stop = threading.Event()
        self._sweeper = threading.Thread(target=self._sweep_loop, daemon=True)
        self._sweeper.start()

    def current_cfg(self):
        if self._cfg_loader is not None:
            try:
                return self._cfg_loader() or {}
            except Exception:
                return self.cfg or {}
        return self.cfg or {}

    def _sweep_loop(self):
        while not self._sweep_stop.wait(60):
            try:
                self.sweep_ttl()
            except Exception:
                pass

    def stop(self):
        self._sweep_stop.set()

    # ---- 载体注册（T2/T3 接入）----
    def register_carrier(self, carrier, scan_fn, apply_fn):
        with self._lock:
            self._carriers[carrier] = {"scan": scan_fn, "apply": apply_fn}

    # ---- 目录 ----
    def job_dir(self, job_id):
        return self.jobs_dir / job_id

    # ---- 创建与预检 ----
    def create_job(self, filename, size, carrier, source_path="", job_id=None):
        job_id = job_id or ("fj_" + secrets.token_hex(8))
        now = time.time()
        job = FileJob(id=job_id, status=ST_PROBING, carrier=carrier, filename=filename,
                      size=size, created_at=now, expires_at=now + self.review_ttl_min * 60,
                      source_path=source_path)
        with self._lock:
            self._jobs[job_id] = job
            self._cancel_flags[job_id] = threading.Event()
        job._mgr = self          # 载体经此取 cfg / 命中注册表（file_carriers）
        self.job_dir(job_id).mkdir(parents=True, exist_ok=True)
        return job

    def probe_result(self, job_id, ok, page_count=None, error=""):
        """预检完成：通过转 ready，不通过转 failed（G750：扫不了不建成品）。"""
        with self._lock:
            job = self._require(job_id)
            if ok:
                job.status = ST_READY
                job.page_count = page_count
            else:
                job.status = ST_FAILED
                job.error = error or E_UNSUPPORTED
                job.expires_at = time.time() + FAILED_TTL_MIN * 60   # 失败档 10 分钟
        return job

    # ---- 查询 ----
    def _require(self, job_id):
        job = self._jobs.get(job_id)
        if job is None:
            raise FileWorkbenchError(E_NOT_FOUND, 404)
        return job

    def get_job(self, job_id):
        with self._lock:
            return self._require(job_id)

    def list_jobs(self):
        with self._lock:
            return [j.snapshot() for j in self._jobs.values()]

    def set_progress(self, job_id, stage, current, total):
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None and job.status == ST_SCANNING:
                job.progress = {
                    "stage": str(stage),
                    "current": int(current),
                    "total": max(1, int(total)),
                }

    def hits(self, job_id):
        with self._lock:
            self._require(job_id)
            reg = self._registries.get(job_id) or {}
            return [h.api_view() for h in reg.values()]

    # ---- 状态机守卫（G741）----
    def _check_op(self, job, op):
        # @guard G741 非法跃迁一律 FILE_7401 / 409，绝不放行。
        allowed = OP_STATES.get(op)
        if allowed is None or job.status not in allowed:
            raise FileWorkbenchError(E_STATE, 409,
                                     "当前状态 %s 不允许 %s" % (job.status, op))

    # ---- 队列 admission（G742）----
    def _admit(self, job):
        """返回 (run_now, position)。队列满抛 FILE_7402；不得「429 但已排队」。"""
        # @guard G742 并发钳 [1,2]；队满才 429，否则进队回 position。
        if self._active < self.concurrency:
            self._active += 1
            job.status = ST_SCANNING
            job.position = None
            return True, None
        if len(self._queue) >= self.queue_max:
            raise FileWorkbenchError(E_QUEUE_FULL, 429)
        self._queue.append(job.id)
        job.status = ST_QUEUED
        job.position = len(self._queue)
        return False, job.position

    def request_scan(self, job_id, mode="auto", scan_embedded=True):
        with self._lock:
            job = self._require(job_id)
            self._check_op(job, "scan")
            job.mode = mode
            job._scan_embedded = bool(scan_embedded)
            run_now, position = self._admit(job)
        if run_now:
            self._executor(lambda: self._run_scan(job_id, job._scan_embedded))
        return job

    def _run_scan(self, job_id, scan_embedded):
        import transparent as tr
        cancel = None
        try:
            # 每次扫描前强制热重载配置（与扩展/试验台同口径），确保冷启动及面板修改的
            # 敏感词/白名单/规则开关即时生效；必须在进入隔离作用域之前执行。
            tr._maybe_reload(force=True)
            cfg_now = self.current_cfg()
            with self._lock:
                self.cfg = cfg_now
                job = self._require(job_id)
                carrier = self._carriers.get(job.carrier)
            # G750：未注册载体一律失败，绝不产出原文件冒充成品。
            # @guard G750 fail-closed：扫不了就失败，不写 shield-events，注册表只在内存。
            if carrier is None:
                self._fail(job_id, E_FAILCLOSED)
                return
            src = self.job_dir(job_id) / "src.bin"
            staged = self.job_dir(job_id) / "staged.bin"
            cancel = self._cancel_flags.get(job_id)
            # G745/G746：扫描在隔离作用域内，全局表零污染；后缀登记进活跃注册表。
            # 启用文件任务耐心模式（patient=True）：宁愿慢些等完，也绝不因实时 2s 速率桶截断而漏脱；
            # 若仍发生任何 NER 降级/跳过，必显式记入 warnings 与 coverage。
            ner_skips = {}
            with tr.file_store_scope(job_id), tr._ner_doc_budget(
                3600.0, cancel_event=cancel, patient=True
            ):
                outcome = carrier["scan"](job, str(src), str(staged),
                                          {"scan_embedded": scan_embedded, "mode": job.mode},
                                          cancel)
                try:
                    import ner_engine
                    ner_skips = ner_engine.request_skips(reset=True) or {}
                except Exception:
                    ner_skips = {}
            with self._lock:
                job = self._require(job_id)
                if cancel is not None and cancel.is_set():
                    self._finish_cancel(job_id)
                    return
                reg = {}
                for h in (outcome.get("hits") or []):
                    reg[h.original if not h.credential else h.token] = h
                self._registries[job_id] = reg
                job.hit_count = len(reg)
                cov = dict(outcome.get("coverage") or {})
                warns = list(outcome.get("warnings") or [])
                real_skips = {k: int(v) for k, v in ner_skips.items() if k != "cancelled" and int(v or 0) > 0}
                if real_skips:
                    cov["ner_skipped_chunks"] = sum(real_skips.values())
                    if "ner_degraded" not in warns:
                        warns.append("ner_degraded")
                job.coverage = cov
                job.warnings = warns
                job.progress = {}
                job.status = ST_REVIEW
                ttl_min = int(self.cfg.get("files_review_ttl_min", self.review_ttl_min) or self.review_ttl_min)
                job.expires_at = time.time() + ttl_min * 60
        except Exception as e:
            if cancel is not None and cancel.is_set():
                self._finish_cancel(job_id)
                return
            self._fail(job_id, getattr(e, "code", E_FAILCLOSED))
        finally:
            tr.file_suffix_unregister(job_id)
            self._release_slot(job_id)

    def _release_slot(self, job_id):
        with self._lock:
            if self._active > 0:
                self._active -= 1
            nxt = self._queue.pop(0) if self._queue else None
            if nxt is not None:
                j = self._jobs.get(nxt)
                if j is not None and j.status == ST_QUEUED:
                    self._active += 1
                    j.status = ST_SCANNING
                    j.position = None
                    se = bool(getattr(j, "_scan_embedded", True))
                    self._executor(lambda jid=nxt, _se=se: self._run_scan(jid, _se))
            # 重排剩余排位
            for i, qid in enumerate(self._queue, 1):
                q = self._jobs.get(qid)
                if q is not None:
                    q.position = i

    def _fail(self, job_id, code):
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None and job.status not in _TERMINAL:
                job.status = ST_FAILED
                job.error = code
                job.expires_at = time.time() + FAILED_TTL_MIN * 60   # 失败档 10 分钟
        self._record_history(job_id)

    def _finish_cancel(self, job_id):
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.status = ST_CANCELED
        self._cleanup_dir(job_id)
        self._record_history(job_id)

    # ---- 应用 ----
    def request_apply(self, job_id, edits=None, redactions=None, options=None):
        with self._lock:
            job = self._require(job_id)
            self._check_op(job, "apply")
            job.status = ST_APPLYING
        self._executor(lambda: self._run_apply(job_id, edits, redactions, options))
        return job

    def _run_apply(self, job_id, edits, redactions, options):
        try:
            with self._lock:
                job = self._require(job_id)
                carrier = self._carriers.get(job.carrier)
            if carrier is None:
                self._fail(job_id, E_FAILCLOSED)
                return
            staged = self.job_dir(job_id) / "staged.bin"
            out_dir = self.job_dir(job_id) / "out"
            out_dir.mkdir(parents=True, exist_ok=True)
            out = out_dir / ("masked" + (os.path.splitext(job.filename)[1] or ".bin"))
            coverage = carrier["apply"](job, str(staged), str(out), edits or [],
                                        redactions or [], options or {})
            with self._lock:
                job = self._require(job_id)
                if isinstance(coverage, dict):
                    merged_cov = dict(job.coverage or {})
                    merged_cov.update(coverage)
                    job.coverage = merged_cov
                if isinstance(coverage, dict) and coverage.get("warnings"):
                    merged = list(job.warnings or [])
                    for w in coverage["warnings"]:
                        if w not in merged:
                            merged.append(w)
                    job.warnings = merged
                job.status = ST_DONE
                job.expires_at = time.time() + 30 * 60   # 完成档 30 分钟
            self._record_history(job_id)
        except Exception as e:
            self._fail(job_id, getattr(e, "code", E_FAILCLOSED))

    # ---- 取消（G741）----
    def cancel(self, job_id):
        with self._lock:
            job = self._require(job_id)
            self._check_op(job, "cancel")
            flag = self._cancel_flags.get(job_id)
            if flag is not None:
                flag.set()
            if job.status == ST_QUEUED:
                # 排队任务立即生效：移出队列。
                if job_id in self._queue:
                    self._queue.remove(job_id)
                job.status = ST_CANCELED
                self._cleanup_dir(job_id)
                self._record_history(job_id)
                for i, qid in enumerate(self._queue, 1):
                    q = self._jobs.get(qid)
                    if q is not None:
                        q.position = i
        return job

    # ---- 下载态校验（G747/G750）----
    def check_download(self, job_id):
        with self._lock:
            job = self._require(job_id)
            self._check_op(job, "download")
            return job

    # ---- 删除（G749：先目录后记录）----
    def delete(self, job_id):
        # @guard G749 先清目录后删记录，Windows 句柄占用退避重试。
        with self._lock:
            job = self._jobs.get(job_id)
        # 未登记的 id 一律当无操作：job_id 来自 URL，旧实现不先校验就清目录，
        # 在 `..` 这类相对段上会把清理范围扩到 jobs_dir 之外（2026-11-26 实测
        # DELETE /api/files/jobs/.. 把 DATA_ROOT 整棵删掉：配置、事件库、证书）。
        if job is None:
            return False
        self._cleanup_dir(job_id)
        with self._lock:
            self._jobs.pop(job_id, None)
            self._registries.pop(job_id, None)
            self._cancel_flags.pop(job_id, None)
            if job_id in self._queue:
                self._queue.remove(job_id)
        import transparent as tr
        tr.file_suffix_unregister(job_id)
        return job is not None

    def _cleanup_dir(self, job_id):
        import shutil
        d = self.job_dir(job_id)
        # 第二道防线：即使调用方绕过了 delete 的存在性校验，清理目标也必须真的是
        # jobs_dir 的直接子目录。`jobs_dir / ".."` 会解析到上个目录（DATA_ROOT），
        # rmtree 一下就删到配置/事件库/证书（实测可经 HTTP 命中）。
        try:
            if d.resolve().parent != self.jobs_dir.resolve():
                return
        except OSError:
            return
        # Windows 句柄占用退避重试（参考 local-dev-deploy.ps1）。
        for attempt in range(6):
            try:
                if d.exists():
                    shutil.rmtree(d)
                return
            except OSError:
                time.sleep(0.2 * (attempt + 1))

    # ---- TTL 与孤儿清理（G749）----
    def sweep_ttl(self, now=None):
        # @guard G749 待确认 60 / 完成 30 / 失败 10 分钟到期转 expired 并清目录。
        # 进行中（queued/scanning/applying）不打断；canceled/expired 已清过跳过。
        now = now or time.time()
        with self._lock:
            for job in list(self._jobs.values()):
                if job.status in _ACTIVE or job.status in (ST_CANCELED, ST_EXPIRED):
                    continue
                if job.expires_at and now >= job.expires_at:
                    job.status = ST_EXPIRED
                    self._cleanup_dir(job.id)
                    self._record_history(job.id)

    def startup_cleanup(self, now=None):
        # @guard G749 启动清 >24h 目录，未完成任务标失败（引擎重启即失）。
        now = now or time.time()
        # 启动清 >24h 目录；未完成任务标失败。
        if self.jobs_dir.exists():
            for d in self.jobs_dir.iterdir():
                try:
                    age = now - d.stat().st_mtime
                    if age > 24 * 3600:
                        self._cleanup_dir(d.name)
                except OSError:
                    pass
        with self._lock:
            for job in self._jobs.values():
                if job.status not in _TERMINAL:
                    job.status = ST_FAILED
                    job.error = "engine_restart"
                    job.expires_at = time.time() + FAILED_TTL_MIN * 60

    # ---- 历史（G750：只存打码名与计数）----
    def _record_history(self, job_id):
        # @guard G750 历史只存打码文件名与计数，不存真实文件名/原文/命中列表。
        if self.history is None:
            return
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            summary = {
                "id": job.id, "ts": time.time(), "name_preview": name_preview(job.filename),
                "ext": os.path.splitext(job.filename)[1].lstrip("."), "size": job.size,
                "carrier": job.carrier, "mode": job.mode, "status": job.status,
                "hit_count": job.hit_count, "page_count": job.page_count,
                "cost_ms": int((time.time() - job.created_at) * 1000), "error": job.error,
            }
        self.history.append(summary)