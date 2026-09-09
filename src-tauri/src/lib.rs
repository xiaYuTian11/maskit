// Data Maskit — 本地 LLM 敏感信息脱敏代理
// Copyright (C) 2026 TMW
//
// 本程序是自由软件：你可以依据自由软件基金会发布的 GNU Affero 通用公共许可证
// （版本 3）条款重新分发和/或修改它。本程序不附带任何担保。
// 详见 <https://www.gnu.org/licenses/>。

// Data Maskit — Tauri 壳层
// 方案 §4.1/§4.2/§4.4/§4.7/§12.5/§13.4：
// - sidecar 引擎进程管理（resources/engine 整体携带，非 externalBin）
// - token 经 IPC 读取（不进 HTML）
// - 就绪探测 + 崩溃自动重启 + 三段式退出

use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::Serialize;
use tauri::{AppHandle, Manager, RunEvent};

/// 引擎 API 端口（panel.py PANEL_PORT = 5801，可用 SHIELD_ENGINE_PORT 覆盖——测试隔离用）
fn engine_port() -> u16 {
    std::env::var("SHIELD_ENGINE_PORT")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .unwrap_or(5801)
}
/// 就绪等待上限（秒）
const READY_TIMEOUT_SECS: u64 = 20;
/// 崩溃自动重启：1 分钟窗口内的最大重启次数
const MAX_RESTARTS_PER_MIN: u32 = 3;
/// 假死判定：进程还活着但端口连续探测失败的次数（× 2s 轮询 = 12s 无响应才动手，
/// 避免引擎启动/重载期间的短暂不可达被误判成挂死）
const HANG_STRIKES: u32 = 6;

/// GUI 进程拉控制台子进程（taskkill / reg）必须带 CREATE_NO_WINDOW，
/// 否则每次退出清理、每次设开机自启都会闪一个黑色控制台窗口
#[cfg(windows)]
fn no_window(cmd: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW)
}

#[cfg(not(windows))]
fn no_window(cmd: &mut Command) -> &mut Command {
    cmd
}

// ========== 引擎进程状态 ==========

#[derive(Serialize, Clone)]
struct EngineState {
    ready: bool,
    /// 引擎实际监听端口（SHIELD_ENGINE_PORT 可覆盖）。前端据此拼 baseUrl——
    /// 少了这个字段，App.tsx 的 initEnginePort(s.port) 恒收到 undefined，
    /// 覆盖端口后前端仍然死打 5801
    port: u16,
    pid: Option<u32>,
    started_at: Option<u64>,
    last_error: Option<String>,
    /// Rust 侧崩溃自动重启成功时间戳（前端横幅用，epoch 秒）
    auto_recovered_at: Option<u64>,
}

struct EngineManager {
    state: Arc<Mutex<EngineState>>,
    child: Mutex<Option<Child>>,
    restart_in_flight: AtomicBool,
}

impl EngineManager {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(EngineState {
                ready: false,
                port: engine_port(),
                pid: None,
                started_at: None,
                last_error: None,
                auto_recovered_at: None,
            })),
            child: Mutex::new(None),
            restart_in_flight: AtomicBool::new(false),
        }
    }

    fn set_last_error(&self, err: &str) {
        if let Ok(mut s) = self.state.lock() {
            s.last_error = Some(err.to_string());
        }
    }

    /// 引擎 exe 路径：多候选探测（开发直跑 / bundle 安装两种布局）
    fn engine_exe(app: &AppHandle) -> Result<PathBuf, String> {
        let res = app
            .path()
            .resource_dir()
            .map_err(|e| format!("资源目录不可用: {e}"))?;
        // 新名优先、旧名兜底：更名版本与旧版本可能共存于同一台机器
        // （开发树 target/release 还留着上一次构建的产物），少了旧名会「引擎缺失」。
        const ENGINE_NAMES: [&str; 2] = ["MaskitEngine.exe", "LLMShieldEngine.exe"];
        let mut candidates = Vec::new();
        for name in ENGINE_NAMES {
            candidates.push(res.join("engine").join(name));
            candidates.push(res.join("resources").join("engine").join(name));
            candidates.push(res.join(name));
        }
        // 绝对兜底：exe 同目录
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(dir) = exe_path.parent() {
                for name in ENGINE_NAMES {
                    candidates.push(dir.join("engine").join(name));
                    candidates.push(dir.join("resources").join("engine").join(name));
                }
            }
        }
        for c in candidates {
            if c.exists() {
                return Ok(c);
            }
        }
        Err(format!("引擎缺失（已探测 {res:?} 下 engine/ 与 resources/engine/）"))
    }

    /// 拉起引擎（debug 构建不自动拉，dev 手动 `python panel.py --no-browser`；
    /// SHIELD_CLIENT_ONLY=1 时纯客户端模式，连外部引擎；
    /// 端口已有引擎监听时直接复用（升级/热切换场景，避免反复拉起失败）
    fn spawn(&self, app: &AppHandle) -> Result<(), String> {
        if cfg!(debug_assertions) || std::env::var_os("SHIELD_CLIENT_ONLY").is_some() {
            return Ok(());
        }
        if Self::port_ready() {
            if let Ok(mut s) = self.state.lock() {
                s.ready = true;
                s.last_error = None;
                // 复用已有引擎：探测并记录 pid（watchdog 存活校验 + 退出清理依赖它）
                // 曾漏设 → watchdog 一直认为「无 pid」不监控 + 退出不杀引擎
                if s.pid.is_none() {
                    if let Some(p) = pid_listening_on_port(engine_port()) {
                        s.pid = Some(p);
                    }
                }
            }
            return Ok(());
        }
        let exe = Self::engine_exe(app)?;
        let dir = exe.parent().ok_or("引擎目录解析失败")?.to_path_buf();
        // 引擎 stdout/stderr 落盘（数据目录下 engine-stdout.log）：
        // Flask access log 与 mitmdump 启动错误在此可见，排查 401/403/启动失败。
        // 引擎首启会做旧目录迁移，此处目录可能尚不存在，先建再开。
        let log_path = data_root()
            .map(|r| {
                let _ = std::fs::create_dir_all(&r);
                r.join("engine-stdout.log")
            })
            .unwrap_or_else(|| dir.join("engine-stdout.log"));
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| format!("打开引擎日志失败: {e}"))?;
        let child = Command::new(&exe)
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(log_file))
            .spawn()
            .map_err(|e| format!("拉起引擎失败: {e}"))?;
        let pid = child.id();
        if let Ok(mut c) = self.child.lock() {
            *c = Some(child);
        }
        if let Ok(mut s) = self.state.lock() {
            s.pid = Some(pid);
            s.started_at = Some(now_epoch());
            s.last_error = None;
            s.ready = false;
        }
        Ok(())
    }

    /// 就绪探测：5801 TCP 可达（300ms 超时）
    fn port_ready() -> bool {
        let addr = format!("127.0.0.1:{}", engine_port())
            .to_socket_addrs()
            .ok()
            .and_then(|mut i| i.next());
        match addr {
            Some(a) => TcpStream::connect_timeout(&a, Duration::from_millis(300)).is_ok(),
            None => false,
        }
    }

    /// 就绪轮询：等待引擎写 token 文件 + 监听 5801（上限 READY_TIMEOUT_SECS）
    fn readiness_loop(&self) {
        let start = std::time::Instant::now();
        let deadline = start + Duration::from_secs(READY_TIMEOUT_SECS);
        loop {
            if Self::port_ready() && token_candidates().iter().any(|p| p.exists()) {
                if let Ok(mut s) = self.state.lock() {
                    s.ready = true;
                    s.last_error = None;
                }
                // 引擎就绪后探测一次当前运行状态并同步托盘菜单文案
                let token = token_candidates()
                    .iter()
                    .find_map(|p| std::fs::read_to_string(p).ok())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let base = format!("http://127.0.0.1:{}", engine_port());
                if let Ok(client) = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(3))
                    .build()
                {
                    if let Some(running) = client
                        .get(format!("{base}/api/status"))
                        .header("X-Shield-Token", &token)
                        .send()
                        .ok()
                        .and_then(|r| r.json::<serde_json::Value>().ok())
                        .and_then(|v| v.get("proxy_running").cloned())
                        .and_then(|v| v.as_bool())
                    {
                        update_tray_proxy_text(running);
                    }
                }
                return;
            }
            if std::time::Instant::now() > deadline {
                if let Ok(mut s) = self.state.lock() {
                    s.ready = false;
                    s.last_error = Some(format!("引擎 {READY_TIMEOUT_SECS}s 内未就绪（5801/token）"));
                }
                return;
            }
            // 前 2 秒 50ms 极速探活，之后 200ms 探活，大幅降低就绪感知延迟
            let elapsed = start.elapsed();
            if elapsed < Duration::from_secs(2) {
                std::thread::sleep(Duration::from_millis(50));
            } else {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    /// 崩溃监控：进程退出 → 自动重启（限频）+ 记 auto_recovered_at
    ///
    /// 两类故障都要守：
    /// 1. 进程退出（try_wait 可见）；
    /// 2. **进程活着但端口不响应**（Flask 死锁 / 端口被抢 / 引擎假死）——只看 try_wait 会永远
    ///    认为"引擎健在"，前端 ready 也一直是 true，用户看到面板正常但所有请求超时。
    ///    连续 HANG_STRIKES 次端口探测失败才判定假死，然后按崩溃路径杀掉重拉。
    fn crash_watchdog(self: Arc<Self>) {
        let mut restarts: Vec<u64> = Vec::new();
        let mut strikes: u32 = 0;
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let exited = {
                let mut c = match self.child.lock() {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                match c.as_mut() {
                    Some(child) => matches!(child.try_wait(), Ok(Some(_))),
                    None => false,
                }
            };
            if self.restart_in_flight.load(Ordering::SeqCst) {
                continue;
            }
            // 假死检测：进程在但端口不通，连续多次才认账
            let hung = if exited {
                false
            } else {
                let alive = self.state.lock().ok().and_then(|s| s.pid).is_some();
                if alive && !Self::port_ready() {
                    strikes += 1;
                    strikes >= HANG_STRIKES
                } else {
                    strikes = 0;
                    false
                }
            };
            if !exited && !hung {
                continue;
            }
            if hung {
                strikes = 0;
                self.set_last_error("引擎端口无响应（疑似假死），正在强制重启");
                // 假死进程不会自己退出，必须先杀进程树再重拉，否则新引擎抢不到 5801
                let pid = self.state.lock().ok().and_then(|s| s.pid);
                if let Some(pid) = pid {
                    #[cfg(target_os = "windows")]
                    let _ = no_window(&mut Command::new("taskkill"))
                        .args(["/F", "/T", "/PID", &pid.to_string()])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                    #[cfg(not(target_os = "windows"))]
                    let _ = pid; // macOS/Linux: 用 libc kill 或直接依赖引擎自退出
                }
                std::thread::sleep(Duration::from_millis(800));
            }
            // 进程退出：清理引用（锁 poison 时不能 unwrap——watchdog 线程一 panic
            // 崩溃恢复能力就永久静默失效，这正是它要防的故障本身）
            if let Ok(mut c) = self.child.lock() {
                *c = None;
            }
            if let Ok(mut s) = self.state.lock() {
                s.pid = None;
                s.ready = false;
            }
            // 限频：1 分钟内最多 MAX_RESTARTS_PER_MIN 次
            let now = now_epoch();
            restarts.retain(|t| now.saturating_sub(*t) < 60);
            if restarts.len() >= MAX_RESTARTS_PER_MIN as usize {
                self.set_last_error("引擎频繁崩溃，已暂停自动重启（1 分钟后重试）");
                continue;
            }
            restarts.push(now);
            self.restart_in_flight.store(true, Ordering::SeqCst);
            match self.spawn(app_handle()) {
                Ok(_) => {
                    if let Ok(mut s) = self.state.lock() {
                        s.auto_recovered_at = Some(now);
                    }
                    // 就绪即清错：auto_recovered_at 已记录这次恢复（Dashboard 用它提示），
                    // last_error 留着会让顶栏一直挂红色「引擎错误」，与「已恢复」自相矛盾。
                    self.readiness_loop();
                    if let Ok(mut s) = self.state.lock() {
                        if s.ready {
                            s.last_error = None;
                        }
                    }
                }
                Err(e) => self.set_last_error(&e),
            }
            self.restart_in_flight.store(false, Ordering::SeqCst);
        }
    }

    /// 三段式退出：HTTP /api/proxy/stop 优雅停 → 3s 超时 → taskkill /T /F
    fn shutdown(&self) {
        let pid = self.state.lock().ok().and_then(|s| s.pid);
        if pid.is_none() {
            return;
        }
        // 1) 优雅停：带 token 调引擎 stop（stop_mode 语义 + env 还原）
        let _ = Self::http_stop_graceful();
        // 2) 等 3s 让引擎 shutdown() 收尾（写线程/env 还原）
        std::thread::sleep(Duration::from_secs(3));
        // 3) 强杀进程树（mitmdump 多代子进程）
        if let Some(pid) = pid {
            #[cfg(target_os = "windows")]
            let _ = no_window(&mut Command::new("taskkill"))
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            #[cfg(not(target_os = "windows"))]
            let _ = pid; // macOS/Linux 依赖引擎自退出（优雅停已发）
        }
    }

    fn http_stop_graceful() -> Result<(), String> {
        let token = token_candidates()
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if token.is_empty() {
            return Err("token 为空，跳过优雅停".into());
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| e.to_string())?;
        client
            .post(format!("http://127.0.0.1:{}/api/proxy/stop", engine_port()))
            .header("X-Shield-Token", token)
            .send()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

// 全局 AppHandle：崩溃监控线程重拉引擎时使用（setup 时初始化）
static APP_HANDLE: OnceLock<AppHandle> = OnceLock::new();

// 全局托盘「启动/停止代理」菜单项引用：用于动态切换文案
static TRAY_TOGGLE_ITEM: OnceLock<tauri::menu::MenuItem<tauri::Wry>> = OnceLock::new();

pub fn update_tray_proxy_text(running: bool) {
    if let Some(item) = TRAY_TOGGLE_ITEM.get() {
        let text = if running { "停止代理" } else { "启动代理" };
        let _ = item.set_text(text);
    }
}

fn app_handle() -> &'static AppHandle {
    APP_HANDLE.get().expect("AppHandle 未初始化")
}

/// 跨平台可写数据目录，必须与 panel.py `_default_data_root()` 完全一致：
/// Windows `%APPDATA%\Maskit` / macOS `~/Library/Application Support/Maskit`
/// / Linux `$XDG_DATA_HOME/maskit`（缺省 `~/.local/share/maskit`）。
/// 两侧不一致会让壳读不到引擎写的 proxy_token，表现为「引擎起来了但面板 401」。
fn data_root() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok().map(|a| PathBuf::from(a).join("Maskit"))
    }
    #[cfg(target_os = "macos")]
    {
        dirs_home().map(|h| h.join("Library").join("Application Support").join("Maskit"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        std::env::var("XDG_DATA_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| dirs_home().map(|h| h.join(".local").join("share")))
            .map(|b| b.join("maskit"))
    }
}

/// 更名前的数据目录（1.5.66 及以前）。迁移失败（跨盘/占用）时壳仍要能读到 token，
/// 所以候选路径里保留它作为回退，而不是直接假定迁移一定成功。
fn legacy_data_root() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok().map(|a| PathBuf::from(a).join("LLMShield"))
    }
    #[cfg(target_os = "macos")]
    {
        dirs_home().map(|h| h.join("Library").join("Application Support").join("LLMShield"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        dirs_home().map(|h| h.join(".local").join("share").join("llmshield"))
    }
}

#[cfg(not(target_os = "windows"))]
fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// proxy_token 候选路径：新数据目录 → 旧数据目录（迁移失败回退）→ 开发态项目根
fn token_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(root) = data_root() {
        paths.push(root.join("proxy_token"));
    }
    if let Some(root) = legacy_data_root() {
        paths.push(root.join("proxy_token"));
    }
    if let Ok(cwd) = std::env::current_dir() {
        paths.push(cwd.join("proxy_token"));
    }
    paths
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 探测监听指定端口的 PID（复用已有引擎时记录 pid，watchdog 存活校验依赖）
/// 用 netstat -ano 解析（一次性快照，不逐端口探测）
#[cfg(target_os = "windows")]
fn pid_listening_on_port(port: u16) -> Option<u32> {
    let out = no_window(&mut Command::new("netstat"))
        .args(["-ano", "-p", "TCP"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let txt = String::from_utf8_lossy(&out.stdout);
    let needle = format!(":{} ", port);
    for line in txt.lines() {
        if line.contains("LISTENING") && line.contains(&needle) {
            // netstat 行格式：TCP 127.0.0.1:5801 0.0.0.0:0 LISTENING <PID>
            return line.split_whitespace().last().and_then(|s| s.parse().ok());
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn pid_listening_on_port(_port: u16) -> Option<u32> { None }

/// 唤醒窗口并置顶（方案 §13.2）。
/// Win11 的 Foreground Lock 会拒绝后台进程直接抢焦点——单 show()+set_focus() 经常只是
/// 任务栏闪一下、窗口仍在后面。标准规避：瞬时置顶再放开。
fn show_and_focus(w: &tauri::WebviewWindow) {
    let _ = w.show();
    let _ = w.unminimize();
    let _ = w.set_focus();
    let _ = w.set_always_on_top(true);
    std::thread::sleep(Duration::from_millis(50));
    let _ = w.set_always_on_top(false);
}

// ========== Tauri Commands ==========

/// 系统代理地址（更新下载用）。
///
/// 为什么必须显式传而不是靠 reqwest 自动探测：实测（2026-08-17）同一个包
/// 直连 171 KB/s、走本机代理 2.21 MB/s，**差 13 倍**，而用户的
/// `ProxyEnable=1 / ProxyServer=127.0.0.1:7890` 明明设着，updater 却在直连。
///
/// 原因是这条链路的地理位置：安装包由 Cloudflare 边缘缓存（实测 cf-cache-status: HIT），
/// 但免费版 CF 不用中国境内 PoP，边缘节点是东京（CF-RAY 后缀 NRT）。
/// 每次下载都要跨一次国际线路，而本机代理恰好能绕开那段拥塞。
///
/// 交给代理还有一层好处：**由代理自己的规则决定走不走**。
/// 我们不替用户判断哪个域名该代理——他的规则集比我们清楚。
///
/// 顺序：环境变量（跨平台通用）→ Windows 注册表（图形界面设的代理只写这里，
/// 不会进环境变量，这正是自动探测漏掉它的那一格）。
fn system_proxy_url() -> Option<String> {
    for key in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        if let Ok(v) = std::env::var(key) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some(normalize_proxy_url(&v));
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let key = r#"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"#;
        let enabled = no_window(&mut Command::new("reg"))
            .args(["query", key, "/v", "ProxyEnable"])
            .output()
            .ok()?;
        // 值形如 `ProxyEnable    REG_DWORD    0x1`。只认 0x1，0x0 表示用户关了代理。
        let text = String::from_utf8_lossy(&enabled.stdout);
        if !text.contains("0x1") {
            return None;
        }
        let server = no_window(&mut Command::new("reg"))
            .args(["query", key, "/v", "ProxyServer"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&server.stdout);
        // `ProxyServer    REG_SZ    127.0.0.1:7890`，也可能是
        // `http=host:port;https=host:port` 的分协议写法，取 https= 那段优先。
        let raw = text
            .lines()
            .find(|l| l.contains("ProxyServer"))
            .and_then(|l| l.split_whitespace().last())?
            .trim()
            .to_string();
        if raw.is_empty() {
            return None;
        }
        let picked = if raw.contains('=') {
            raw.split(';')
                .find_map(|p| p.strip_prefix("https="))
                .or_else(|| raw.split(';').find_map(|p| p.strip_prefix("http=")))
                .map(|s| s.to_string())?
        } else {
            raw
        };
        return Some(normalize_proxy_url(&picked));
    }
    #[cfg(not(target_os = "windows"))]
    None
}

/// 注册表里的代理是裸 `host:port`，reqwest::Proxy 要求带 scheme。
fn normalize_proxy_url(raw: &str) -> String {
    if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    }
}

/// 给 updater 挂上系统代理。check 和 install 两条路径都要挂——
/// 只挂一条会出现「检查很快、下载很慢」这种更难归因的状态。
fn updater_with_proxy(app: &AppHandle) -> Result<tauri_plugin_updater::Updater, String> {
    use tauri_plugin_updater::UpdaterExt;
    let mut builder = app.updater_builder().timeout(Duration::from_secs(12));
    if let Some(p) = system_proxy_url() {
        match url::Url::parse(&p) {
            Ok(u) => builder = builder.proxy(u),
            Err(e) => log::warn!("[updater] 系统代理地址无法解析，改直连: {p} ({e})"),
        }
    }
    builder.build().map_err(|e| format!("更新器未配置: {e}"))
}

/// 检查更新：命中 tauri.conf.json 的 plugins.updater.endpoints（签名由 pubkey 校验）
///
/// 返回给前端的字段刻意做成「无更新也是成功」而不是报错——检查更新失败（断网、
/// 服务器挂了）不能变成打断用户的错误弹窗，UI 按 `ok` 决定要不要提示。
#[tauri::command]
async fn check_update(app: AppHandle) -> Result<serde_json::Value, String> {
    let updater = updater_with_proxy(&app)?;
    match updater.check().await {
        Ok(Some(update)) => Ok(serde_json::json!({
            "ok": true,
            "has_update": true,
            "version": update.version,
            "current_version": update.current_version,
            "notes": update.body,
            "pub_date": update.date.map(|d| d.to_string()),
        })),
        Ok(None) => Ok(serde_json::json!({"ok": true, "has_update": false})),
        Err(e) => Ok(serde_json::json!({"ok": false, "has_update": false, "error": e.to_string()})),
    }
}

/// 更新完成后重启应用，剥掉 --minimized 参数，确保新进程窗口正常显示。
///
/// `app.restart()` 会把原命令行参数原样传给新进程。若当前实例是开机自启
/// （带 --minimized）启动的，更新后新进程 setup 里检测到 --minimized 会 hide
/// 窗口——用户刚更新完就看不到窗口，以为程序没起来。这里自己 spawn 新进程
/// 并从参数里滤掉 --minimized，让新进程走「正常启动」路径显示窗口。
fn restart_after_update(app: &AppHandle) -> ! {
    use std::process::{exit, Command};
    let exe = std::env::current_exe().unwrap_or_else(|_| {
        tauri::process::current_binary(&app.env()).unwrap_or_else(|_| {
            // 最后兜底：拿不到路径就退回 app.restart()，至少保证重启
            app.restart();
        })
    });
    let args: Vec<std::ffi::OsString> = std::env::args_os()
        .skip(1)
        .filter(|a| a != "--minimized")
        .collect();
    if let Err(e) = Command::new(&exe).args(&args).spawn() {
        log::error!("更新后重启失败: {e}");
        // 兜底：spawn 失败时退回 app.restart()（至少保证重启，即便窗口会隐藏）
        app.restart();
    }
    exit(0);
}

/// 下载并安装更新，完成后重启应用。
///
/// 进度经 `update://progress` 事件推给前端（started/progress/finished），
/// 否则大包下载期间界面完全没有反馈，用户会以为卡死然后强杀——
/// 强杀发生在 NSIS 替换文件的窗口期就会装坏。
#[tauri::command]
async fn install_update(app: AppHandle) -> Result<serde_json::Value, String> {
    use tauri::Emitter;
    let updater = updater_with_proxy(&app)?;
    let update = updater
        .check()
        .await
        .map_err(|e| format!("检查更新失败: {e}"))?
        .ok_or_else(|| "当前已是最新版本".to_string())?;

    let version = update.version.clone();
    let mut downloaded: u64 = 0;
    let _ = app.emit(
        "update://progress",
        serde_json::json!({"event": "started", "version": version}),
    );
    // 写入更新标记文件：NSIS 安装完启动新进程时，新进程 setup 会读取该标记，
    // 强制显示并置顶窗口，无视旧进程透传给 NSIS 的 --minimized 参数
    if let Some(root) = data_root() {
        let flag_path = root.join(".just_updated");
        let _ = std::fs::write(&flag_path, b"1");
    }

    // 引擎必须在 NSIS 开始覆盖文件之前退出，否则 MaskitEngine.exe / *.pyd 被占用装不上。
    // 关键是时机：download_and_install 在 Windows 上会拉起 NSIS 然后让本进程退出，
    // 排在它后面的停机代码根本执行不到（实测确认）。第二个回调是「下载完成、
    // 即将安装」的钩子，这里才是唯一还能停引擎的地方。
    // 走 manager.shutdown() 而不是 taskkill：只杀自己拉起的那棵进程树。
    let engine_for_install = app.try_state::<Arc<EngineManager>>().map(|s| s.inner().clone());
    update
        .download_and_install(
            |chunk, total| {
                downloaded += chunk as u64;
                let _ = app.emit(
                    "update://progress",
                    serde_json::json!({
                        "event": "progress",
                        "downloaded": downloaded,
                        "total": total,
                    }),
                );
            },
            || {
                if let Some(root) = data_root() {
                    let _ = std::fs::write(root.join(".just_updated"), b"1");
                }
                if let Some(m) = &engine_for_install {
                    m.shutdown();
                }
                let _ = app.emit(
                    "update://progress",
                    serde_json::json!({"event": "finished"}),
                );
            },
        )
        .await
        .map_err(|e| format!("下载/安装更新失败: {e}"))?;

    // 兜底：万一本进程没被 NSIS 结束（非 Windows 或安装器行为变化），再停一次。
    // shutdown 幂等，重复调用无副作用。
    if let Some(manager) = app.try_state::<Arc<EngineManager>>() {
        manager.shutdown();
    }
    // 更新重启后窗口必须显示出来，不能沿用原启动参数里的 --minimized。
    restart_after_update(&app);
}

/// 读取引擎 token（dev/prod 双路径探测，§12.5）
/// 时序竞态防护：引擎每次启动生成新 token 并写入文件（app.run 之前），
/// 壳启动早于引擎就绪时读到的旧 token 会导致全部 403——因此等待
/// 引擎端口就绪后再读（就绪 = token 已写入，实测竞态修复 2026-08-12）。
/// async：避免同步阻塞 Tauri 主线程 25s（曾冻结 UI）
#[tauri::command]
async fn get_shield_token() -> Result<String, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(READY_TIMEOUT_SECS + 5);
    loop {
        if EngineManager::port_ready() {
            if let Some(t) = token_candidates()
                .iter()
                .find_map(|p| std::fs::read_to_string(p).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                return Ok(t);
            }
        }
        if std::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(String::new())
}

/// 引擎状态（就绪/pid/自动恢复时间戳）
#[tauri::command]
fn engine_state(manager: tauri::State<'_, Arc<EngineManager>>) -> Result<EngineState, String> {
    manager
        .state
        .lock()
        .map(|s| s.clone())
        .map_err(|e| e.to_string())
}

/// 开机自启注册表值名。更名后必须换：旧值 "LLMShield" 指向旧安装路径的 exe，
/// 卸载旧版后仍留在 Run 键里 → 每次开机弹「找不到文件」。
#[cfg(target_os = "windows")]
const AUTOSTART_VALUE: &str = "Maskit";
/// 更名前的自启值名，用于开关自启时顺手清理残留
#[cfg(target_os = "windows")]
const AUTOSTART_VALUE_LEGACY: &str = "LLMShield";

/// 自启自愈：把 Run 项修正到**当前这个** exe，但不抢别人的。
///
/// 修的是一类必然复发的故障：Run 项里存的是**绝对路径**，而 exe 的位置会变——
/// 改名（llm-shield.exe → Maskit.exe）、换安装目录、开发机上曾指向构建树。
/// 路径一旦过期，开机拉起的要么是旧程序、要么直接报找不到文件，
/// 而用户完全无从察觉：面板照样显示「自启已开启」，因为 Run 键里确实有项。
///
/// 实测 2026-08-17：值名 `LLMShield` 指向 `...\target\release\llm-shield.exe`
/// （构建残留，文件还在所以旧的清理逻辑故意不删），新值名 `Maskit` 从未写入。
/// 开机拉起的是几天前的构建产物，装好的 0.1.x 反而没启动。
///
/// 判据（按值名分两套，因为两者的歧义程度不同）：
///
/// - **旧值名 `LLMShield`**：无条件迁移到当前 exe 再删掉它。
///   它是更名前的产品名，不可能有第二个「正在使用中的」程序用这个名字，
///   所以不存在抢别人的问题。这也是上面那个实测故障唯一能被修好的分支——
///   它指向的文件**是存在的**，任何「只在目标缺失时才动」的规则都救不了它。
///
/// - **新值名 `Maskit`**：只在「指向的 exe 已不存在」或「指向的就是自己」时才写。
///   否则说明另一份**装得好好的**副本占着自启，不该被顺手抢走：
///   `heal_autostart` 每次启动都跑，没有这道限制的话，跑一次便携版/测试副本
///   就会把开机自启永久改到那份上，而用户完全不知道（2026-08-17 评审提出）。
///   正常升级不受影响：NSIS 原地覆盖，路径不变，走「指向的就是自己」这一格。
///
/// 用 winreg 直接读值，不再 `reg query` 拿 stdout：
/// `reg` 在中文 Windows 上输出 GBK，按 UTF-8 解会把中文安装路径解坏，
/// 而这里要拿路径做比对，解坏了就会做出错误判断。winreg 走的是宽字符 API，没这问题。
#[cfg(target_os = "windows")]
fn heal_autostart() {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
    use winreg::RegKey;

    let sub = r"Software\Microsoft\Windows\CurrentVersion\Run";
    let Ok(run) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(sub, KEY_READ | KEY_SET_VALUE)
    else {
        return;
    };
    let legacy: Option<String> = run.get_value(AUTOSTART_VALUE_LEGACY).ok();
    let current: Option<String> = run.get_value(AUTOSTART_VALUE).ok();

    // 检查 config.json 中的自启配置，支持卸载重装后的自愈
    let config_autostart = data_root()
        .and_then(|r| std::fs::read_to_string(r.join("config.json")).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("autostart").and_then(|b| b.as_bool()))
        .unwrap_or(false);

    let Ok(exe) = std::env::current_exe() else { return };

    let should_write = match &current {
        // 注册表无当前项：若有旧项或 config 中开启了自启，必须补写当前 exe 路径
        None => legacy.is_some() || config_autostart,
        Some(v) => match autostart_target(v) {
            // 值解析不出路径（被人手改坏了）→ 当成过期，重写
            None => true,
            Some(p) => {
                let same = std::fs::canonicalize(&p)
                    .ok()
                    .zip(std::fs::canonicalize(&exe).ok())
                    .map(|(a, b)| a == b)
                    .unwrap_or(false);
                // 指向自己（正常升级）→ 重写无副作用；指向的东西没了 → 必须重写；
                // 指向另一份还活着的安装 → **不动**，那是别人的自启
                same || !std::path::Path::new(&p).exists()
            }
        },
    };

    if should_write {
        let cmd = format!("\"{}\" --minimized", exe.display());
        let _ = run.set_value(AUTOSTART_VALUE, &cmd);
    }
    if legacy.is_some() {
        let _ = run.delete_value(AUTOSTART_VALUE_LEGACY);
    }
}

/// 从 Run 值里取出 exe 路径。值形如 `"C:\...\Maskit.exe" --minimized`，
/// 也可能是没有引号的裸路径（旧版本或手工写入）。
#[cfg(target_os = "windows")]
fn autostart_target(value: &str) -> Option<String> {
    let v = value.trim();
    if let Some(rest) = v.strip_prefix('"') {
        return rest.split('"').next().map(|s| s.to_string()).filter(|s| !s.is_empty());
    }
    // 裸路径：按 " --" 之前截断（参数一律以 -- 开头，路径里不会有这个组合）
    let end = v.find(" --").unwrap_or(v.len());
    let p = v[..end].trim();
    if p.is_empty() { None } else { Some(p.to_string()) }
}

#[cfg(not(target_os = "windows"))]
fn heal_autostart() {}

/// 开机自启（winreg 写壳 exe 路径 + --minimized；绕开引擎侧 sys.executable 指向 sidecar 的坑）
#[tauri::command]
async fn set_autostart(enabled: bool) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        let key = r#"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"#;
        // 无论开还是关，先清掉更名前的残留项（指向已卸载的旧 exe，开机必报错）
        let _ = no_window(&mut Command::new("reg"))
            .args(["delete", key, "/v", AUTOSTART_VALUE_LEGACY, "/f"])
            .output();
        if enabled {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let cmd = format!("\"{}\" --minimized", exe.display());
            let out = no_window(&mut Command::new("reg"))
                .args(["add", key, "/v", AUTOSTART_VALUE, "/t", "REG_SZ", "/d", &cmd, "/f"])
                .output()
                .map_err(|e| e.to_string())?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).to_string());
            }
        } else {
            let _ = no_window(&mut Command::new("reg"))
                .args(["delete", key, "/v", AUTOSTART_VALUE, "/f"])
                .output();
        }
        Ok(enabled)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // macOS/Linux: 用 tauri-plugin-autostart 或 ~/.config/autostart 桌面文件
        // 开源后跨平台时实现。当前非 Windows 直接返回成功（不阻塞功能）
        let _ = enabled;
        Ok(true)
    }
}

/// 重启引擎（手动触发：先停旧进程再拉起）
#[tauri::command]
fn restart_engine(
    app: tauri::AppHandle,
    manager: tauri::State<'_, Arc<EngineManager>>,
) -> Result<(), String> {
    manager.shutdown();
    std::thread::sleep(Duration::from_millis(500));
    manager.spawn(&app)?;
    manager.readiness_loop();
    Ok(())
}

/// 同步代理运行状态至系统托盘菜单（运行中显示「停止代理」，已停止显示「启动代理」）
#[tauri::command]
fn update_tray_proxy_status(running: bool) {
    update_tray_proxy_text(running);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let manager = Arc::new(EngineManager::new());

    tauri::Builder::default()
        .plugin(
            // tauri-plugin-http：前端 fetch 经 Rust reqwest 代发（方案 §4.3）
            // scope 限制在 capabilities 的 http:scope（仅 127.0.0.1:5801）
            tauri_plugin_http::init(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        // tauri-plugin-updater：公钥在 tauri.conf.json，私钥只在构建机
        // （~/.tauri/maskit-updater.key，永不入库）。没有正确签名的包装不上。
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(
            // 单实例：二次启动聚焦已有窗口（方案 §4.9）
            tauri_plugin_single_instance::init(|app, _args, _cwd| {
                if let Some(w) = app.get_webview_window("main") {
                    show_and_focus(&w);
                }
            }),
        )
        .manage(manager.clone())
        .invoke_handler(tauri::generate_handler![
            get_shield_token,
            engine_state,
            restart_engine,
            set_autostart,
            check_update,
            install_update,
            update_tray_proxy_status
        ])
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            let handle = app.handle().clone();
            let _ = APP_HANDLE.set(handle.clone());

            // 检查是否刚完成更新：更新后必须弹出并聚焦窗口，无视任何 --minimized 参数。
            // 解决根因：
            // 1. 本版本主动写入的 .just_updated 标记文件；
            // 2. NSIS 安装器更新启动时可能携带的 /UPDATE 或 /ARGS 标识。
            // 只要命中任一项，强制显示并聚焦窗口，绝不进入 hide 分支。
            let is_update_launch = {
                let has_flag = data_root()
                    .map(|r| r.join(".just_updated"))
                    .and_then(|flag| {
                        if flag.exists() {
                            let _ = std::fs::remove_file(&flag);
                            Some(true)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(false);
                let has_update_arg = std::env::args().any(|a| a == "/UPDATE" || a == "/ARGS" || a == "--updated");
                has_flag || has_update_arg
            };

            if is_update_launch {
                if let Some(w) = app.get_webview_window("main") {
                    show_and_focus(&w);
                    // 异步再次聚焦，确保 webview 渲染完全准备就绪后窗口依然在前台
                    let w_clone = w.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(200));
                        show_and_focus(&w_clone);
                    });
                }
            } else if std::env::args().any(|a| a == "--minimized") {
                // --minimized：仅在真实的开机自启/快捷方式启动时隐藏窗口
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }

            // 自启项指向的路径可能已过期（改名/换目录/指向构建树），每次启动校正一次。
            // 放后台线程：要发 2-4 次 reg 子进程调用，没必要卡住窗口显示。
            std::thread::spawn(heal_autostart);

            // 系统托盘：显示窗口 / 启停代理（Rust 直连引擎 API）/ 退出
            {
                use tauri::menu::{Menu, MenuItem};
                use tauri::tray::TrayIconBuilder;
                let show_i = MenuItem::with_id(app, "show", "显示窗口", true, None::<&str>)?;
                let toggle_i = MenuItem::with_id(app, "toggle", "启动代理", true, None::<&str>)?;
                let _ = TRAY_TOGGLE_ITEM.set(toggle_i.clone());
                let quit_i = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&show_i, &toggle_i, &quit_i])?;
                let tray = TrayIconBuilder::new()
                    .icon(app.default_window_icon().unwrap().clone())
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "show" => {
                            if let Some(w) = app.get_webview_window("main") {
                                show_and_focus(&w);
                            }
                        }
                        "toggle" => {
                            // 必须另开线程：菜单回调跑在主线程，这里要发两个阻塞 HTTP
                            // （查状态 + 启停），而 start_proxy 拉 mitmdump 可能好几秒——
                            // 在主线程里等于把托盘和窗口一起冻住
                            std::thread::spawn(|| {
                                let token = token_candidates()
                                    .iter()
                                    .find_map(|p| std::fs::read_to_string(p).ok())
                                    .map(|s| s.trim().to_string())
                                    .unwrap_or_default();
                                let base = format!("http://127.0.0.1:{}", engine_port());
                                if let Ok(client) = reqwest::blocking::Client::builder()
                                    .timeout(Duration::from_secs(5))
                                    .build()
                                {
                                    let running = client
                                        .get(format!("{base}/api/status"))
                                        .header("X-Shield-Token", &token)
                                        .send()
                                        .ok()
                                        .and_then(|r| r.json::<serde_json::Value>().ok())
                                        .and_then(|v| v.get("proxy_running").cloned())
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);
                                    let path = if running { "stop" } else { "start" };
                                    let res = client
                                        .post(format!("{base}/api/proxy/{path}"))
                                        .header("X-Shield-Token", &token)
                                        .send();
                                    if res.is_ok() {
                                        update_tray_proxy_text(!running);
                                    }
                                }
                            });
                        }
                        "quit" => {
                            // 三段式退出（Exit 事件统一处理）
                            app.exit(0);
                        }
                        _ => {}
                    })
                    .build(app)?;
                let _ = tray;
            }
            let mgr = app.state::<Arc<EngineManager>>();
            match mgr.spawn(&handle) {
                Ok(_) => {
                    // 就绪轮询（不阻塞 setup）
                    let mgr_ready = mgr.inner().clone();
                    let _ = std::thread::Builder::new()
                        .name("engine-ready".into())
                        .spawn(move || mgr_ready.readiness_loop());
                    // 崩溃监控
                    let mgr_watch = mgr.inner().clone();
                    let _ = std::thread::Builder::new()
                        .name("engine-crash-watchdog".into())
                        .spawn(move || mgr_watch.crash_watchdog());
                }
                Err(e) => mgr.set_last_error(&e),
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // 点关闭按钮 → 最小化到托盘（与旧版一致）
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| match event {
            // 三段式退出：Exit 前同步清理（引擎停 + 进程树）
            RunEvent::Exit => {
                let mgr = app.state::<Arc<EngineManager>>();
                mgr.shutdown();
            }
            _ => {}
        });
}

#[cfg(all(test, target_os = "windows"))]
mod autostart_tests {
    use super::autostart_target;

    /// Run 值的形态不止一种：模板写的带引号、老版本/手工写的裸路径、
    /// 还有被人改坏的。解析错会让自愈做出错误判断——要么该修的不修，
    /// 要么把别人的自启抢过来。
    #[test]
    fn parses_quoted_path_with_args() {
        assert_eq!(
            autostart_target(r#""D:\software\work\Maskit\Maskit.exe" --minimized"#).as_deref(),
            Some(r"D:\software\work\Maskit\Maskit.exe")
        );
    }

    #[test]
    fn parses_bare_path_with_args() {
        assert_eq!(
            autostart_target(r"C:\Apps\Maskit.exe --minimized").as_deref(),
            Some(r"C:\Apps\Maskit.exe")
        );
    }

    #[test]
    fn parses_bare_path_without_args() {
        assert_eq!(
            autostart_target(r"C:\Apps\Maskit.exe").as_deref(),
            Some(r"C:\Apps\Maskit.exe")
        );
    }

    /// 中文安装路径：这正是不再用 `reg query` 拿 stdout 的原因
    /// （reg 在中文 Windows 输出 GBK，按 UTF-8 解会把路径解坏）。
    #[test]
    fn handles_non_ascii_path() {
        assert_eq!(
            autostart_target(r#""D:\程序\数据面具\Maskit.exe" --minimized"#).as_deref(),
            Some(r"D:\程序\数据面具\Maskit.exe")
        );
    }

    /// 路径里带空格必须靠引号界定，不能被 " --" 规则误截。
    #[test]
    fn handles_spaces_inside_quotes() {
        assert_eq!(
            autostart_target(r#""C:\Program Files\Maskit\Maskit.exe" --minimized"#).as_deref(),
            Some(r"C:\Program Files\Maskit\Maskit.exe")
        );
    }

    /// 解析不出路径时返回 None —— 调用方据此当成「已过期」重写，
    /// 而不是拿一个空串去和 current_exe 比对（那会永远不相等、永远不重写）。
    #[test]
    fn returns_none_for_unparsable() {
        assert_eq!(autostart_target(""), None);
        assert_eq!(autostart_target("   "), None);
        assert_eq!(autostart_target(r#""""#), None);
    }

    /// 更新标记文件（.just_updated）写入与消费生命周期测试
    #[test]
    fn test_just_updated_flag_lifecycle() {
        let tmp = std::env::temp_dir().join(format!("maskit-test-flag-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let flag = tmp.join(".just_updated");

        // 写入标记
        std::fs::write(&flag, b"1").unwrap();
        assert!(flag.exists());

        // 模拟 setup 消费标记
        let consumed = if flag.exists() {
            let _ = std::fs::remove_file(&flag);
            true
        } else {
            false
        };
        assert!(consumed);
        assert!(!flag.exists());

        // 再次检查应为 false
        let second_check = if flag.exists() {
            let _ = std::fs::remove_file(&flag);
            true
        } else {
            false
        };
        assert!(!second_check);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
