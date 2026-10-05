//! Linux 使用原生 StatusNotifierItem：AppIndicator 不提供 Activate，
//! Tauri 的左键事件与 show_menu_on_left_click 在该后端也不生效。
//! D-Bus 线程只投递窗口/菜单动作，GTK 操作仍由主线程完成。

use std::io;
use std::sync::OnceLock;
use tauri::AppHandle;

static TRAY: OnceLock<ksni::Handle<LinuxTray>> = OnceLock::new();

struct LinuxTray {
    icon: ksni::Icon,
    running: bool,
    on_action: Box<dyn Fn(&'static str) + Send>,
}

impl LinuxTray {
    fn new(
        icon: &tauri::image::Image<'_>,
        on_action: impl Fn(&'static str) + Send + 'static,
    ) -> Self {
        // Tauri 提供 RGBA；SNI IconPixmap 要求网络字节序 ARGB，不能直接拷贝。
        let mut data = icon.rgba().to_vec();
        for pixel in data.chunks_exact_mut(4) {
            pixel.rotate_right(1);
        }
        Self {
            icon: ksni::Icon {
                width: icon.width() as i32,
                height: icon.height() as i32,
                data,
            },
            running: false,
            on_action: Box::new(on_action),
        }
    }
}

impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        "maskit".into()
    }

    fn title(&self) -> String {
        "Maskit".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![self.icon.clone()]
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        (self.on_action)("show");
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        [
            ("show", "显示窗口"),
            (
                "toggle",
                if self.running {
                    "停止代理"
                } else {
                    "启动代理"
                },
            ),
            ("quit", "退出"),
        ]
        .into_iter()
        .map(|(id, label)| {
            ksni::menu::StandardItem {
                label: label.into(),
                activate: Box::new(move |tray: &mut Self| (tray.on_action)(id)),
                ..Default::default()
            }
            .into()
        })
        .collect()
    }
}

fn dispatch(app: &AppHandle, id: &'static str) {
    let handle = app.clone();
    if let Err(error) = app.run_on_main_thread(move || super::handle_tray_menu_event(&handle, id)) {
        log::error!("[tray] 无法投递托盘动作 {id}: {error}");
    }
}

/// 在独立线程服务本机会话总线；运行失败时显示主窗口，避免自启隐藏后无入口。
pub(super) fn install(app: &AppHandle) -> io::Result<()> {
    let icon = app
        .default_window_icon()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "缺少托盘图标"))?;
    let handle = app.clone();
    let service = ksni::TrayService::new(LinuxTray::new(icon, move |id| dispatch(&handle, id)));
    let tray = service.handle();
    let handle = app.clone();
    std::thread::Builder::new()
        .name("linux-tray".into())
        .spawn(move || {
            // 不使用 ksni::spawn：其内部 unwrap 会丢失应用层错误处理。
            if let Err(error) = service.run() {
                log::error!("[tray] Linux 托盘服务退出: {error}");
                dispatch(&handle, "show");
            }
        })?;
    let _ = TRAY.set(tray);
    Ok(())
}

pub(super) fn update_proxy_text(running: bool) {
    if let Some(tray) = TRAY.get() {
        tray.update(|tray| tray.running = running);
    }
}

pub(super) fn shutdown() {
    if let Some(tray) = TRAY.get() {
        tray.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbus::arg::{PropMap, RefArg, Variant};
    use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
    use dbus::blocking::{Connection, Proxy};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const SNI: &str = "org.kde.StatusNotifierItem";
    const MENU: &str = "com.canonical.dbusmenu";

    fn menu_items(proxy: &Proxy<'_, &Connection>) -> Vec<(i32, PropMap)> {
        type Layout = (i32, PropMap, Vec<Variant<Box<dyn RefArg>>>);
        let (_, layout): (u32, Layout) = proxy
            .method_call(MENU, "GetLayout", (0_i32, -1_i32, Vec::<String>::new()))
            .unwrap();
        let ids: Vec<i32> = layout
            .2
            .iter()
            .map(|child| child.0.as_iter().unwrap().next().unwrap().as_i64().unwrap() as i32)
            .collect();
        let (items,): (Vec<(i32, PropMap)>,) = proxy
            .method_call(
                MENU,
                "GetGroupProperties",
                (ids, vec!["label", "enabled", "visible"]),
            )
            .unwrap();
        items
    }

    /// 真正调用导出的 D-Bus 接口；子进程私有总线不会向用户桌面注册测试图标。
    #[test]
    fn activation_and_menu_over_dbus() {
        const CHILD: &str = "MASKIT_TRAY_TEST_PRIVATE_BUS";
        const TEST: &str = "linux_tray::tests::activation_and_menu_over_dbus";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new("timeout")
                .args(["20s", "dbus-run-session", "--"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(CHILD, "1")
                .output()
                .expect("需要 dbus-run-session 执行隔离托盘测试");
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let image = tauri::image::Image::new_owned(vec![11, 22, 33, 44], 1, 1);
        let (tx, rx) = mpsc::channel();
        let service =
            ksni::TrayService::new(LinuxTray::new(&image, move |id| tx.send(id).unwrap()));
        let handle = service.handle();
        let thread = std::thread::spawn(move || service.run().unwrap());
        let conn = Connection::new_session().unwrap();
        let bus = conn.with_proxy(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            Duration::from_secs(2),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let name = loop {
            let (names,): (Vec<String>,) = bus
                .method_call("org.freedesktop.DBus", "ListNames", ())
                .unwrap();
            if let Some(name) = names
                .into_iter()
                .find(|name| name.starts_with("org.kde.StatusNotifierItem-"))
            {
                break name;
            }
            assert!(Instant::now() < deadline, "托盘没有注册 D-Bus 服务");
            std::thread::sleep(Duration::from_millis(20));
        };
        let tray = conn.with_proxy(name.clone(), "/StatusNotifierItem", Duration::from_secs(2));
        let (xml,): (String,) = tray
            .method_call("org.freedesktop.DBus.Introspectable", "Introspect", ())
            .unwrap();
        assert!(
            xml.contains("name=\"Activate\""),
            "桌面必须能自省到 Activate"
        );
        assert!(!tray.get::<bool>(SNI, "ItemIsMenu").unwrap());
        let pixmaps: Vec<(i32, i32, Vec<u8>)> = tray.get(SNI, "IconPixmap").unwrap();
        assert_eq!(pixmaps, vec![(1, 1, vec![44, 11, 22, 33])]);
        let _: () = tray.method_call(SNI, "Activate", (0_i32, 0_i32)).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), "show");

        let path: dbus::Path<'static> = tray.get(SNI, "Menu").unwrap();
        let menu = conn.with_proxy(name, path, Duration::from_secs(2));
        let items = menu_items(&menu);
        assert_eq!(items.len(), 3);
        for ((id, props), (label, action)) in items.iter().zip([
            ("显示窗口", "show"),
            ("启动代理", "toggle"),
            ("退出", "quit"),
        ]) {
            assert_eq!(props["label"].0.as_str(), Some(label));
            // DBusMenu 省略等于协议默认值的属性；enabled/visible 默认均为 true。
            for key in ["enabled", "visible"] {
                assert_eq!(
                    props
                        .get(key)
                        .map(|value| value.0.as_i64())
                        .unwrap_or(Some(1)),
                    Some(1)
                );
            }
            let _: () = menu
                .method_call(MENU, "Event", (*id, "clicked", Variant(0_i32), 0_u32))
                .unwrap();
            assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), action);
        }
        handle.update(|tray| tray.running = true);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let items = menu_items(&menu);
            if items[1].1["label"].0.as_str() == Some("停止代理") {
                break;
            }
            assert!(Instant::now() < deadline, "代理状态未更新到 D-Bus 菜单");
            std::thread::sleep(Duration::from_millis(20));
        }
        handle.shutdown();
        thread.join().unwrap();
    }
}
