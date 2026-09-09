# Maskit 前端

React 19 + TypeScript + Vite + Tailwind CSS + shadcn/ui。同一套产物既被 Tauri 桌面壳加载，也由 `engine/panel.py` 在 Docker / 源码态下同源托管。

```bash
npm ci
npm run dev        # http://localhost:5173，API 指向本机引擎 127.0.0.1:5801（需先 python engine/panel.py）
npm run build      # tsc -b + vite build → dist/
npm run lint       # oxlint
node ../scripts/check-i18n.mjs   # zh / en 字典对齐
npx tauri dev      # 桌面壳开发（需 Rust）
```

浏览器开发时可设置 `VITE_SHIELD_TOKEN` 自动登录，但该变量仅在 Vite 开发构建（`import.meta.env.DEV`）读取；生产构建不会把它写入 bundle。生产/Docker 请使用 `MASKIT_PANEL_TOKEN`，通过登录页或启动链接提供令牌。

约定：

- 所有请求走 `src/lib/shield-fetch.ts`，不直接 `fetch`；
- 用户可见文案一律 `t()` / `tf()`，key 同时写入 `src/lib/i18n.tsx` 的 zh 与 en；
- 新 UI 用 Tailwind 类 + `src/components/ui` 语义组件，颜色走 CSS 变量以兼容深浅主题。
- 页面文案必须同时补齐 `zh` / `en`；`node ../scripts/check-i18n.mjs` 会检查字典键和静态引用。
- 生产构建不接受前端内嵌令牌；浏览器部署使用面板登录页和 `MASKIT_PANEL_TOKEN`。
- 视觉改动至少验证桌面和窄视口的无横向溢出、加载/空态/错误态及键盘焦点。
