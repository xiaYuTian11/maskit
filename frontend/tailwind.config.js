/** @type {import('tailwindcss').Config} */
// LLM Shield：深色模式沿用 data-theme 属性切换（与旧面板一致），
// 因此 darkMode 必须用 selector + '[data-theme="dark"]'，不能用 .dark class
module.exports = {
  darkMode: ['selector', '[data-theme="dark"]'],
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
          // 文字专用：小字号用 DEFAULT 达不到 4.5:1，见 index.css 注释
          ink: 'hsl(var(--primary-ink))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
          ink: 'hsl(var(--destructive-ink))',
        },
        // index.css 里早就定义了 --success / --warning，但没在这里注册，
        // 于是 `text-success` 这类类名根本生成不出来，两个变量白写。
        // ink 用于小字号文字（DEFAULT 作填充/图标）。
        success: {
          DEFAULT: 'hsl(var(--success))',
          ink: 'hsl(var(--success-ink))',
        },
        warning: {
          DEFAULT: 'hsl(var(--warning))',
          ink: 'hsl(var(--warning-ink))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
      },
      boxShadow: {
        // ⚠️ 必须走主题项，不能用 `shadow-[var(--shadow-card)]`。
        // 后者在 Tailwind 3 里被判定为「颜色」——生成的是
        //   --tw-shadow-color: var(--shadow-card);
        //   --tw-shadow: var(--tw-shadow-colored);   ← 未定义，回退 0 0 #0000
        // 结果 box-shadow: none，卡片完全没有阴影，且变量改了也看不出变化。
        card: 'var(--shadow-card)',
        'card-hover': 'var(--shadow-card-hover)',
      },
      fontSize: {
        // 11px 是这套 UI 的「唯一小字号」（脚注/子项/徽章），此前散成 255 处
        // `text-[11px]` 魔法数。值完全相同，只是给了它一个名字。
        // 注意：只设字号不设行高，与 `text-[11px]` 的行为完全一致。
        '2xs': '11px',
      },
      borderRadius: {
        // radius 阶梯严格递增：sm(8) < md(10) < lg(12) = xl(12)。
        // 原来的 lg=14 比 xl=12 还大，`rounded-lg` 用在导航项上反而比卡片更圆。
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      fontFamily: {
        sans: [
          'Inter',
          '-apple-system',
          'BlinkMacSystemFont',
          'PingFang SC',
          'Hiragino Sans GB',
          'HarmonyOS Sans SC',
          'MiSans',
          'Microsoft YaHei UI',
          'Microsoft YaHei',
          'Noto Sans CJK SC',
          'Source Han Sans SC',
          'WenQuanYi Micro Hei',
          'Segoe UI',
          'ui-sans-serif',
          'system-ui',
          'sans-serif',
        ],
        mono: [
          'JBMono',
          'JetBrains Mono',
          'SF Mono',
          'Cascadia Code',
          'Consolas',
          'PingFang SC',
          'Microsoft YaHei UI',
          'Noto Sans Mono CJK SC',
          'ui-monospace',
          'monospace',
        ],
      },
    },
  },
  plugins: [],
}
