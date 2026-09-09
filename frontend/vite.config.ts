import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Data Maskit 前端构建配置
// 不设 base：产物用绝对路径 /assets/…，Tauri（http://tauri.localhost）与 panel.py 同源托管均可直接加载
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': new URL('./src', import.meta.url).pathname,
    },
  },
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    watch: {
      ignored: ['**/src-tauri/**'],
    },
  },
  build: {
    target: 'es2021',
    // Vite 8 (rolldown) 默认 minify，无需 esbuild
    sourcemap: false,
    outDir: 'dist',
    emptyOutDir: true,
  },
})
