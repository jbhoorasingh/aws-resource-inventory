import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: '../static/vue',
    emptyOutDir: true,
    manifest: true,
    rollupOptions: {
      input: {
        'tasks-island': resolve(__dirname, 'src/islands/tasks-island.ts'),
        'accounts-island': resolve(__dirname, 'src/islands/accounts-island.ts'),
        'enis-island': resolve(__dirname, 'src/islands/enis-island.ts'),
        'vpcs-island': resolve(__dirname, 'src/islands/vpcs-island.ts'),
        'ec2-island': resolve(__dirname, 'src/islands/ec2-island.ts'),
        'security-groups-island': resolve(__dirname, 'src/islands/security-groups-island.ts'),
      },
      output: {
        entryFileNames: '[name].[hash].js',
        chunkFileNames: 'chunks/[name].[hash].js',
        assetFileNames: 'assets/[name].[hash][extname]',
      },
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
