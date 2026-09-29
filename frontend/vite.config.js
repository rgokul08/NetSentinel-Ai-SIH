import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dev server proxies /api to the FastAPI backend so the browser only ever
// talks to one origin (no CORS issues, no hard-coded backend URL in the bundle).
const BACKEND = process.env.VITE_BACKEND_ORIGIN || 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    port: Number(process.env.PORT || 3000),
    host: true,
    allowedHosts: true,
    proxy: {
      '/api': {
        target: BACKEND,
        changeOrigin: true,
        secure: false,
        ws: true,
      },
    },
  },
  preview: {
    port: Number(process.env.PORT || 4173),
    host: true,
    allowedHosts: true,
    proxy: {
      '/api': { target: BACKEND, changeOrigin: true, secure: false, ws: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          charts: ['recharts'],
        },
      },
    },
  },
})
