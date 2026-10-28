import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// In development the backend runs separately (Compose or `go run`); Vite
// proxies API calls to it so the app is same-origin, as it is behind nginx.
const backend = process.env.PAHREDAR_API ?? 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: { '/api': backend, '/healthz': backend },
  },
})
