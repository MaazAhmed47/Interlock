import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

function isDashboardSpaRoute(url: string) {
  const path = url.split(/[?#]/, 1)[0]
  return path === '/dashboard' || (path.startsWith('/dashboard/') && !path.slice('/dashboard/'.length).includes('.'))
}

function dashboardFallback() {
  return {
    name: 'dashboard-fallback',
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        if (isDashboardSpaRoute(req.url || '')) req.url = '/dashboard/'
        next()
      })
    },
    configurePreviewServer(server) {
      server.middlewares.use((req, _res, next) => {
        if (isDashboardSpaRoute(req.url || '')) req.url = '/dashboard/index.html'
        next()
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), dashboardFallback()],
  base: '/',
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        dashboard: resolve(__dirname, 'dashboard/index.html'),
      },
    },
  },
})
