import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * When VITE_API_BASE_URL is set (hosted build), allow that single origin in the page's Content-Security-Policy
 * connect-src. Without it the policy keeps allowing only the local development backend.
 */
const apiOriginCsp = () => ({
  name: 'aisop-api-origin-csp',
  transformIndexHtml(html: string) {
    const raw = process.env.VITE_API_BASE_URL;
    if (!raw) return html;
    const origin = new URL(raw).origin;
    if (!origin.startsWith('https://')) throw new Error('VITE_API_BASE_URL must be an https:// origin');
    return html.replace(/connect-src [^;]*;/, `connect-src 'self' ${origin};`);
  },
});

export default defineConfig({
  plugins: [react(), apiOriginCsp()],
  server: {
    port: 3000,
    strictPort: true,
    host: '127.0.0.1',
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      },
      '/health': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  preview: {
    port: 3000,
    host: '127.0.0.1',
  },
  build: {
    target: 'es2022',
    sourcemap: false,
    chunkSizeWarningLimit: 1000,
  },
});

