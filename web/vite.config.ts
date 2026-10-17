import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';

// The panel serves dist/ itself. `npm run dev` proxies the API to a panel
// started locally with EZHIK_WEB_TLS=0 on port 8443.
export default defineConfig({
  plugins: [preact()],
  build: {
    target: 'es2020',
    cssCodeSplit: false,
    assetsInlineLimit: 0,
    sourcemap: false,
    chunkSizeWarningLimit: 600,
  },
  server: {
    port: 5174,
    proxy: { '/api': 'http://127.0.0.1:8443', '/healthz': 'http://127.0.0.1:8443' },
  },
});
