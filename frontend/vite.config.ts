import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: { '/api': { target: 'http://127.0.0.1:8000', changeOrigin: false } },
  },
  preview: { host: '127.0.0.1', port: 4173 },
  // Unit and component tests (tests/*.test.ts[x]) run in a simulated browser with no backend; the SSR/API contract
  // smoke (scripts/contract-smoke.mjs) covers the real one.
  test: { environment: 'happy-dom', include: ['tests/**/*.test.{ts,tsx}'], restoreMocks: true, unstubGlobals: true },
});
