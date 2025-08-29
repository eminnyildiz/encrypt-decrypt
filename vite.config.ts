import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import nodePolyfills from 'rollup-plugin-node-polyfills';
// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    // Polyfill eklentisi
    nodePolyfills()
  ],
  resolve: {
    alias: {
      buffer: 'buffer',
      process: 'process/browser',
      }
  },
  define: {
    global: 'globalThis' // bazı kütüphaneler global bekler
  },
  optimizeDeps: {
    include: ['buffer', 'process']
  }
});

