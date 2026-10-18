import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vite dev proxy: '/api' -> backend at http://localhost:8000
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
});
