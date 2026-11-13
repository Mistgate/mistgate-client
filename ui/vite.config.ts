import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { host: '127.0.0.1', port: 5183, strictPort: true },
  build: {
    // The flags stay files. Vite would put a small picture into the script as a data: address, and the window then
    // decoded every flag again on each redraw of the server list, keeping the memory: hundreds of megabytes in minutes.
    assetsInlineLimit: (file) => (file.includes('country-flag-icons') ? false : undefined),
  },
});
