import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { host: '127.0.0.1', port: 5183, strictPort: true },
  build: {
    // The flags stay files: some 250 small pictures as data: addresses would only swell the script.
    assetsInlineLimit: (file) => (file.includes('country-flag-icons') ? false : undefined),
  },
});
