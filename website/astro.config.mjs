import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';

// https://astro.build/config
export default defineConfig({
  site: 'https://secureagent.dev',
  integrations: [tailwind()],
  output: 'static',
  build: {
    assets: '_assets'
  },
  vite: {
    build: {
      cssMinify: true
    }
  }
});
