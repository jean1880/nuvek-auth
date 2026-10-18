import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import pkg from './package.json' with { type: 'json' }

const resolve = (rel: string) => fileURLToPath(new URL(rel, import.meta.url))

// Peer and runtime dependencies stay external (including deep imports) so consumers dedupe.
const external = [
  ...Object.keys(pkg.peerDependencies ?? {}),
  ...Object.keys(pkg.dependencies ?? {}),
].map((name) => new RegExp(`^${name}(/.*)?$`))

// Library build: ESM only (every consumer is a Vite app). Types come from vue-tsc.
export default defineConfig({
  plugins: [vue()],
  build: {
    lib: {
      entry: resolve('./vue/src/index.ts'),
      formats: ['es'],
      fileName: 'nuvek-auth',
    },
    rollupOptions: { external },
  },
})
