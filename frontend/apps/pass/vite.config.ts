import { defineConfig } from 'vite'
import { kutupApp } from '@kutup/config/vite'

// Pass serves a stricter policy than the other apps: no inline or eval'd
// script (frontend/docker/40-kutup-hosts.sh).
export default defineConfig(kutupApp({ app: 'pass', wasm: ['crypto', 'pass'], strictCsp: true }))
