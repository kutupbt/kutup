import { defineConfig } from 'vite'
import { kutupApp } from '@kutup/config/vite'

export default defineConfig(kutupApp({ app: 'mail', wasm: ['crypto'] }))
