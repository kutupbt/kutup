import { defineConfig } from 'vite'
import { kutupApp } from '@kutup/config/vite'

// crypto-calendar and calendar-ics: loaded only when a message holds an
// invitation (docs/plans/calendar-e4.md, Q-4), never with the app.
export default defineConfig(kutupApp({ app: 'mail', wasm: ['crypto', 'mail-search', 'crypto-calendar', 'calendar-ics'] }))
