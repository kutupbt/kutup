import { defineConfig } from 'vite'
import { kutupApp } from '@kutup/config/vite'

// crypto-calendar: the crypto runtime with calendars and the time zone
// database, loaded instead of crypto (docs/plans/calendar.md).
export default defineConfig(kutupApp({ app: 'calendar', wasm: ['crypto-calendar'] }))
