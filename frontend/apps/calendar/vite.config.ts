import { defineConfig } from 'vite'
import { kutupApp } from '@kutup/config/vite'

// crypto-calendar: the crypto runtime with calendars and the time zone
// database, loaded instead of crypto (docs/plans/calendar.md); calendar-ics:
// the .ics import and export, loaded on first use (E2c).
export default defineConfig(kutupApp({ app: 'calendar', serviceWorker: true, wasm: ['crypto-calendar', 'calendar-ics'] }))
