import './polyfills'
import './i18n'
import './index.css'
import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Provider } from 'react-redux'
import { store } from './store'
import App from './App'
import AppErrorBoundary from './components/layout/AppErrorBoundary'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 0,
    },
  },
})

import { getThemePreference, applyTheme, initSystemThemeWatcher } from './lib/theme'
// Apply the *preference* (not the resolved theme) so a 'system' choice is
// preserved/persisted as 'system' and keeps tracking the OS. The flash-free
// first paint already happened via the inline <script> in index.html; this
// re-applies (idempotent) and wires up the live-OS-change watcher.
applyTheme(getThemePreference())
initSystemThemeWatcher()

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <Provider store={store}>
        <QueryClientProvider client={queryClient}>
          <App />
        </QueryClientProvider>
      </Provider>
    </AppErrorBoundary>
  </React.StrictMode>,
)
