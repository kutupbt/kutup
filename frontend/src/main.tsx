import './polyfills'
import './i18n'
import './index.css'
import { installTauriFetch } from './lib/httpClient'
// In the Tauri shell, route globalThis.fetch through tauri-plugin-http
// before anything issues a request — gives us CORS-free transport and the
// per-server "skip TLS verification" option. No-op on the web.
installTauriFetch()
import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Provider } from 'react-redux'
import { store } from './store'
import App from './App'

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

import { getTheme, applyTheme } from './lib/theme'
applyTheme(getTheme())

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Provider store={store}>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </Provider>
  </React.StrictMode>,
)
