import '@kutup/crypto/polyfills'
import '@kutup/ui/styles/fonts'
import './styles.css'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from 'next-themes'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { initI18n } from '@kutup/i18n'
import { configureClient } from '@kutup/session/client'
import { App } from './App'
import en from './locales/en.json'
import tr from './locales/tr.json'

initI18n({ en, tr })
configureClient({ clientType: 'web-maps' })

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 30_000 },
    mutations: { retry: 0 },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem storageKey="kutup-theme">
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </ThemeProvider>
  </StrictMode>,
)
