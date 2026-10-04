import { useEffect } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { useKeepFileSharesCurrent } from '@kutup/drive-core/fileShares'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { OfficeShell } from './app/OfficeShell'
import { HomePage } from './features/home/HomePage'
import { NotFoundPage } from './NotFoundPage'

/** When the sign-in ends (signed out elsewhere, expired), ask the account app again. */
function UnauthenticatedHandler() {
  useEffect(() => {
    setUnauthenticatedHandler(() => requestFork('office'))
  }, [])
  return null
}

/** Documents are Drive files: their shares follow the owner's key changes here too. */
function FileSharesUpkeep() {
  useKeepFileSharesCurrent()
  return null
}

export function App() {
  return (
    <BrowserRouter>
      <TooltipProvider delayDuration={300}>
        <Boot>
          <UnauthenticatedHandler />
          <FileSharesUpkeep />
          <Routes>
            <Route element={<OfficeShell />}>
              <Route index element={<HomePage />} />
              <Route path="/notes" element={<HomePage kind="note" />} />
              <Route path="/documents" element={<HomePage kind="document" />} />
              <Route path="/spreadsheets" element={<HomePage kind="spreadsheet" />} />
              <Route path="/presentations" element={<HomePage kind="presentation" />} />
              <Route path="/whiteboards" element={<HomePage kind="whiteboard" />} />
            </Route>
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Boot>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
