import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { Toaster } from '@kutup/ui/components/sonner'
import { NotFoundPage } from './NotFoundPage'

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
      {/* Outside the routes so a toast survives the navigation after a save. */}
      <Toaster />
    </BrowserRouter>
  )
}
