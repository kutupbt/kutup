import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Provider } from 'react-redux'
import { store } from './store'
import Register from './pages/Register'
import Login from './pages/Login'
import FirstLogin from './pages/FirstLogin'
import Recovery from './pages/Recovery'
import Drive from './pages/Drive'
import Admin from './pages/Admin'
import Settings from './pages/Settings'
import PublicShare from './pages/PublicShare'

export default function App() {
  return (
    <Provider store={store}>
      <BrowserRouter>
        {/* Spinner keyframe — injected globally */}
        <style>{`
          @keyframes spin { to { transform: rotate(360deg); } }
          a { color: inherit; }
          button:disabled { opacity: 0.6; cursor: not-allowed; }
          input, textarea { box-sizing: border-box; }
          input[type=number]::-webkit-inner-spin-button,
          input[type=number]::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }
          input[type=number] { -moz-appearance: textfield; }
        `}</style>
        <Routes>
          <Route path="/" element={<Navigate to="/drive" replace />} />
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<Login />} />
          <Route path="/first-login" element={<FirstLogin />} />
          <Route path="/recover" element={<Recovery />} />
          <Route path="/drive" element={<Drive />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/s/:token" element={<PublicShare />} />
        </Routes>
      </BrowserRouter>
    </Provider>
  )
}
