import { configureStore } from '@reduxjs/toolkit'
import { useDispatch, useSelector, TypedUseSelectorHook } from 'react-redux'
import authReducer from './authSlice'

const loadSession = () => {
  try {
    const raw = sessionStorage.getItem('depo_session')
    if (raw) return { auth: JSON.parse(raw) }
  } catch {}
  return undefined
}

export const store = configureStore({
  reducer: { auth: authReducer },
  preloadedState: loadSession(),
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: { ignoredActions: ['auth/setAuth'] },
    }),
})

store.subscribe(() => {
  const { auth } = store.getState()
  if (auth.accessToken) {
    sessionStorage.setItem('depo_session', JSON.stringify(auth))
  } else {
    sessionStorage.removeItem('depo_session')
  }
})

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch
export const useAppDispatch = () => useDispatch<AppDispatch>()
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector
