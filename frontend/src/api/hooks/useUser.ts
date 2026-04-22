import { useQuery } from '@tanstack/react-query'
import api from '../client'
import type { MeResponse, UserByEmailResponse } from '@/types/api'

export function useMe() {
  return useQuery<MeResponse>({
    queryKey: ['user', 'me'],
    queryFn: () => api.get<MeResponse>('/user/me').then((r) => r.data),
    staleTime: 60_000,
  })
}

export function useUserByEmail(email: string | null) {
  return useQuery<UserByEmailResponse>({
    queryKey: ['user', 'by-email', email],
    queryFn: () =>
      api
        .get<UserByEmailResponse>(`/users/by-email/${encodeURIComponent(email!)}`)
        .then((r) => r.data),
    enabled: email !== null && email.length > 0,
    retry: false,
  })
}
