import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api from '../client'
import type { UserRow, AdminStats, AdminSettings } from '@/types/api'

export function useAdminUsers() {
  return useQuery<UserRow[]>({
    queryKey: ['admin', 'users'],
    queryFn: () => api.get<UserRow[]>('/admin/users').then((r) => r.data),
  })
}

export function useAdminStats() {
  return useQuery<AdminStats>({
    queryKey: ['admin', 'stats'],
    queryFn: () => api.get<AdminStats>('/admin/stats').then((r) => r.data),
  })
}

export function useAdminSettings() {
  return useQuery<AdminSettings>({
    queryKey: ['admin', 'settings'],
    queryFn: () => api.get<AdminSettings>('/admin/settings').then((r) => r.data),
  })
}

export function useCreateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: {
      email: string
      username: string
      tempPassword: string
      storageQuotaBytes: number
    }) => api.post('/admin/users', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'stats'] })
      toast.success('User created')
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Failed to create user')
    },
  })
}

export function useUpdateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      body,
    }: {
      id: string
      // `isAdmin` promotes/demotes; the backend rejects demoting the
      // break-glass admin (403) and the last usable admin (400).
      body: Partial<{ isActive: boolean; storageQuotaBytes: number; isAdmin: boolean }>
    }) => api.put(`/admin/users/${id}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Update failed')
    },
  })
}

/**
 * Admin override that force-disables a user's TOTP 2FA — for users locked
 * out of their authenticator. The account becomes password-only until the
 * user re-enables 2FA from their Security page.
 */
export function useForceDisable2fa() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/admin/users/${id}/2fa`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      toast.success('Two-factor authentication disabled for this user')
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Failed to disable 2FA')
    },
  })
}

export function useDeleteUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/admin/users/${id}`),
    onMutate: async (id: string) => {
      await qc.cancelQueries({ queryKey: ['admin', 'users'] })
      const prev = qc.getQueryData<UserRow[]>(['admin', 'users'])
      qc.setQueryData<UserRow[]>(['admin', 'users'], (old) => old?.filter((u) => u.id !== id) ?? [])
      return { prev }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'stats'] })
      toast.success('User deleted')
    },
    onError: (err: any, _id, ctx: any) => {
      qc.setQueryData(['admin', 'users'], ctx?.prev)
      toast.error(err.response?.data?.error ?? 'Delete failed')
    },
  })
}

export function useUpdateAdminSettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Partial<AdminSettings>) =>
      api.put('/admin/settings', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'settings'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Settings update failed')
    },
  })
}
