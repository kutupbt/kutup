import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api from '../client'
import type { CollectionRow } from '@/types/api'

export function useCollections() {
  return useQuery<CollectionRow[]>({
    queryKey: ['collections'],
    queryFn: () => api.get<CollectionRow[]>('/collections/').then((r) => r.data),
  })
}

export function useCreateCollection() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: {
      encryptedName: string
      nameNonce: string
      encryptedKey: string
      encryptedKeyNonce: string
      parentCollectionId: string | null
    }) => api.post<{ id: string }>('/collections/', body).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['collections'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Failed to create folder')
    },
  })
}

export function useUpdateCollection() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: { encryptedName: string; nameNonce: string } }) =>
      api.put(`/collections/${id}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['collections'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Failed to rename folder')
    },
  })
}

export function useDeleteCollection() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/collections/${id}`),
    onMutate: async (id: string) => {
      await qc.cancelQueries({ queryKey: ['collections'] })
      const prev = qc.getQueryData<CollectionRow[]>(['collections'])
      qc.setQueryData<CollectionRow[]>(['collections'], (old) => old?.filter((c) => c.id !== id) ?? [])
      return { prev }
    },
    onError: (err: any, _id, ctx: any) => {
      qc.setQueryData(['collections'], ctx?.prev)
      toast.error(err.response?.data?.error ?? 'Failed to delete folder')
    },
  })
}

export function useUpdateCollectionColor() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, color }: { id: string; color: string | null }) =>
      api.patch(`/collections/${id}/color`, { color }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['collections'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Failed to update color')
    },
  })
}

export function useShareCollection() {
  return useMutation({
    mutationFn: ({
      id,
      body,
    }: {
      id: string
      body: {
        recipientUserId: string
        encryptedCollectionKey: string
        canUpload: boolean
        canDelete: boolean
        uploadQuotaBytes: number | null
      }
    }) => api.post(`/collections/${id}/share`, body).then((r) => r.data),
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Share failed')
    },
  })
}

export function useShareFederated() {
  return useMutation({
    mutationFn: ({
      id,
      body,
    }: {
      id: string
      body: {
        recipientUsername: string
        recipientServer: string
        encryptedCollectionKey: string
        canUpload: boolean
        canDelete: boolean
        uploadQuotaBytes: number | null
      }
    }) =>
      api
        .post<{ inviteUrl: string }>(`/collections/${id}/federated-shares`, body)
        .then((r) => r.data),
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Federated share failed')
    },
  })
}
