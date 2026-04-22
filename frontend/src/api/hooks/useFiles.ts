import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api from '../client'
import type { FileRow } from '@/types/api'

export function useFiles(collectionId: string | null) {
  return useQuery<FileRow[]>({
    queryKey: ['files', collectionId],
    queryFn: () =>
      api.get<FileRow[]>(`/collections/${collectionId}/files`).then((r) => r.data),
    enabled: collectionId !== null,
  })
}

export function useRemoteFiles(remoteShareId: string | null) {
  return useQuery<FileRow[]>({
    queryKey: ['remote-files', remoteShareId],
    queryFn: () =>
      api.get<FileRow[]>(`/fed-proxy/${remoteShareId}/files`).then((r) => r.data),
    enabled: remoteShareId !== null,
  })
}

export function useDeleteFile() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      fileId,
      collectionId,
      remoteShareId,
    }: {
      fileId: string
      collectionId: string
      remoteShareId?: string
    }) => {
      const url = remoteShareId
        ? `/fed-proxy/${remoteShareId}/files/${fileId}`
        : `/files/${fileId}`
      return api.delete(url)
    },
    onMutate: async ({ fileId, collectionId, remoteShareId }) => {
      const key = remoteShareId ? ['remote-files', remoteShareId] : ['files', collectionId]
      await qc.cancelQueries({ queryKey: key })
      const prev = qc.getQueryData<FileRow[]>(key)
      qc.setQueryData<FileRow[]>(key, (old) => old?.filter((f) => f.id !== fileId) ?? [])
      return { prev, key }
    },
    onError: (err: any, _vars, ctx: any) => {
      if (ctx?.prev) qc.setQueryData(ctx.key, ctx.prev)
      toast.error(err.response?.data?.error ?? 'Delete failed')
    },
  })
}

export function useCreatePublicShare() {
  return useMutation({
    mutationFn: (body: {
      shareType: string
      targetId: string
      encryptedCollectionKey: string
      encryptedCollectionKeyNonce: string
      expiresInHours?: number
    }) =>
      api
        .post<{ token: string }>('/share/', body)
        .then((r) => r.data),
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Failed to create link')
    },
  })
}
