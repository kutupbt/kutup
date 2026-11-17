import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Input } from '@kutup/ui/components/input'
import { Section } from '@kutup/ui/components/page'
import { FormSkeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { adminKey } from './api'

interface ClientMinimum {
  clientType: string
  floor: string | null
  minimum: string | null
  effective: string | null
}

interface ClientVersions {
  release: string
  clients: ClientMinimum[]
}

const versionsKey = [...adminKey, 'client-versions'] as const

/** One client type's minimum, saved on its own. */
function MinimumRow({ client }: { client: ClientMinimum }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [value, setValue] = useState(client.minimum ?? '')
  const save = useMutation({
    mutationFn: async (minimum: string | null) =>
      (await api.put<ClientVersions>('/admin/client-versions', { clientType: client.clientType, minimum })).data,
    onSuccess: (data) => {
      queryClient.setQueryData(versionsKey, data)
      toast.success(t('admin.clientVersions.saved'))
    },
    onError: (error) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
  })
  const id = `client-minimum-${client.clientType}`
  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
      <label htmlFor={id} className="text-sm">
        <span className="block font-medium">{t(`admin.clientVersions.types.${client.clientType}`, client.clientType)}</span>
        <span className="block text-muted-foreground">
          {client.floor ? t('admin.clientVersions.floor', { version: client.floor }) : t('admin.clientVersions.noFloor')}
        </span>
      </label>
      <form
        className="flex gap-2"
        onSubmit={(event) => {
          event.preventDefault()
          save.mutate(value.trim() === '' ? null : value.trim())
        }}
      >
        <Input id={id} className="sm:w-40" value={value} placeholder={t('admin.clientVersions.placeholder')} onChange={(event) => setValue(event.target.value)} />
        <Button type="submit" variant="outline" loading={save.isPending} disabled={value.trim() === (client.minimum ?? '')}>
          {t('common.save')}
        </Button>
      </form>
    </div>
  )
}

/**
 * The oldest client version this server accepts, per app and the CLI
 * (docs/plans/api-surface.md §1.3). Older clients are told to update.
 */
export function ClientVersionsSection() {
  const { t } = useTranslation()
  const versions = useQuery({
    queryKey: versionsKey,
    queryFn: async () => (await api.get<ClientVersions>('/admin/client-versions')).data,
  })
  return (
    <Section title={t('admin.clientVersions.title')} description={t('admin.clientVersions.hint')}>
      <Card>
        <CardContent className="flex flex-col gap-4 p-5">
          {versions.isError ? (
            <Alert variant="error">{apiErrorMessage(versions.error, t('common.tryAgain'))}</Alert>
          ) : !versions.data ? (
            <FormSkeleton />
          ) : (
            <>
              <p className="text-sm text-muted-foreground">{t('admin.clientVersions.release', { release: versions.data.release })}</p>
              {versions.data.clients.map((client) => (
                <MinimumRow key={client.clientType} client={client} />
              ))}
            </>
          )}
        </CardContent>
      </Card>
    </Section>
  )
}
