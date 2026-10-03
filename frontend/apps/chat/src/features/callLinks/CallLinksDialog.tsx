import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, ExternalLink, Link2, Loader2, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { apiErrorCode } from '@kutup/ui/lib/apiError'
import { useChat } from '../../app/chatStore'
import { createCallLink, deleteCallLink, listCallLinks, type OwnedCallLink } from './callLinks'
import { rememberCallName } from './callName'

const QUERY = ['chat-call-links'] as const

/**
 * This account's call links: make one, copy it for someone, open it to join
 * the call, or delete it so nobody can join through it any more. A link is a
 * call anyone holding it can join, with or without a Kutup account.
 */
export function CallLinksDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const { snapshot, self } = useChat()
  const queryClient = useQueryClient()
  const [deleting, setDeleting] = useState<OwnedCallLink | null>(null)
  const links = useQuery({
    queryKey: QUERY,
    queryFn: () => listCallLinks(session.masterKey),
    enabled: open,
  })
  const create = useMutation({
    mutationFn: () => createCallLink(session.masterKey),
    onSuccess: (link) => {
      queryClient.setQueryData<OwnedCallLink[]>(QUERY, (previous) => [link, ...(previous ?? [])])
    },
    onError: (error) => {
      toast.error(apiErrorCode(error) === 'conflict' ? t('chat.callLinks.tooMany') : t('chat.callLinks.createFailed'))
    },
  })
  const remove = useMutation({
    mutationFn: (link: OwnedCallLink) => deleteCallLink(link.roomId),
    onSuccess: (_result, link) => {
      queryClient.setQueryData<OwnedCallLink[]>(QUERY, (previous) => (previous ?? []).filter((other) => other.roomId !== link.roomId))
      setDeleting(null)
    },
  })

  async function copy(link: OwnedCallLink) {
    try {
      await navigator.clipboard.writeText(link.url)
      toast.success(t('chat.callLinks.copied'))
    } catch {
      toast.error(t('chat.callLinks.copyFailed'))
    }
  }

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-lg" data-testid="chat-call-links">
          <DialogHeader>
            <DialogTitle>{t('chat.callLinks.title')}</DialogTitle>
            <DialogDescription>{t('chat.callLinks.description')}</DialogDescription>
          </DialogHeader>
          {links.isError ? <Alert variant="error">{t('chat.callLinks.loadFailed')}</Alert> : null}
          {links.isPending ? (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" aria-hidden />
              {t('common.loading')}
            </p>
          ) : null}
          {links.data && links.data.length === 0 ? (
            <p className="text-sm text-muted-foreground" data-testid="chat-call-links-empty">
              {t('chat.callLinks.empty')}
            </p>
          ) : null}
          {links.data && links.data.length > 0 ? (
            <ul className="max-h-[50vh] space-y-3 overflow-y-auto">
              {links.data.map((link) => (
                <li key={link.roomId} className="space-y-2 rounded-lg border border-border p-3" data-testid="chat-call-link">
                  <p className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Link2 className="size-3.5" aria-hidden />
                    {t('chat.callLinks.createdOn', {
                      date: new Date(link.createdAt).toLocaleString(i18n.language, { dateStyle: 'medium', timeStyle: 'short' }),
                    })}
                  </p>
                  <Input
                    readOnly
                    value={link.url}
                    aria-label={t('chat.callLinks.link')}
                    onFocus={(event) => event.target.select()}
                    className="font-mono text-xs"
                    data-testid="chat-call-link-url"
                  />
                  <div className="flex flex-wrap gap-2">
                    <Button type="button" size="sm" variant="outline" onClick={() => void copy(link)} data-testid="chat-call-link-copy">
                      <Copy />
                      {t('chat.callLinks.copy')}
                    </Button>
                    <Button type="button" size="sm" variant="outline" asChild>
                      <a
                        href={link.url}
                        target="_blank"
                        rel="noreferrer"
                        // The call opens with this account's name filled in.
                        onClick={() => rememberCallName(snapshot.profile?.displayName || self?.account.username || '')}
                        data-testid="chat-call-link-open"
                      >
                        <ExternalLink />
                        {t('chat.callLinks.join')}
                      </a>
                    </Button>
                    <Button type="button" size="sm" variant="ghost" className="ml-auto text-destructive" onClick={() => setDeleting(link)} data-testid="chat-call-link-delete">
                      <Trash2 />
                      {t('chat.callLinks.delete')}
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          ) : null}
          <div className="pt-2">
            <Button type="button" onClick={() => create.mutate()} disabled={create.isPending || links.isPending} data-testid="chat-call-link-create">
              {create.isPending ? <Loader2 className="animate-spin" /> : <Plus />}
              {t('chat.callLinks.create')}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(next) => {
          if (!next) setDeleting(null)
        }}
        title={t('chat.callLinks.deleteTitle')}
        description={t('chat.callLinks.deleteDescription')}
        submit={t('chat.callLinks.delete')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('chat.callLinks.deleteFailed')}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting)
        }}
      />
    </>
  )
}
