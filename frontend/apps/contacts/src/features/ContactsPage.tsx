import { Download, Pencil, Plus, Search, Trash2, Upload, Users } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { useContactGroups, useContacts, useDeleteContacts } from '@kutup/contacts-core/api'
import { displayName, type Contact } from '@kutup/contacts-core/model'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Input } from '@kutup/ui/components/input'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { EmptyState } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { ContactAvatar } from './ContactAvatar'
import { ContactView } from './ContactView'
import { useEditor } from './editorState'
import { downloadVCards } from './exportVCards'
import { GroupDialog } from './GroupDialog'
import { ImportDialog } from './ImportDialog'

/** Search over name, emails, phones and organisation, case- and accent-insensitive. */
function matches(contact: Contact, query: string): boolean {
  if (!query) return true
  const fold = (value: string) => value.toLocaleLowerCase('tr').normalize('NFKD').replace(/\p{M}/gu, '')
  const q = fold(query)
  const draft = contact.draft
  return [displayName(draft), draft.organization, ...draft.emails.map((e) => e.address), ...draft.phones.map((p) => p.value)]
    .some((value) => fold(value).includes(q))
}

/**
 * The address book: the list (search, letters, multi-select) and, beside it,
 * the chosen person, as Proton's contacts widget and details view.
 */
export function ContactsPage() {
  const { t, i18n } = useTranslation()
  const { id, groupId } = useParams()
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const query = params.get('q') ?? ''
  const contacts = useContacts()
  const groups = useContactGroups()
  const editor = useEditor()
  const remove = useDeleteContacts()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [importing, setImporting] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [editingGroup, setEditingGroup] = useState(false)

  const group = groupId ? groups.data?.find((g) => g.id === groupId) : undefined
  const base = groupId ? `/groups/${groupId}` : ''
  const all = useMemo(() => contacts.data?.contacts ?? [], [contacts.data])
  const visible = useMemo(() => {
    const collator = new Intl.Collator(i18n.language, { sensitivity: 'base' })
    return all
      .filter((contact) => !groupId || contact.draft.groups.includes(groupId))
      .filter((contact) => matches(contact, query))
      .sort((a, b) => collator.compare(displayName(a.draft), displayName(b.draft)))
  }, [all, groupId, query, i18n.language])
  const current = id ? all.find((contact) => contact.id === id) : undefined
  const chosen = visible.filter((contact) => selected.has(contact.id))

  function toggle(contactId: string, on: boolean) {
    setSelected((now) => {
      const next = new Set(now)
      if (on) next.add(contactId)
      else next.delete(contactId)
      return next
    })
  }

  function deleteChosen() {
    remove.mutate(
      chosen.map((contact) => contact.id),
      {
        onSuccess: () => {
          toast.success(t('contacts.deleted', { count: chosen.length }))
          setSelected(new Set())
          setConfirming(false)
          if (current && chosen.some((contact) => contact.id === current.id)) void navigate(base || '/')
        },
      },
    )
  }

  const list = (
    <section
      aria-label={t('contacts.list')}
      className={cn('flex min-h-0 flex-1 flex-col border-border md:w-80 md:flex-none md:shrink-0 md:border-r', current && 'hidden md:flex')}
    >
      <div className="space-y-3 border-b border-border p-3">
        <div className="flex items-center justify-between gap-2">
          <h1 className="truncate font-display text-lg font-semibold">{group ? group.name : t('nav.all')}</h1>
          <div className="flex shrink-0 gap-1">
            <Button variant="ghost" size="icon" className="md:hidden" onClick={() => editor.open({ kind: 'new', groupId })} aria-label={t('contacts.new')} title={t('contacts.new')}>
              <Plus />
            </Button>
            {group ? (
              <Button variant="ghost" size="icon" onClick={() => setEditingGroup(true)} aria-label={t('groups.edit')} title={t('groups.edit')}>
                <Pencil />
              </Button>
            ) : null}
            <Button variant="ghost" size="icon" onClick={() => setImporting(true)} aria-label={t('contacts.import')} title={t('contacts.import')}>
              <Upload />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              disabled={visible.length === 0}
              onClick={() => downloadVCards(chosen.length > 0 ? chosen : visible)}
              aria-label={chosen.length > 0 ? t('contacts.exportSelected', { count: chosen.length }) : t('contacts.exportAll')}
              title={chosen.length > 0 ? t('contacts.exportSelected', { count: chosen.length }) : t('contacts.exportAll')}
            >
              <Download />
            </Button>
          </div>
        </div>
        <label className="relative block">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            type="search"
            value={query}
            onChange={(e) => setParams((now) => {
              const next = new URLSearchParams(now)
              if (e.target.value) next.set('q', e.target.value)
              else next.delete('q')
              return next
            }, { replace: true })}
            placeholder={t('contacts.search')}
            aria-label={t('contacts.search')}
            className="pl-9"
          />
        </label>
        {chosen.length > 0 ? (
          <div className="flex items-center justify-between gap-2 text-sm">
            <span>{t('contacts.selected', { count: chosen.length })}</span>
            <Button variant="outline" size="sm" onClick={() => setConfirming(true)}>
              <Trash2 />
              {t('contacts.delete')}
            </Button>
          </div>
        ) : null}
      </div>
      {contacts.isPending ? (
        <div className="space-y-2 p-3">
          {[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-12 w-full" />)}
        </div>
      ) : contacts.isError ? (
        <Alert variant="error" className="m-3">{apiErrorMessage(contacts.error, t('common.tryAgain'))}</Alert>
      ) : visible.length === 0 ? (
        <div className="p-3">
          <EmptyState
            title={query ? t('contacts.noMatches') : group ? t('groups.empty') : t('contacts.empty')}
            description={query ? t('contacts.noMatchesHint') : t('contacts.emptyHint')}
            action={query ? undefined : <Button onClick={() => editor.open({ kind: 'new', groupId })}>{t('contacts.new')}</Button>}
          />
        </div>
      ) : (
        <ul className="min-h-0 flex-1 overflow-y-auto py-1">
          {visible.map((contact, index) => {
            const name = displayName(contact.draft)
            const letter = name.charAt(0).toLocaleUpperCase(i18n.language)
            const previous = index > 0 ? displayName(visible[index - 1].draft).charAt(0).toLocaleUpperCase(i18n.language) : null
            return (
              <li key={contact.id}>
                {letter !== previous ? (
                  <p className="px-4 pb-1 pt-3 text-xs font-medium text-muted-foreground" aria-hidden>
                    {letter}
                  </p>
                ) : null}
                <div className={cn('group flex items-center gap-3 px-3 py-2 hover:bg-muted/60', contact.id === id && 'bg-accent')}>
                  <Checkbox
                    checked={selected.has(contact.id)}
                    onCheckedChange={(on) => toggle(contact.id, on === true)}
                    aria-label={t('contacts.select', { name })}
                    className={cn(selected.size === 0 && 'opacity-0 group-hover:opacity-100 focus-visible:opacity-100')}
                  />
                  <Link to={`${base}/c/${contact.id}${query ? `?q=${encodeURIComponent(query)}` : ''}`} className="flex min-w-0 flex-1 items-center gap-3">
                    <ContactAvatar draft={contact.draft} size={32} />
                    <span className="min-w-0">
                      <span className="block truncate text-sm font-medium">{name}</span>
                      <span className="block truncate text-xs text-muted-foreground">
                        {contact.draft.emails[0]?.address ?? contact.draft.phones[0]?.value ?? contact.draft.organization}
                      </span>
                    </span>
                  </Link>
                </div>
              </li>
            )
          })}
        </ul>
      )}
      {contacts.data && contacts.data.unreadable > 0 ? (
        <Alert variant="warn" className="m-3">{t('contacts.unreadable', { count: contacts.data.unreadable })}</Alert>
      ) : null}
    </section>
  )

  return (
    <div className="flex h-full min-h-0">
      {list}
      <div className={cn('min-h-0 min-w-0 flex-1 overflow-y-auto', !current && 'hidden md:block')}>
        {current ? (
          <ContactView contact={current} groups={groups.data ?? []} backTo={base || '/'} />
        ) : id && contacts.isSuccess ? (
          <div className="p-6"><Alert>{t('contacts.notFound')}</Alert></div>
        ) : (
          <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center text-muted-foreground">
            <Users className="size-10" aria-hidden />
            <p className="text-sm">{t('contacts.pick')}</p>
          </div>
        )}
      </div>
      <ImportDialog open={importing} onOpenChange={setImporting} existing={all} />
      <GroupDialog open={editingGroup} onOpenChange={setEditingGroup} group={group} />
      <ConfirmDestructive
        open={confirming}
        onOpenChange={setConfirming}
        title={t('contacts.deleteTitle', { count: chosen.length })}
        description={t('contacts.deleteDescription', { count: chosen.length })}
        submit={t('contacts.delete')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('contacts.deleteFailed')}
        onConfirm={deleteChosen}
      />
    </div>
  )
}
