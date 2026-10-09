import { ArrowLeft, Cake, Download, Globe, Mail, MapPin, Pencil, Phone, StickyNote, Trash2 } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { useAccountAddress, useDeleteContacts } from '@kutup/contacts-core/api'
import { displayName, type Contact, type ContactGroup } from '@kutup/contacts-core/model'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { ContactAvatar } from './ContactAvatar'
import { useEditor } from './editorState'
import { downloadVCards } from './exportVCards'

function Section({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <section className="flex gap-4 border-t border-border py-4">
      <span className="mt-0.5 text-muted-foreground [&_svg]:size-4" aria-hidden>{icon}</span>
      <div className="min-w-0 flex-1 space-y-2">
        <h2 className="sr-only">{title}</h2>
        {children}
      </div>
    </section>
  )
}

function Labelled({ label, children }: { label?: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="break-words text-sm">{children}</div>
      {label ? <div className="text-xs capitalize text-muted-foreground">{label}</div> : null}
    </div>
  )
}

/** A person: who they are, every way to reach them, and their groups. */
export function ContactView({ contact, groups, backTo }: { contact: Contact; groups: ContactGroup[]; backTo: string }) {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const editor = useEditor()
  const account = useAccountAddress()
  const remove = useDeleteContacts()
  const [confirming, setConfirming] = useState(false)
  const { draft } = contact
  const name = displayName(draft)
  const server = account.data?.split('@')[1]
  const memberOf = groups.filter((group) => draft.groups.includes(group.id))

  function birthday(value: string) {
    const noYear = value.startsWith('--')
    const date = new Date(noYear ? `2000-${value.slice(2)}T00:00:00` : `${value}T00:00:00`)
    if (Number.isNaN(date.getTime())) return value
    return date.toLocaleDateString(i18n.language, noYear ? { month: 'long', day: 'numeric' } : { year: 'numeric', month: 'long', day: 'numeric' })
  }

  return (
    <article className="mx-auto max-w-2xl p-4 sm:p-6" aria-label={name}>
      <Button variant="ghost" size="sm" className="mb-2 md:hidden" onClick={() => void navigate(backTo)}>
        <ArrowLeft />
        {t('contacts.back')}
      </Button>
      <header className="flex flex-wrap items-center gap-4 pb-4">
        <ContactAvatar draft={draft} size={80} />
        <div className="min-w-0 flex-1">
          <h1 className="break-words font-display text-2xl font-semibold">{name}</h1>
          {draft.title || draft.organization ? (
            <p className="text-sm text-muted-foreground">{[draft.title, draft.organization].filter(Boolean).join(' · ')}</p>
          ) : null}
          {memberOf.length > 0 ? (
            <div className="mt-2 flex flex-wrap gap-1">
              {memberOf.map((group) => (
                <Badge key={group.id} variant="neutral">
                  <span aria-hidden className="mr-1 inline-block size-2 rounded-full" style={{ background: group.color }} />
                  {group.name}
                </Badge>
              ))}
            </div>
          ) : null}
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => editor.open({ kind: 'edit', contact })}>
            <Pencil />
            {t('contacts.edit')}
          </Button>
          <Button variant="ghost" size="icon" onClick={() => downloadVCards([contact])} aria-label={t('contacts.exportOne')} title={t('contacts.exportOne')}>
            <Download />
          </Button>
          <Button variant="ghost" size="icon" onClick={() => setConfirming(true)} aria-label={t('contacts.delete')} title={t('contacts.delete')}>
            <Trash2 />
          </Button>
        </div>
      </header>

      {draft.emails.length > 0 ? (
        <Section icon={<Mail />} title={t('fields.emails')}>
          {draft.emails.map((email) => (
            <div key={email.address} className="flex flex-wrap items-center gap-2">
              <Labelled label={email.label}>
                <a href={`mailto:${email.address}`} className="hover:underline">{email.address}</a>
              </Labelled>
              {server && email.address.toLowerCase().endsWith(`@${server}`) ? (
                <Badge title={t('contacts.kutupAddressHint')}>{t('contacts.kutupAddress')}</Badge>
              ) : null}
            </div>
          ))}
        </Section>
      ) : null}
      {draft.phones.length > 0 ? (
        <Section icon={<Phone />} title={t('fields.phones')}>
          {draft.phones.map((phone, i) => (
            <Labelled key={i} label={phone.label}>
              <a href={`tel:${phone.value.replace(/[^\d+]/g, '')}`} className="hover:underline">{phone.value}</a>
            </Labelled>
          ))}
        </Section>
      ) : null}
      {draft.addresses.length > 0 ? (
        <Section icon={<MapPin />} title={t('fields.addresses')}>
          {draft.addresses.map((address, i) => (
            <Labelled key={i} label={address.label}>
              <span className="whitespace-pre-line">
                {[address.street, [address.postcode, address.locality].filter(Boolean).join(' '), address.region, address.country].filter(Boolean).join('\n')}
              </span>
            </Labelled>
          ))}
        </Section>
      ) : null}
      {draft.birthday ? (
        <Section icon={<Cake />} title={t('fields.birthday')}>
          <Labelled>{birthday(draft.birthday)}</Labelled>
        </Section>
      ) : null}
      {draft.urls.length > 0 ? (
        <Section icon={<Globe />} title={t('fields.urls')}>
          {draft.urls.map((url) => (
            <Labelled key={url}>
              <a href={/^https?:\/\//i.test(url) ? url : `https://${url}`} target="_blank" rel="noreferrer noopener" className="hover:underline">{url}</a>
            </Labelled>
          ))}
        </Section>
      ) : null}
      {draft.notes ? (
        <Section icon={<StickyNote />} title={t('fields.notes')}>
          <p className="whitespace-pre-wrap text-sm">{draft.notes}</p>
        </Section>
      ) : null}

      <ConfirmDestructive
        open={confirming}
        onOpenChange={setConfirming}
        title={t('contacts.deleteOneTitle', { name })}
        description={t('contacts.deleteOneDescription')}
        submit={t('contacts.delete')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('contacts.deleteFailed')}
        onConfirm={() =>
          remove.mutate([contact.id], {
            onSuccess: () => {
              setConfirming(false)
              toast.success(t('contacts.deleted', { count: 1 }))
              void navigate(backTo)
            },
          })
        }
      />
    </article>
  )
}
