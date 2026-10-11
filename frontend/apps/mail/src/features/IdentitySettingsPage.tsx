import { EditorContent, useEditor, type Editor } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'
import { Bold, Italic, Link as LinkIcon, List } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useMailIdentity, useUpdateMailIdentity } from '@kutup/mail-core/api'
import { sanitizeSignature } from '@kutup/mail-core/sanitize'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

function Tool({ label, active, onClick, children }: { label: string; active: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <Tooltip label={label}>
      <Button type="button" variant={active ? 'secondary' : 'ghost'} size="icon" className="size-8" aria-label={label} aria-pressed={active} onClick={onClick}>
        {children}
      </Button>
    </Tooltip>
  )
}

/** The signature editor: bold, italic, a list and links, as the composer's. */
function SignatureEditor({ value, onChange }: { value: string; onChange: (html: string) => void }) {
  const { t } = useTranslation()
  const [linking, setLinking] = useState(false)
  const [href, setHref] = useState('https://')
  const editor = useEditor({
    extensions: [StarterKit.configure({ heading: false, codeBlock: false, link: { openOnClick: false, autolink: true, defaultProtocol: 'https' } })],
    content: value,
    editorProps: { attributes: { class: 'prose prose-sm max-w-none min-h-28 px-3 py-2 focus:outline-none dark:prose-invert', 'aria-label': t('identity.signature') } },
    onUpdate: ({ editor: e }: { editor: Editor }) => onChange(e.isEmpty ? '' : e.getHTML()),
  })
  if (!editor) return null
  function addLink() {
    const target = href.trim()
    if (!editor || !/^(https:\/\/|mailto:)\S+$/i.test(target)) return
    editor.chain().focus().extendMarkRange('link').setLink({ href: target }).run()
    setLinking(false)
    setHref('https://')
  }
  return (
    <div className="rounded-md border border-input">
      <div className="flex gap-1 border-b border-border px-1 py-1">
        <Tool label={t('compose.bold')} active={editor.isActive('bold')} onClick={() => editor.chain().focus().toggleBold().run()}>
          <Bold />
        </Tool>
        <Tool label={t('compose.italic')} active={editor.isActive('italic')} onClick={() => editor.chain().focus().toggleItalic().run()}>
          <Italic />
        </Tool>
        <Tool label={t('compose.bulletList')} active={editor.isActive('bulletList')} onClick={() => editor.chain().focus().toggleBulletList().run()}>
          <List />
        </Tool>
        <Tool
          label={t('identity.link')}
          active={editor.isActive('link') || linking}
          onClick={() => {
            if (editor.isActive('link')) editor.chain().focus().unsetLink().run()
            else setLinking((now) => !now)
          }}
        >
          <LinkIcon />
        </Tool>
        {linking ? (
          // Not a <form>: the editor sits inside the page's form.
          <div className="flex flex-1 items-center gap-1">
            <Input
              autoFocus
              className="h-8"
              value={href}
              onChange={(e) => setHref(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  addLink()
                }
              }}
              aria-label={t('identity.linkPrompt')}
            />
            <Button type="button" size="sm" variant="outline" className="h-8" onClick={addLink}>
              {t('identity.addLink')}
            </Button>
          </div>
        ) : null}
      </div>
      <EditorContent editor={editor} />
    </div>
  )
}

/** Settings → Identity (Proton's Identity and addresses): display name and signature. */
export function IdentitySettingsPage() {
  const { t } = useTranslation()
  const identity = useMailIdentity()
  const update = useUpdateMailIdentity()
  const [name, setName] = useState('')
  const [signature, setSignature] = useState('')
  const [error, setError] = useState<string | undefined>()
  const loaded = identity.data
  useEffect(() => {
    if (loaded) {
      setName(loaded.displayName)
      setSignature(loaded.signature)
    }
  }, [loaded])

  if (identity.isPending) return <LoadingPanel label={t('common.loading')} />
  if (identity.isError) return <Alert variant="error">{apiErrorMessage(identity.error, t('common.tryAgain'))}</Alert>

  function save() {
    const trimmed = name.trim()
    if (trimmed.length > 100) {
      setError(t('identity.nameTooLong'))
      return
    }
    const clean = sanitizeSignature(signature)
    if (new TextEncoder().encode(clean).length > 10_000) {
      toast.error(t('identity.signatureTooLong'))
      return
    }
    update.mutate(
      { displayName: trimmed, signature: clean },
      {
        onSuccess: () => toast.success(t('general.saved')),
        onError: (e) => toast.error(apiErrorMessage(e, t('common.tryAgain'))),
      },
    )
  }

  return (
    <PageBody>
      <PageHeader title={t('identity.title')} description={t('identity.description', { address: identity.data.address })} />
      <form
        className="max-w-2xl space-y-5"
        onSubmit={(e) => {
          e.preventDefault()
          save()
        }}
      >
        <Field label={t('identity.displayName')} description={t('identity.displayNameHint')} error={error}>
          {(props) => (
            <Input
              {...props}
              value={name}
              maxLength={100}
              onChange={(e) => {
                setName(e.target.value)
                setError(undefined)
              }}
            />
          )}
        </Field>
        <div className="space-y-2">
          <p className="text-sm font-medium">{t('identity.signature')}</p>
          <p className="text-sm text-muted-foreground">{t('identity.signatureHint')}</p>
          {loaded ? <SignatureEditor key={loaded.address} value={loaded.signature} onChange={setSignature} /> : null}
        </div>
        <Button type="submit" disabled={update.isPending}>
          {t('common.save')}
        </Button>
      </form>
    </PageBody>
  )
}
