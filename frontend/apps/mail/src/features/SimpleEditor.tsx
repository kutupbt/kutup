import { EditorContent, useEditor, type Editor } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'
import { Bold, Italic, Link as LinkIcon, List } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { Tooltip } from '@kutup/ui/components/tooltip'

function Tool({ label, active, onClick, children }: { label: string; active: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <Tooltip label={label}>
      <Button type="button" variant={active ? 'secondary' : 'ghost'} size="icon" className="size-8" aria-label={label} aria-pressed={active} onClick={onClick}>
        {children}
      </Button>
    </Tooltip>
  )
}

/** A small editor for a signature or an auto-reply: bold, italic, a list and links, as the composer's. `onChange` gets the HTML and the plain text, both empty when it is. */
export function SimpleEditor({ value, label, onChange }: { value: string; label: string; onChange: (html: string, text: string) => void }) {
  const { t } = useTranslation()
  const [linking, setLinking] = useState(false)
  const [href, setHref] = useState('https://')
  const editor = useEditor({
    extensions: [StarterKit.configure({ heading: false, codeBlock: false, link: { openOnClick: false, autolink: true, defaultProtocol: 'https' } })],
    content: value,
    editorProps: { attributes: { class: 'prose prose-sm max-w-none min-h-28 px-3 py-2 focus:outline-none dark:prose-invert', 'aria-label': label } },
    onUpdate: ({ editor: e }: { editor: Editor }) => (e.isEmpty ? onChange('', '') : onChange(e.getHTML(), e.getText({ blockSeparator: '\n\n' }))),
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
