// The note editor's right-click menu, after Obsidian's: links, then Format,
// Paragraph and Insert for Markdown notes, then the clipboard. Each action
// runs on the editor and hands focus back to it.

import type { StateCommand } from '@codemirror/state'
import type { EditorView } from '@codemirror/view'
import { startCompletion } from '@codemirror/autocomplete'
import {
  Bold, ClipboardPaste, Highlighter, MessageSquareQuote, ClipboardType, Code, Copy, ExternalLink, Heading1, Heading2, Heading3, Heading4,
  Image as ImageIcon, Italic, Link, List, ListOrdered, ListTodo, Minus, Paintbrush, Pilcrow, Quote, Scissors,
  Sigma, SquareCode, SquareDashed, SquarePlus, Strikethrough, Table, Type,
} from 'lucide-react'
import { useRef, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  ContextMenu, ContextMenuContent, ContextMenuItem, ContextMenuSeparator, ContextMenuSub,
  ContextMenuSubContent, ContextMenuSubTrigger, ContextMenuTrigger,
} from '@kutup/ui/components/context-menu'
import { INSERTS, insertBlock, insertLink, setLineStyle, toggleWrap, type LineStyle } from './markdownCommands'

const MOD = typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/i.test(navigator.platform) ? '⌘' : 'Ctrl+'

function Shortcut({ keys }: { keys: string }) {
  return <span className="ml-auto pl-4 text-xs text-muted-foreground">{keys}</span>
}

export default function NoteContextMenu({
  view,
  markdown,
  readOnly,
  onPictures,
  children,
}: {
  /** The editor, once built. */
  view: () => EditorView | null
  /** Markdown notes get Format, Paragraph, Insert and links. */
  markdown: boolean
  readOnly: boolean
  /** Stores pictures into the note at the cursor; absent where pictures cannot be added. */
  onPictures?: (files: File[]) => void
  children: ReactNode
}) {
  const { t } = useTranslation()
  const pictureInput = useRef<HTMLInputElement>(null)

  /** Runs `action` on the editor, then gives it back the focus. */
  const on = (action: (v: EditorView) => void | boolean | Promise<void>) => () => {
    const v = view()
    if (!v) return
    void Promise.resolve(action(v)).finally(() => v.focus())
  }
  const command = (cmd: StateCommand) => on((v) => cmd(v))
  const selected = (v: EditorView) => v.state.selection.ranges.map((r) => v.state.sliceDoc(r.from, r.to)).join('\n')

  const copy = on(async (v) => {
    const text = selected(v)
    if (text) await navigator.clipboard.writeText(text).catch(() => toast.error(t('editor.menu.clipboardBlocked')))
  })
  const cut = on(async (v) => {
    const text = selected(v)
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      v.dispatch(v.state.replaceSelection(''), { userEvent: 'delete.cut' })
    } catch {
      toast.error(t('editor.menu.clipboardBlocked'))
    }
  })
  /** Paste: pictures go into the note (Markdown notes), text as text. */
  const paste = (plain: boolean) =>
    on(async (v) => {
      try {
        if (!plain && onPictures && navigator.clipboard.read) {
          const items = await navigator.clipboard.read()
          const pictures: File[] = []
          for (const item of items) {
            const type = item.types.find((ty) => ty.startsWith('image/'))
            if (type) pictures.push(new File([await item.getType(type)], `pasted.${type.split('/')[1]}`, { type }))
          }
          if (pictures.length) return onPictures(pictures)
        }
        const text = await navigator.clipboard.readText()
        if (text) v.dispatch(v.state.replaceSelection(text), { userEvent: 'input.paste', scrollIntoView: true })
      } catch {
        toast.error(t('editor.menu.clipboardBlocked'))
      }
    })
  const selectAll = on((v) => v.dispatch({ selection: { anchor: 0, head: v.state.doc.length } }))
  /** A Kutup link: the selection (if any) becomes the picker's search. */
  const addLink = on((v) => {
    const range = v.state.selection.main
    const text = v.state.sliceDoc(range.from, range.to).replace(/[\]\n]/g, ' ')
    const insert = `[[${text}`
    v.dispatch({ changes: { from: range.from, to: range.to, insert }, selection: { anchor: range.from + insert.length } })
    startCompletion(v)
  })

  const style = (s: LineStyle) => command(setLineStyle(s))
  const block = (b: { block: string; cursorAt: number }) => command(insertBlock(b.block, b.cursorAt))
  const editable = !readOnly
  const hasSelection = () => {
    const v = view()
    return Boolean(v && v.state.selection.ranges.some((r) => !r.empty))
  }

  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>{children}</ContextMenuTrigger>
      <ContextMenuContent className="min-w-56" onCloseAutoFocus={(e) => e.preventDefault()}>
        {markdown && editable ? (
          <>
            <ContextMenuItem onSelect={addLink}><Link /> {t('editor.menu.addLink')}</ContextMenuItem>
            <ContextMenuItem onSelect={command(insertLink)}><ExternalLink /> {t('editor.menu.addExternalLink')}</ContextMenuItem>
            <ContextMenuSeparator />
            <ContextMenuSub>
              <ContextMenuSubTrigger><Paintbrush /> {t('editor.menu.format')}</ContextMenuSubTrigger>
              <ContextMenuSubContent className="min-w-52">
                <ContextMenuItem onSelect={command(toggleWrap('**'))}><Bold /> {t('editor.shortcuts.bold')}<Shortcut keys={`${MOD}B`} /></ContextMenuItem>
                <ContextMenuItem onSelect={command(toggleWrap('_'))}><Italic /> {t('editor.shortcuts.italic')}<Shortcut keys={`${MOD}I`} /></ContextMenuItem>
                <ContextMenuItem onSelect={command(toggleWrap('~~'))}><Strikethrough /> {t('editor.menu.strikethrough')}</ContextMenuItem>
                <ContextMenuItem onSelect={command(toggleWrap('=='))}><Highlighter /> {t('editor.menu.highlight')}</ContextMenuItem>
                <ContextMenuItem onSelect={command(toggleWrap('`'))}><Code /> {t('editor.shortcuts.code')}<Shortcut keys={`${MOD}⇧C`} /></ContextMenuItem>
                <ContextMenuItem onSelect={command(toggleWrap('$'))}><Sigma /> {t('editor.menu.math')}</ContextMenuItem>
              </ContextMenuSubContent>
            </ContextMenuSub>
            <ContextMenuSub>
              <ContextMenuSubTrigger><Pilcrow /> {t('editor.menu.paragraph')}</ContextMenuSubTrigger>
              <ContextMenuSubContent className="min-w-52">
                <ContextMenuItem onSelect={style('bullet')}><List /> {t('editor.menu.bullet')}</ContextMenuItem>
                <ContextMenuItem onSelect={style('number')}><ListOrdered /> {t('editor.menu.numbered')}</ContextMenuItem>
                <ContextMenuItem onSelect={style('task')}><ListTodo /> {t('editor.menu.task')}</ContextMenuItem>
                <ContextMenuSeparator />
                <ContextMenuItem onSelect={style('h1')}><Heading1 /> {t('editor.menu.heading', { level: 1 })}</ContextMenuItem>
                <ContextMenuItem onSelect={style('h2')}><Heading2 /> {t('editor.menu.heading', { level: 2 })}</ContextMenuItem>
                <ContextMenuItem onSelect={style('h3')}><Heading3 /> {t('editor.menu.heading', { level: 3 })}</ContextMenuItem>
                <ContextMenuItem onSelect={style('h4')}><Heading4 /> {t('editor.menu.heading', { level: 4 })}</ContextMenuItem>
                <ContextMenuSeparator />
                <ContextMenuItem onSelect={style('quote')}><Quote /> {t('editor.menu.quote')}</ContextMenuItem>
                <ContextMenuItem onSelect={style('body')}><Type /> {t('editor.menu.body')}</ContextMenuItem>
              </ContextMenuSubContent>
            </ContextMenuSub>
            <ContextMenuSub>
              <ContextMenuSubTrigger><SquarePlus /> {t('editor.menu.insert')}</ContextMenuSubTrigger>
              <ContextMenuSubContent className="min-w-52">
                <ContextMenuItem onSelect={block(INSERTS.callout)}><MessageSquareQuote /> {t('editor.menu.callout')}</ContextMenuItem>
                <ContextMenuItem onSelect={block(INSERTS.table)}><Table /> {t('editor.menu.table')}</ContextMenuItem>
                <ContextMenuItem onSelect={block(INSERTS.codeBlock)}><SquareCode /> {t('editor.menu.codeBlock')}</ContextMenuItem>
                <ContextMenuItem onSelect={block(INSERTS.mathBlock)}><Sigma /> {t('editor.menu.mathBlock')}</ContextMenuItem>
                <ContextMenuItem onSelect={block(INSERTS.rule)}><Minus /> {t('editor.menu.rule')}</ContextMenuItem>
                {onPictures ? (
                  <ContextMenuItem onSelect={() => pictureInput.current?.click()}><ImageIcon /> {t('editor.menu.picture')}</ContextMenuItem>
                ) : null}
              </ContextMenuSubContent>
            </ContextMenuSub>
            <ContextMenuSeparator />
          </>
        ) : null}
        {editable ? (
          <ContextMenuItem onSelect={cut} disabled={!hasSelection()}><Scissors /> {t('editor.menu.cut')}</ContextMenuItem>
        ) : null}
        <ContextMenuItem onSelect={copy} disabled={!hasSelection()}><Copy /> {t('editor.menu.copy')}</ContextMenuItem>
        {editable ? (
          <>
            <ContextMenuItem onSelect={paste(false)}><ClipboardPaste /> {t('editor.menu.paste')}</ContextMenuItem>
            <ContextMenuItem onSelect={paste(true)}><ClipboardType /> {t('editor.menu.pastePlain')}</ContextMenuItem>
          </>
        ) : null}
        <ContextMenuItem onSelect={selectAll}><SquareDashed /> {t('editor.menu.selectAll')}</ContextMenuItem>
      </ContextMenuContent>
      {onPictures ? (
        <input
          ref={pictureInput}
          type="file"
          accept="image/png,image/jpeg,image/gif,image/webp,image/avif"
          multiple
          hidden
          onChange={(e) => {
            const files = [...(e.target.files ?? [])]
            e.target.value = ''
            if (files.length) onPictures(files)
          }}
        />
      ) : null}
    </ContextMenu>
  )
}
