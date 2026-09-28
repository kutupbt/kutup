// Everything a note can do, for the command palette (Ctrl/Cmd+P): views,
// panels, saving, and (Markdown notes, when editable) formatting, paragraph
// styles, inserts, links and folding. Each runs on the live editor.

import { foldAll, foldCode, unfoldAll, unfoldCode } from '@codemirror/language'
import type { StateCommand } from '@codemirror/state'
import type { EditorView } from '@codemirror/view'
import type { useTranslation } from 'react-i18next'
import {
  BookmarkPlus, BookOpen, Bold, ChevronsDownUp, ChevronsUpDown, Code, Columns2, ExternalLink, FoldVertical,
  Heading1, Heading2, Heading3, Heading4, Highlighter, History, Italic, Keyboard, Link, List, ListOrdered, ListTodo,
  ListTree, Maximize2, MessageSquareQuote, Minus, PencilLine, Quote, Save, Search, Sigma, SquareCode, Strikethrough,
  Table, Type, UnfoldVertical,
} from 'lucide-react'
import { INSERTS, insertBlock, insertLink, setLineStyle, toggleWrap, type LineStyle } from '../markdownCommands'
import { openLinkPicker } from '../links/linkPicker'
import type { MarkdownMode } from '../markdown/useMarkdownMode'
import type { PaletteItem } from './CommandPalette'

const MOD = typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/i.test(navigator.platform) ? '⌘' : 'Ctrl+'

type TFunction = ReturnType<typeof useTranslation>['t']

export interface NoteCommandContext {
  t: TFunction
  view: () => EditorView | null
  markdown: boolean
  editable: boolean
  setMode: (mode: MarkdownMode) => void
  toggleOutline: () => void
  toggleHistory: () => void
  toggleFocus: () => void
  showShortcuts: () => void
  openSwitcher: () => void
  save: (() => void) | null
  saveVersion: (() => void) | null
}

export function noteCommands(ctx: NoteCommandContext): PaletteItem[] {
  const { t } = ctx
  const onView = (run: (v: EditorView) => unknown) => () => {
    const v = ctx.view()
    if (!v) return
    run(v)
    v.focus()
  }
  const state = (cmd: StateCommand) => onView((v) => cmd(v))
  const groups = {
    view: t('editor.palette.groups.view'),
    file: t('editor.palette.groups.file'),
    format: t('editor.menu.format'),
    paragraph: t('editor.menu.paragraph'),
    insert: t('editor.menu.insert'),
    fold: t('editor.palette.groups.fold'),
  }
  const items: PaletteItem[] = []
  const add = (id: string, label: string, detail: string, icon: PaletteItem['icon'], run: () => void, keys?: string) =>
    items.push({ id, label, detail, icon, run, keys })

  add('switcher', t('editor.palette.switcher'), groups.view, <Search />, ctx.openSwitcher, `${MOD}O`)
  if (ctx.markdown) {
    add('mode-edit', t('editor.mode.edit'), groups.view, <PencilLine />, () => ctx.setMode('edit'))
    add('mode-split', t('editor.mode.split'), groups.view, <Columns2 />, () => ctx.setMode('split'))
    add('mode-read', t('editor.mode.read'), groups.view, <BookOpen />, () => ctx.setMode('read'))
    add('outline', t('editor.outline.title'), groups.view, <ListTree />, ctx.toggleOutline)
  }
  add('history', t('editor.historyTitle'), groups.view, <History />, ctx.toggleHistory)
  add('focus', t('editor.focus.enter'), groups.view, <Maximize2 />, ctx.toggleFocus, `${MOD}⇧F`)
  add('shortcuts', t('editor.shortcutsButton'), groups.view, <Keyboard />, ctx.showShortcuts)
  if (ctx.save) add('save', t('editor.save'), groups.file, <Save />, ctx.save, `${MOD}S`)
  if (ctx.saveVersion) add('save-version', t('editor.saveVersion'), groups.file, <BookmarkPlus />, ctx.saveVersion)

  if (ctx.markdown && ctx.editable) {
    add('link', t('editor.menu.addLink'), groups.insert, <Link />, onView((v) => openLinkPicker(v)), '[[')
    add('external-link', t('editor.menu.addExternalLink'), groups.insert, <ExternalLink />, state(insertLink), `${MOD}K`)
    add('bold', t('editor.shortcuts.bold'), groups.format, <Bold />, state(toggleWrap('**')), `${MOD}B`)
    add('italic', t('editor.shortcuts.italic'), groups.format, <Italic />, state(toggleWrap('_')), `${MOD}I`)
    add('strike', t('editor.menu.strikethrough'), groups.format, <Strikethrough />, state(toggleWrap('~~')))
    add('highlight', t('editor.menu.highlight'), groups.format, <Highlighter />, state(toggleWrap('==')))
    add('code', t('editor.shortcuts.code'), groups.format, <Code />, state(toggleWrap('`')), `${MOD}⇧C`)
    add('math', t('editor.menu.math'), groups.format, <Sigma />, state(toggleWrap('$')))
    const style = (id: string, label: string, icon: PaletteItem['icon'], s: LineStyle) =>
      add(id, label, groups.paragraph, icon, state(setLineStyle(s)))
    style('bullet', t('editor.menu.bullet'), <List />, 'bullet')
    style('number', t('editor.menu.numbered'), <ListOrdered />, 'number')
    style('task', t('editor.menu.task'), <ListTodo />, 'task')
    style('h1', t('editor.menu.heading', { level: 1 }), <Heading1 />, 'h1')
    style('h2', t('editor.menu.heading', { level: 2 }), <Heading2 />, 'h2')
    style('h3', t('editor.menu.heading', { level: 3 }), <Heading3 />, 'h3')
    style('h4', t('editor.menu.heading', { level: 4 }), <Heading4 />, 'h4')
    style('quote', t('editor.menu.quote'), <Quote />, 'quote')
    style('body', t('editor.menu.body'), <Type />, 'body')
    const insert = (id: string, label: string, icon: PaletteItem['icon'], b: { block: string; cursorAt: number }) =>
      add(id, label, groups.insert, icon, state(insertBlock(b.block, b.cursorAt)))
    insert('callout', t('editor.menu.callout'), <MessageSquareQuote />, INSERTS.callout)
    insert('table', t('editor.menu.table'), <Table />, INSERTS.table)
    insert('code-block', t('editor.menu.codeBlock'), <SquareCode />, INSERTS.codeBlock)
    insert('math-block', t('editor.menu.mathBlock'), <Sigma />, INSERTS.mathBlock)
    insert('rule', t('editor.menu.rule'), <Minus />, INSERTS.rule)
  }
  if (ctx.markdown) {
    add('fold', t('editor.palette.fold'), groups.fold, <FoldVertical />, onView((v) => foldCode(v)), `${MOD}⇧[`)
    add('unfold', t('editor.palette.unfold'), groups.fold, <UnfoldVertical />, onView((v) => unfoldCode(v)), `${MOD}⇧]`)
    add('fold-all', t('editor.palette.foldAll'), groups.fold, <ChevronsDownUp />, onView((v) => foldAll(v)), `${MOD}⌥[`)
    add('unfold-all', t('editor.palette.unfoldAll'), groups.fold, <ChevronsUpDown />, onView((v) => unfoldAll(v)), `${MOD}⌥]`)
  }
  return items
}
