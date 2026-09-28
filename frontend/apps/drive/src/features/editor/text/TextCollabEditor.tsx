// TextCollabEditor: CodeMirror 6 + Yjs + AEAD-encrypted relay transport.
// Mounts in place of the existing file preview when the file extension matches a
// CodeMirror language (see ../components/editors/dispatch.tsx, written in G1).
import { useEffect, useMemo, useRef, useState } from 'react'
import * as Y from 'yjs'
import { yCollab } from 'y-codemirror.next'
import { Compartment, EditorState, type Extension } from '@codemirror/state'
import {
  EditorView, keymap,
  lineNumbers, highlightActiveLine, drawSelection,
  rectangularSelection, crosshairCursor, placeholder,
} from '@codemirror/view'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'
import { bracketMatching, defaultHighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { closeBrackets } from '@codemirror/autocomplete'
import { search, searchKeymap } from '@codemirror/search'
import { oneDark } from '@codemirror/theme-one-dark'
import { useResolvedTheme } from '../useResolvedTheme'

import { langForExtension } from './lang'
import { markdownNoteKeymap } from './markdownCommands'
import { liveMarkdown } from './liveMarkdown'
import { SnapshotTrigger } from '@kutup/collab/snapshot'
import { QuotaExceededError } from '@kutup/session/errors'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'
import { useRequiredSession } from '@kutup/session/store'
import { deterministicSeed, openCollabSession } from '@kutup/collab/session'
import { buildAwarenessName, withAlpha } from '@kutup/collab/identity'
import type { Awareness } from 'y-protocols/awareness'
import VersionHistoryPanel from '../versions/VersionHistoryPanel'
import RestoreConfirmDialog from '../versions/RestoreConfirmDialog'
import { Button } from '@kutup/ui/components/button'
import { Save, BookmarkPlus, History, X, Check, Keyboard, Eye } from 'lucide-react'
import { NameDialog } from '../../dialogs/NameDialog'
import EditorShortcutsDialog from '../EditorShortcutsDialog'
import CursorColorPicker from '../CursorColorPicker'
import { useCursorColor } from '../useCursorColor'
import { noteThumbnailScheduler } from '../../thumbnails/noteScheduler'
import MarkdownPreview from './markdown/MarkdownPreview'
import ModeToggle from './markdown/ModeToggle'
import StatusBar from './markdown/StatusBar'
import { countWords } from './markdown/countWords'
import { useMarkdownMode, nextMode, prevMode } from './markdown/useMarkdownMode'

interface Props {
  fileId: string
  filename: string
  /** The file's current key (32 bytes): collaboration frames and saved
   *  states are sealed under it. MUST be referentially stable across
   *  renders — otherwise the editor tears down and reconnects every parent
   *  re-render. */
  fileKey: Uint8Array
  /** The generation of `fileKey`, bound into every frame and saved state. */
  keyGeneration: number
  /** Plaintext content of the original encrypted file blob (kutup's existing per-file
   *  encryption flow). Used as the initial Y.Text content when no Yjs snapshot exists
   *  yet — i.e. on the very first time a freshly-uploaded file is opened in the editor.
   *  After the first Save Version, snapshots become canonical and this is ignored. */
  initialContent?: string
  /** View-only access: follow edits live, change nothing (no typing, no
   *  saving, no restoring). */
  readOnly?: boolean
  /** The file key of an older generation, for what was stored before the
   *  file's last re-key (log frames, saved states; docs/plans/drive-move.md). */
  fileKeyAt?: (generation: number) => Promise<Uint8Array>
  /** A file on another server: its calls go through this server (see `localBase`). */
  base?: string
}

/** The first content of a note no one has edited yet (see deterministicSeed). */
function seedUpdate(fileId: string, text: string): Uint8Array {
  return deterministicSeed(fileId, (doc) => doc.getText('content').insert(0, text))
}

/** Notes: room at the edges and a line length made for reading, centred. */
const NOTE_LAYOUT = EditorView.theme({
  '.cm-content': { maxWidth: '80ch', margin: '0 auto', padding: '16px 24px' },
})

/** The editor's look and code colours for Drive's theme. */
function editorTheme(theme: 'dark' | 'light'): Extension {
  return theme === 'dark' ? oneDark : syntaxHighlighting(defaultHighlightStyle)
}

export default function TextCollabEditor({
  fileId,
  filename,
  fileKey,
  keyGeneration,
  initialContent,
  readOnly = false,
  fileKeyAt,
  base,
}: Props) {
  const { t } = useTranslation()
  const ref = useRef<HTMLDivElement>(null)
  const [status, setStatus] = useState<'connecting' | 'ready' | 'error'>('connecting')
  const [trigger, setTrigger] = useState<SnapshotTrigger | null>(null)
  const triggerRef = useRef<SnapshotTrigger | null>(null)
  const [savingVersion, setSavingVersion] = useState(false)
  const [savingPlain, setSavingPlain] = useState(false)
  const [justSaved, setJustSaved] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [namingVersion, setNamingVersion] = useState(false)
  const [shortcutsOpen, setShortcutsOpen] = useState(false)
  const [restoreHandler, setRestoreHandler] = useState<((vid: string, choice: 'save-and-restore' | 'restore-only') => Promise<void>) | null>(null)
  const [pendingRestoreVersionId, setPendingRestoreVersionId] = useState<string | null>(null)
  // Cursor color: per-user via authSlice (persisted in DB via /user/me +
  // synced cross-tab via BroadcastChannel). Falls back to localStorage on
  // first load before authSlice has hydrated, or for users who haven't
  // picked a color yet — getCursorColor populates a random palette pick
  // and stashes it locally so the cursor is never invisible.
  const session = useRequiredSession()
  const username = session.username
  const storedDeviceId = session.currentDeviceId
  const [cursorColor, changeCursorColor] = useCursorColor()
  // Stable awareness ref so the color-picker callback can mutate the live
  // awareness state without re-mounting the editor.
  const awarenessRef = useRef<Awareness | null>(null)
  // Stable ytext ref so the markdown preview's checkbox-toggle handler
  // can mutate the document without re-mounting the editor. y-codemirror
  // .next picks the change up and dispatches a CM update — preview re-
  // renders with the new state.
  const ytextRef = useRef<Y.Text | null>(null)
  // EditorView ref so React effects can drive scroll back into the
  // editor (preview-side scroll sync uses this).
  const viewRef = useRef<EditorView | null>(null)
  // Compartment wrapping the CodeMirror theme extension so we can swap
  // light/dark without rebuilding the EditorView (which would tear down
  // cursor + selection state). One Compartment per mount.
  const themeCompartment = useMemo(() => new Compartment(), [])
  const theme = useResolvedTheme()
  // Ignore the next 'scroll' event after we apply a controlled scroll —
  // otherwise the editor's own onScroll re-emits scrollPercent and we
  // get a feedback loop with the preview.
  const ignoreEditorScrollRef = useRef(false)

  // Markdown view-mode state. The mode toggle (Edit/Split/Read) only
  // appears for .md/.markdown files; code files keep the plain editor.
  const isMarkdown = (() => {
    const dot = filename.lastIndexOf('.')
    if (dot < 0) return false
    const ext = filename.slice(dot + 1).toLowerCase()
    return ext === 'md' || ext === 'markdown'
  })()
  const [mdMode, setMdMode] = useMarkdownMode(fileId)
  // Live document content for the preview pane + word/char count. Updated
  // from the CodeMirror updateListener below — we read ytext.toJSON()
  // each tick so it picks up remote changes too.
  const [docText, setDocText] = useState<string>(initialContent ?? '')
  const [cursorPos, setCursorPos] = useState<{ line: number; col: number }>({ line: 1, col: 1 })
  // Scroll-percent state shared between editor pane and preview pane in
  // Split mode. The pane that scrolled most-recently is the source of
  // truth; the other mirrors via this state.
  const [scrollPercent, setScrollPercent] = useState<number>(0)
  // Number of remote collaborators currently online (excludes self).
  // Updated from awareness 'change' events.
  const [collaboratorCount, setCollaboratorCount] = useState<number>(0)

  // Toggle the Nth GFM task-list checkbox in the source. Pattern is
  // line-anchored to match only legal task-list syntax (CommonMark +
  // GFM). Mutating ytext via .delete + .insert propagates through
  // y-codemirror.next to the editor (and to remote peers via the
  // existing collab transport).
  function handleToggleTaskList(idx: number, checked: boolean) {
    const ytext = ytextRef.current
    if (!ytext) return
    const taskRE = /^([ \t]*[-*+] +)\[([ xX])\]/gm
    const src = ytext.toJSON()
    let i = 0
    for (const m of src.matchAll(taskRE)) {
      if (i === idx) {
        const pos = (m.index ?? 0) + m[1].length + 1
        const newChar = checked ? 'x' : ' '
        if (src[pos] === newChar) return
        ytext.delete(pos, 1)
        ytext.insert(pos, newChar)
        return
      }
      i++
    }
  }

  useEffect(() => {
    if (!ref.current) return
    const controller = new AbortController()
    let view: EditorView | null = null
    let cleanup: (() => void) | null = null

    void (async () => {
      // Only editors save; each saved version also redraws the thumbnail
      // (throttled; see noteThumbnailScheduler).
      // Thumbnails are stored with the file's own server: not from here for a
      // file on another one.
      const thumbnails = readOnly || base ? null : noteThumbnailScheduler({ fileId, fileKey, keyGeneration }, filename)
      let ytext: Y.Text | null = null
      // 1–6: the shared editing session (@kutup/collab/session).
      const session = await openCollabSession({
        fileId,
        base,
        fileKey,
        keyGeneration,
        fileKeyAt,
        readOnly,
        username,
        storedDeviceId,
        cursorColor,
        seed: initialContent
          ? {
              update: () => seedUpdate(fileId, initialContent),
              isEmpty: (doc) => doc.getText('content').length === 0,
            }
          : undefined,
        // CodeMirror sees a restore as a delete + insert.
        replaceContent: (live, old) => {
          const text = live.getText('content')
          const oldText = old.getText('content').toJSON()
          live.transact(() => {
            text.delete(0, text.length)
            text.insert(0, oldText)
          })
        },
        labels: {
          preRestore: () => t('editor.preRestoreLabel', { time: new Date().toLocaleString() }),
          restored: () => t('editor.restoredLabel', { time: new Date().toLocaleString() }),
        },
        onSnapshot: (versionId, explicit) => thumbnails?.saved(versionId, explicit, ytext?.toJSON() ?? ''),
        // A full storage is said once (the trigger disarms itself after a
        // 413); other autosave failures are only logged, not to spam users
        // on flaky networks.
        onSaveError: (err) => {
          if (err instanceof QuotaExceededError) toast.error(t('editor.quotaSave'))
          else console.warn('snapshot save failed', err)
        },
        onStatus: setStatus,
        onCollaborators: setCollaboratorCount,
        signal: controller.signal,
      })
      if (!session) {
        thumbnails?.flush()
        return
      }
      const { doc: ydoc, awareness, trigger: trig } = session
      ytext = ydoc.getText('content')
      ytextRef.current = ytext
      awarenessRef.current = awareness
      triggerRef.current = trig
      setTrigger(trig)
      if (session.restore) {
        const restore = session.restore
        setRestoreHandler(() => async (versionId: string, choice: 'save-and-restore' | 'restore-only') => {
          try {
            await restore(versionId, choice)
            toast.success(t('editor.restored'))
          } catch (e) {
            console.error('restore failed', e)
            toast.error(t('editor.restoreFailed'))
          }
        })
      }

      // 7. Build the CodeMirror editor.
      const ext = filename.split('.').pop()?.toLowerCase() ?? ''
      const langExt = langForExtension(ext)
      // Notes are writing, not code: lines wrap, no line numbers, a hint
      // when empty; Markdown notes also get formatting keys and lists
      // that continue on Enter.
      const prose = ext === 'md' || ext === 'markdown' || ext === 'txt'
      const markdownNote = prose && ext !== 'txt'
      // Cmd/Ctrl+S → force-save snapshot. Wires to the same `trig.forceSave()`
      // the Save button calls; `triggerRef.current` lets the closure see the
      // latest trigger instance even though it's captured at editor build time.
      const saveKeymap = keymap.of(trig ? [{
        key: 'Mod-s',
        preventDefault: true,
        run: () => {
          void (async () => {
            try {
              await trig.forceSave(undefined, false)
              setJustSaved(true)
              setTimeout(() => setJustSaved(false), 1200)
            } catch (e) { console.warn('save shortcut failed', e) }
          })()
          return true
        },
      }] : [])
      const exts: Extension[] = [
        // Note: saveKeymap and the user keymap come BEFORE search keymap
        // so Cmd+S still saves (search wires Cmd+F + a few others).
        saveKeymap,
        ...(markdownNote && !readOnly ? [keymap.of(markdownNoteKeymap)] : []),
        keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap]),
        history(),
        ...(langExt ? [langExt] : []),
        yCollab(ytext, awareness),
        // ---- Tier 1 baseline polish ----
        ...(prose ? [EditorView.lineWrapping, NOTE_LAYOUT] : [lineNumbers()]),
        // Markdown notes read like the note while you edit them.
        ...(markdownNote ? [liveMarkdown()] : []),
        ...(prose && !readOnly ? [placeholder(t('editor.notePlaceholder'))] : []),
        highlightActiveLine(),
        drawSelection(),
        bracketMatching(),
        closeBrackets(),
        search({ top: true }),
        rectangularSelection(),
        crosshairCursor(),
        EditorState.allowMultipleSelections.of(true),
        // Theme: dark mode picks oneDark (its own code colours); light mode
        // CodeMirror's default look with its default code colours.
        // Wrapped in a Compartment so the useEffect below can reconfigure
        // on theme change without rebuilding the EditorView.
        themeCompartment.of(editorTheme(theme)),
        ...(readOnly ? [EditorState.readOnly.of(true), EditorView.editable.of(false)] : []),
        // Click-anywhere fallback. CodeMirror's own posAtCoords handles
        // clicks within .cm-content correctly (snapping past line-end to
        // the line's end). For clicks BELOW the last line the wrapper
        // CSS makes .cm-content fill the height — but as a belt+braces
        // measure, if a click reports no position we move the caret to
        // end-of-document (matches Obsidian/VSCode behavior).
        EditorView.domEventHandlers({
          mousedown(event, v) {
            const pos = v.posAtCoords({ x: event.clientX, y: event.clientY })
            if (pos == null) {
              v.dispatch({ selection: { anchor: v.state.doc.length } })
              v.focus()
            }
          },
          scroll(_event, v) {
            // Mirror editor scroll into the React state so the preview
            // pane (in Split mode) follows along. The scrollDOM is the
            // CodeMirror outer scroller. Suppress when the document
            // hasn't grown beyond the viewport (no scroll possible),
            // and when the scroll was caused by a controlled-write from
            // the preview (would feedback-loop otherwise).
            if (ignoreEditorScrollRef.current) {
              ignoreEditorScrollRef.current = false
              return
            }
            const el = v.scrollDOM
            const max = el.scrollHeight - el.clientHeight
            if (max <= 0) return
            setScrollPercent(el.scrollTop / max)
          },
        }),
        // Track document content + cursor position for the status bar
        // and the markdown preview pane. Using updateListener over a
        // ViewPlugin keeps it ergonomic; the cost is one closure call
        // per dispatch, which is negligible at the dispatch rates Yjs
        // produces (typing is debounced upstream).
        EditorView.updateListener.of((u) => {
          if (u.docChanged) {
            setDocText(u.state.doc.toString())
          }
          if (u.selectionSet || u.docChanged) {
            const head = u.state.selection.main.head
            const line = u.state.doc.lineAt(head)
            setCursorPos({ line: line.number, col: head - line.from + 1 })
          }
        }),
      ]
      // Seed CodeMirror's initial doc from ytext so they're in sync at mount.
      // y-codemirror.next assumes parity at mount; if Y.Text was populated by the
      // snapshot-load step above and CM started empty, a later ytext.delete()
      // (e.g. from restore) would reference a CM range that doesn't exist.
      const state = EditorState.create({ doc: ytext.toJSON(), extensions: exts })
      view = new EditorView({ state, parent: ref.current! })
      viewRef.current = view
      // Seed the React state mirror to the editor's initial doc. Without
      // this, docText holds the stale `initialContent` (cold-start seed)
      // until the user's first keypress fires updateListener — meaning
      // the markdown preview rendered only the seed (often just the
      // "# Untitled" heading) until typing.
      setDocText(state.doc.toString())
      // Auto-focus on mount so the user can start typing immediately
      // without an extra click. Mirrors the way most editors behave on
      // open. Safe because the view is the primary interaction surface;
      // header buttons and dialogs still receive their own focus.
      view.focus()

      // 8. Cleanup on unmount.
      cleanup = () => {
        thumbnails?.flush()
        view?.destroy()
        session.close()
      }
      if (controller.signal.aborted) cleanup()
    })()

    return () => {
      controller.abort()
      cleanup?.()
    }
    // storedDeviceId is intentionally NOT a dep: the first render reads it
    // (often null), the registration flow sets it via dispatch, and React's
    // re-render would otherwise tear down + recreate the WS for no reason —
    // and on second mount the claimSeed call would lose, leaving the seed
    // un-inserted. Same pattern as OfficeEditor.tsx.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileId, filename, fileKey, username])

  // Page-level Cmd/Ctrl+S — catches the case when CodeMirror doesn't
  // have focus (filename input, color picker, history sidebar, etc.).
  // CM's own keymap (line ~360) still wins when CM is focused, which is
  // faster + cancels its default key bindings.
  // Also Cmd/Ctrl+E cycles markdown view modes (Edit → Split → Read),
  // matching Obsidian's binding. Only fires for .md/.markdown files.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && (e.key === 's' || e.key === 'S')) {
        const t = triggerRef.current
        if (!t) return
        e.preventDefault()
        t.forceSave(undefined, false)
          .then(() => { setJustSaved(true); setTimeout(() => setJustSaved(false), 1200) })
          .catch((err) => console.warn('save shortcut failed', err))
        return
      }
      if (isMarkdown && (e.metaKey || e.ctrlKey) && (e.key === 'e' || e.key === 'E')) {
        e.preventDefault()
        setMdMode(e.shiftKey ? prevMode(mdMode) : nextMode(mdMode))
        return
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [isMarkdown, mdMode, setMdMode])

  // Push live cursor-color updates to awareness without remounting the editor.
  useEffect(() => {
    const a = awarenessRef.current
    if (!a) return
    const prev = a.getLocalState() as { user?: { name?: string } } | null
    a.setLocalStateField('user', {
      name: prev?.user?.name ?? buildAwarenessName(username),
      color: cursorColor,
      colorLight: withAlpha(cursorColor, 0.3),
    })
  }, [cursorColor, username])

  // Drive the editor's scroll position from the shared scrollPercent
  // state — this is the preview-pane → editor leg of the bidirectional
  // sync (the editor → preview leg is handled by the scroll handler in
  // the extension list). Only active in Split mode; in Edit / Read the
  // panes don't share a viewport.
  useEffect(() => {
    if (!isMarkdown || mdMode !== 'split') return
    const v = viewRef.current
    if (!v) return
    const el = v.scrollDOM
    const max = el.scrollHeight - el.clientHeight
    if (max <= 0) return
    const target = Math.round(max * scrollPercent)
    if (Math.abs(el.scrollTop - target) < 2) return
    ignoreEditorScrollRef.current = true
    el.scrollTop = target
  }, [scrollPercent, mdMode, isMarkdown])

  // Reactive theme: when kutup's theme toggles, reconfigure the
  // Compartment instead of rebuilding the view.
  useEffect(() => {
    viewRef.current?.dispatch({
      effects: themeCompartment.reconfigure(editorTheme(theme)),
    })
  }, [theme, themeCompartment])

  const statusDot = status === 'ready'
    ? 'bg-primary'
    : status === 'connecting'
      ? 'bg-status-warn animate-pulse'
      : 'bg-destructive'

  return (
    <div className="flex h-full w-full flex-col">
      <div className="flex h-12 items-center gap-3 border-b border-border bg-background/95 px-4">
        <div className="flex min-w-0 items-center gap-2">
          <span className={`inline-block h-2 w-2 rounded-full ${statusDot}`} aria-hidden />
          <span className="truncate text-sm font-medium">{filename}</span>
          <span className="text-xs text-muted-foreground" role="status">· {t(`editor.status.${status}`)}</span>
        </div>

        <div className="ml-auto flex items-center gap-2">
          {isMarkdown && <ModeToggle mode={mdMode} onChange={setMdMode} />}
          <CursorColorPicker color={cursorColor} onChange={changeCursorColor} />
          {readOnly ? (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-muted px-2.5 py-1 text-xs font-medium text-muted-foreground">
              <Eye className="h-3.5 w-3.5" aria-hidden /> {t('editor.viewOnly')}
            </span>
          ) : (<>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={!trigger || savingPlain || savingVersion}
            onClick={() => void (async () => {
              if (!trigger) return
              setSavingPlain(true)
              try {
                await trigger.forceSave(undefined, false)
                setJustSaved(true)
                setTimeout(() => setJustSaved(false), 1200)
              } catch (e) {
                toast.error(e instanceof QuotaExceededError ? t('editor.quotaSave') : t('common.tryAgain'))
              } finally {
                setSavingPlain(false)
              }
            })()}
            title={t('editor.saveHint')}
            className="gap-1.5"
          >
            {justSaved ? <Check className="h-4 w-4 text-primary" /> : <Save className="h-4 w-4" />}
            {savingPlain ? t('editor.saving') : justSaved ? t('editor.saved') : t('editor.save')}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={!trigger || savingVersion || savingPlain}
            onClick={() => setNamingVersion(true)}
            title={t('editor.saveVersionHint')}
            className="gap-1.5"
          >
            <BookmarkPlus className="h-4 w-4" />
            {savingVersion ? t('editor.saving') : t('editor.saveVersion')}
          </Button>
          </>)}
          <Button
            type="button"
            size="sm"
            variant={historyOpen ? 'default' : 'outline'}
            onClick={() => setHistoryOpen((v) => !v)}
            className="gap-1.5"
          >
            <History className="h-4 w-4" />
            {t('editor.history')}
          </Button>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            onClick={() => setShortcutsOpen(true)}
            title={t('editor.shortcutsButton')}
            aria-label={t('editor.shortcutsButton')}
          >
            <Keyboard />
          </Button>
        </div>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">
        {/* The CSS class trio is what fixes the "can't click anywhere"
            bug: by default CM6 sizes .cm-editor to its content, so the
            scroll area below the last line was dead. h-full on the
            CodeMirror root + min-h-full on .cm-content makes the
            content area fill the wrapper, so clicks below the text
            land inside .cm-content and CM positions the caret at the
            nearest line. The mousedown handler in the extension list
            above is the belt-and-suspenders fallback for the rare
            null-pos case. */}
        <div
          ref={ref}
          className={
            'overflow-auto [&>.cm-editor]:h-full [&_.cm-content]:min-h-full ' +
            (isMarkdown && mdMode === 'read'
              ? 'hidden'
              : isMarkdown && mdMode === 'split'
                ? 'flex-1 min-w-0 border-r border-border'
                : 'flex-1')
          }
        />

        {/* Markdown preview pane. Visible in Split (50/50) and Read
            (full) modes; hidden in Edit. Source pulls from the live
            ytext via docText state, updated by the editor's
            updateListener — that means remote edits via Yjs propagate
            to the preview within the same React tick. */}
        {isMarkdown && (mdMode === 'split' || mdMode === 'read') && (
          <MarkdownPreview
            source={docText}
            scrollPercent={mdMode === 'split' ? scrollPercent : undefined}
            onScrollPercent={mdMode === 'split' ? setScrollPercent : undefined}
            onToggleTaskList={readOnly ? undefined : handleToggleTaskList}
            className={mdMode === 'split' ? 'flex-1 min-w-0' : 'flex-1'}
          />
        )}

        {historyOpen && (
          <aside className="flex h-full w-[360px] min-h-0 shrink-0 flex-col overflow-hidden border-l border-border bg-card">
            <header className="flex h-12 shrink-0 items-center justify-between border-b border-border px-4">
              <h2 className="text-sm font-semibold">{t('editor.historyTitle')}</h2>
              <Button
                type="button"
                size="icon"
                variant="ghost"
                onClick={() => setHistoryOpen(false)}
                aria-label={t('editor.closeHistory')}
                className="h-7 w-7"
              >
                <X className="h-4 w-4" />
              </Button>
            </header>
            <div className="flex-1 min-h-0 overflow-y-auto overscroll-contain">
              <VersionHistoryPanel
                base={base}
                fileId={fileId}
                onRestore={(vid) => setPendingRestoreVersionId(vid)}
                readOnly={readOnly}
              />
            </div>
          </aside>
        )}
      </div>

      {/* Status bar — shown in Edit + Split (where the editor is visible
          and cursor position is meaningful). Hidden in Read mode where
          the editor isn't visible. Shown for both markdown and code
          files since line:col + word/char count is useful in code too.
       */}
      {mdMode !== 'read' && (
        <StatusBar
          cursorLine={cursorPos.line}
          cursorCol={cursorPos.col}
          words={countWords(docText)}
          chars={docText.length}
          collaborators={collaboratorCount}
        />
      )}

      <RestoreConfirmDialog
        open={pendingRestoreVersionId !== null}
        onCancel={() => setPendingRestoreVersionId(null)}
        onChoose={(choice) => {
          const vid = pendingRestoreVersionId
          setPendingRestoreVersionId(null)
          if (vid && restoreHandler) restoreHandler(vid, choice).catch(() => {})
        }}
      />

      <NameDialog
        open={namingVersion}
        title={t('editor.nameVersion.title')}
        description={t('editor.nameVersion.description')}
        initial=""
        submit={t('editor.saveVersion')}
        pending={savingVersion}
        error={null}
        onClose={() => setNamingVersion(false)}
        onSubmit={(name) => void (async () => {
          if (!trigger) return
          setSavingVersion(true)
          try {
            await trigger.forceSave(name, true)
            setNamingVersion(false)
          } catch (e) {
            toast.error(e instanceof QuotaExceededError ? t('editor.quotaSave') : t('common.tryAgain'))
          } finally {
            setSavingVersion(false)
          }
        })()}
      />
      <EditorShortcutsDialog
        open={shortcutsOpen}
        onOpenChange={setShortcutsOpen}
        showMarkdownShortcuts={isMarkdown}
      />
    </div>
  )
}
