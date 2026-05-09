import { useEffect, useRef, useState } from 'react'
import { splitFilename, joinFilename } from '@/lib/filename'
import { cn } from '@/lib/utils'

interface Props {
  filename: string
  /** Commits the new full filename (basename + locked ext re-joined).
   *  Returns true on success so we can fall back to the previous value
   *  on a network error. */
  onCommit: (newFullName: string) => Promise<boolean>
  className?: string
  /** Disable interactivity (e.g. while a network commit is in flight). */
  disabled?: boolean
}

// Click-to-edit filename — Google Docs style. Renders as text by default;
// click swaps to an input showing only the basename (the file's known
// extension stays locked and visible alongside). Enter or blur commits;
// Esc or unchanged reverts.
export default function EditableFilename({ filename, onCommit, className, disabled }: Props) {
  const { base, ext } = splitFilename(filename)
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(base)
  const [pending, setPending] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  // Reset the draft if the upstream filename changes (e.g. another tab
  // renamed the same file and we got fresh state).
  useEffect(() => { setDraft(base) }, [base])

  useEffect(() => {
    if (editing) {
      inputRef.current?.focus()
      inputRef.current?.select()
    }
  }, [editing])

  async function commit() {
    const trimmed = draft.trim()
    if (!trimmed || trimmed === base) {
      setDraft(base)
      setEditing(false)
      return
    }
    setPending(true)
    const ok = await onCommit(joinFilename(trimmed, ext))
    setPending(false)
    if (!ok) setDraft(base)  // server error → revert
    setEditing(false)
  }

  if (!editing) {
    return (
      <button
        type="button"
        onClick={() => !disabled && setEditing(true)}
        className={cn(
          'rounded px-1.5 py-0.5 text-sm font-medium truncate text-left max-w-[28rem] hover:bg-accent disabled:cursor-default disabled:hover:bg-transparent',
          className,
        )}
        title={filename}
        disabled={disabled}
      >
        {filename}
      </button>
    )
  }

  return (
    <span className={cn('inline-flex items-center gap-0.5 rounded border border-input bg-background px-1.5 py-0.5 ring-2 ring-ring', className)}>
      <input
        ref={inputRef}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') { e.preventDefault(); commit() }
          else if (e.key === 'Escape') { e.preventDefault(); setDraft(base); setEditing(false) }
        }}
        onBlur={() => commit()}
        disabled={pending}
        className="bg-transparent text-sm font-medium outline-none w-[18rem] max-w-[24rem]"
      />
      {ext && <span className="text-sm text-muted-foreground select-none">.{ext}</span>}
    </span>
  )
}
