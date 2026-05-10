// Rendered markdown preview pane for the notes editor's Split / Read modes.
//
// react-markdown does the AST + JSX render. Plugins:
// - remark-gfm: GitHub-Flavored Markdown (tables, task lists, strikethrough,
//   autolinks, footnotes). Matches what most users expect when they write .md.
// - rehype-sanitize: defense-in-depth XSS protection for user-authored
//   content. Notes are E2EE so the server never sees plaintext, but a
//   collaborator could embed <script> tags that fire on view.
// - rehype-highlight: code-block syntax highlighting using highlight.js.
//
// Styling: Tailwind's @tailwindcss/typography `prose` classes give sane
// defaults for headings/lists/code/blockquotes; `prose-invert` flips for
// dark mode. Sized via `prose-sm` because the preview pane sits next to
// the editor at half-width and full prose width feels cramped.
//
// Scroll sync: the parent passes a controlled scroll percentage; we apply
// it to the inner scroll container in a useEffect. Onscroll, we report the
// pane's own percentage so the parent can mirror back to the editor.

import { useEffect, useRef } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import rehypeSanitize from 'rehype-sanitize'
import rehypeHighlight from 'rehype-highlight'

interface Props {
  source: string
  /** 0..1 desired scroll position. Parent drives this when in Split mode. */
  scrollPercent?: number
  /** Notify parent of the user's own scroll inside this pane. */
  onScrollPercent?: (p: number) => void
  className?: string
}

export default function MarkdownPreview({
  source,
  scrollPercent,
  onScrollPercent,
  className,
}: Props) {
  const scrollRef = useRef<HTMLDivElement>(null)
  // Suppress the next scroll-event echo when the parent drives our position
  // (otherwise we'd report-back and create a feedback loop).
  const ignoreNextScroll = useRef(false)

  // Apply controlled scroll percent from parent.
  useEffect(() => {
    if (scrollPercent == null) return
    const el = scrollRef.current
    if (!el) return
    const max = el.scrollHeight - el.clientHeight
    if (max <= 0) return
    const target = Math.round(max * scrollPercent)
    if (Math.abs(el.scrollTop - target) < 2) return
    ignoreNextScroll.current = true
    el.scrollTop = target
  }, [scrollPercent])

  function handleScroll() {
    if (ignoreNextScroll.current) {
      ignoreNextScroll.current = false
      return
    }
    if (!onScrollPercent) return
    const el = scrollRef.current
    if (!el) return
    const max = el.scrollHeight - el.clientHeight
    if (max <= 0) {
      onScrollPercent(0)
      return
    }
    onScrollPercent(el.scrollTop / max)
  }

  return (
    <div
      ref={scrollRef}
      onScroll={handleScroll}
      className={
        'overflow-auto px-6 py-4 ' +
        'prose prose-sm dark:prose-invert max-w-none ' +
        // Make code-block + inline-code visible against both themes.
        'prose-code:before:hidden prose-code:after:hidden ' +
        (className ?? '')
      }
    >
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeSanitize, rehypeHighlight]}
      >
        {source}
      </ReactMarkdown>
    </div>
  )
}
