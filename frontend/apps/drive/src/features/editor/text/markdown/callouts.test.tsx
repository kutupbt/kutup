import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { calloutKind } from './callouts'

vi.mock('mermaid', () => ({ default: { initialize: () => undefined, render: () => Promise.resolve({ svg: '' }) } }))
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (k: string) => k }) }))
const { default: MarkdownPreview } = await import('./MarkdownPreview')

const html = (source: string) => renderToStaticMarkup(<MarkdownPreview source={source} />)

describe('callouts', () => {
  it('turns a [!type] quote into a titled callout', () => {
    const out = html('> [!warning] Mind the gap\n> Trains leave at 07:40.')
    expect(out).toContain('class="callout callout-warning"')
    expect(out).toContain('class="callout-title"')
    expect(out).toContain('Mind the gap')
    expect(out).toContain('Trains leave at 07:40.')
    expect(out).not.toContain('[!warning]')
    expect(out).not.toContain('<blockquote')
  })

  it('names an untitled callout by its kind, aliases included', () => {
    expect(html('> [!tip]\n> body')).toContain('editor.callout.tip')
    expect(calloutKind('Caution')).toBe('warning')
    expect(calloutKind('whatever')).toBe('note')
  })

  it('leaves plain quotes as quotes', () => {
    expect(html('> just a quote')).toContain('<blockquote')
  })
})

describe('highlights', () => {
  it('marks ==text==, not inside code', () => {
    const out = html('a ==bright== idea and `==code==`')
    expect(out).toContain('<mark>bright</mark>')
    expect(out).toContain('<code>==code==</code>')
  })

  it('ignores lone or spaced equals signs', () => {
    expect(html('a == b and == c')).not.toContain('<mark>')
  })
})
