import { render, waitFor } from '@testing-library/react'
import { forEachDiagnostic } from '@codemirror/lint'
import { EditorView } from '@codemirror/view'
import { describe, expect, it, vi } from 'vitest'
import SieveEditor from './SieveEditor'

vi.mock('next-themes', () => ({ useTheme: () => ({ resolvedTheme: 'light' }) }))

describe('the Sieve text editor', () => {
  it('shows the script, reports edits, and marks each problem where it is', async () => {
    const onChange = vi.fn()
    const script = 'require ["vacation"];\nvacation "away";\n'
    const { container, rerender } = render(<SieveEditor value={script} onChange={onChange} marks={[]} label="Sieve script" />)
    const content = container.querySelector<HTMLElement>('.cm-content')!
    expect(content.getAttribute('aria-label')).toBe('Sieve script')
    const view = EditorView.findFromDOM(container.querySelector<HTMLElement>('.cm-editor')!)!
    expect(view.state.doc.toString()).toBe(script)

    view.dispatch({ changes: { from: 0, insert: '# hi\n' } })
    expect(onChange).toHaveBeenLastCalledWith(`# hi\n${script}`)

    const from = view.state.doc.toString().indexOf('vacation "away";')
    rerender(<SieveEditor value={script} onChange={onChange} marks={[{ from, to: from + 16, message: 'not here' }, { from: 0, to: 9999, message: 'clamped' }]} label="Sieve script" />)
    await waitFor(() => {
      const found: { from: number; to: number; message: string }[] = []
      forEachDiagnostic(view.state, (d, f, t) => found.push({ from: f, to: t, message: d.message }))
      expect(found).toEqual([
        { from, to: from + 16, message: 'not here' },
        { from: 0, to: view.state.doc.length, message: 'clamped' },
      ])
    })
  })
})
