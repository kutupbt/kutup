// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

let groups = false
vi.mock('../../app/chatStore', () => ({
  useGroupLinksEnabled: () => groups,
  getChatState: () => ({ capabilities: { mlsGroups: groups } }),
}))

const { MessageText } = await import('./MessageText')
const { closeJoinLink, openJoinLink, useJoinLink } = await import('../../lib/joinLink')

const LINK = `https://chat.example/join#${'a'.repeat(44)}`

function Shown() {
  return <output data-testid="join">{useJoinLink() ?? ''}</output>
}

afterEach(() => {
  groups = false
  closeJoinLink()
})

describe('group links with groups off', () => {
  it('shows a group link in a message as text, with nothing to open', () => {
    const { container } = render(<MessageText text={`join us ${LINK}`} outgoing={false} />)
    expect(screen.queryByRole('link')).toBeNull()
    expect(container.querySelector('p')).toHaveTextContent(`join us ${LINK}`)
  })

  it('still links other web addresses', () => {
    render(<MessageText text="see https://example.org/page" outgoing={false} />)
    expect(screen.getByRole('link')).toHaveAttribute('href', 'https://example.org/page')
  })

  it('opens nothing from /join or a pasted link', () => {
    render(<Shown />)
    openJoinLink(LINK)
    openJoinLink('')
    expect(screen.getByTestId('join')).toHaveTextContent('')
  })
})

describe('group links with groups on', () => {
  it('opens a group link from a message in the app', () => {
    groups = true
    render(
      <>
        <MessageText text={LINK} outgoing={false} />
        <Shown />
      </>,
    )
    fireEvent.click(screen.getByRole('link'))
    expect(screen.getByTestId('join')).toHaveTextContent(LINK)
  })
})
