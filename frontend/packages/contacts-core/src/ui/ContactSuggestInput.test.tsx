import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import api from '@kutup/session/client'
import { ContactSuggestInput } from './ContactSuggestInput'

function Harness() {
  const [value, setValue] = useState('')
  return <ContactSuggestInput aria-label="To" value={value} onValueChange={setValue} />
}

describe('ContactSuggestInput', () => {
  it('suggests contacts after two letters and fills the picked address', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({
      data: [{ contactId: 'c1', name: 'Ayşe Yılmaz', address: 'ayse@kutup.local', label: null }],
    })
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Harness />
      </QueryClientProvider>,
    )
    const box = screen.getByRole('combobox', { name: 'To' })
    await userEvent.type(box, 'ay')
    await waitFor(() => expect(get).toHaveBeenCalledWith('/contacts/emails', { params: { q: 'ay', limit: 20 } }))
    await userEvent.click(await screen.findByRole('option', { name: /Ayşe Yılmaz/ }))
    expect(box).toHaveValue('ayse@kutup.local')
  })
})
