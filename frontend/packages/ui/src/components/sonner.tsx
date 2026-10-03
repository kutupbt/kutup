import { useTheme } from 'next-themes'
import { Toaster as Sonner } from 'sonner'

/**
 * Transient confirmations.
 *
 * **Load-bearing, not decoration.** Once an authoring form is a page rather
 * than a modal, a successful save navigates away — and the user arrives back at
 * a list with no statement that anything happened. The dialog that used to
 * close *was* the confirmation; without a replacement, saving and failing to
 * save look identical from the destination.
 *
 * Copy follows `docs/frontend/visual-direction.md`: the button that says
 * *Publish* produces *Published*. Same verb, past tense — not "Success", which
 * says an operation completed without saying which one, on a screen that has
 * already changed.
 *
 * Errors stay in `Alert`, in the page, next to the thing that failed. A toast
 * disappears, and a message somebody needs to read and act on must not.
 *
 * `richColors` is off: the palette in `tokens.css` is the product's, and
 * sonner's own would be a second green and a second red with no relationship
 * to the status tokens.
 */
export function Toaster() {
  const { resolvedTheme } = useTheme()

  return (
    <Sonner
      theme={resolvedTheme === 'dark' ? 'dark' : 'light'}
      position="bottom-right"
      // The tokens, so a toast belongs to the same surface as the cards behind
      // it in both themes.
      toastOptions={{
        classNames: {
          toast: 'bg-card text-card-foreground border border-border shadow-lg',
          description: 'text-muted-foreground',
          actionButton: 'bg-primary text-primary-foreground',
          cancelButton: 'bg-muted text-muted-foreground',
        },
      }}
    />
  )
}
