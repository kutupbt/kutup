import { forwardRef, type InputHTMLAttributes } from 'react'
import { cn } from '../lib/cn'

/**
 * A text box, and — with `type="file"` — a file picker that looks like it
 * belongs here.
 *
 * The file case needs its own treatment because the browser draws two things
 * inside the control: a button, and the words *"No file chosen"*. Left alone,
 * that button takes the platform's own chrome, which is why a screenshot of
 * this product showed a Linux GTK button sitting inside a rounded shadcn
 * field. The `file:` variants restyle the button; the rest of the box is the
 * same field every other control uses.
 *
 * `bg-card` rather than `bg-background`: inputs now sit inside cards, and a
 * field the same colour as the paper behind the card reads as a hole in it.
 */
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, type = 'text', ...props }, ref) {
    return (
      <input
        ref={ref}
        type={type}
        className={cn(
          'flex h-9 w-full rounded-md border border-input bg-card px-3 py-1 text-sm transition-colors',
          'placeholder:text-muted-foreground',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
          'disabled:cursor-not-allowed disabled:opacity-50',
          'aria-[invalid=true]:border-destructive aria-[invalid=true]:focus-visible:ring-destructive',
          type === 'file' &&
            'cursor-pointer py-1.5 text-muted-foreground file:mr-3 file:cursor-pointer ' +
              'file:rounded file:border-0 file:bg-secondary file:px-2.5 file:py-1 ' +
              'file:text-xs file:font-medium file:text-secondary-foreground',
          className,
        )}
        {...props}
      />
    )
  },
)
