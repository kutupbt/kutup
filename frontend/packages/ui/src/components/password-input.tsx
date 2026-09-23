import { Eye, EyeOff } from 'lucide-react'
import { forwardRef, useState, type InputHTMLAttributes } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '../lib/cn'
import { Input } from './input'

/**
 * A password field with a show/hide toggle. The toggle is a real button with
 * a pressed state, so a screen reader announces what it will do; it does not
 * take focus away from the form's tab order (it sits after the field).
 */
export const PasswordInput = forwardRef<
  HTMLInputElement,
  Omit<InputHTMLAttributes<HTMLInputElement>, 'type'>
>(function PasswordInput({ className, ...props }, ref) {
  const { t } = useTranslation()
  const [visible, setVisible] = useState(false)
  return (
    <div className="relative">
      <Input
        ref={ref}
        type={visible ? 'text' : 'password'}
        className={cn('pr-10', className)}
        spellCheck={false}
        autoCapitalize="off"
        {...props}
      />
      <button
        type="button"
        onClick={() => setVisible((v) => !v)}
        aria-pressed={visible}
        aria-label={visible ? t('common.hidePassword') : t('common.showPassword')}
        className={cn(
          'absolute inset-y-0 right-0 flex w-10 items-center justify-center rounded-r-md',
          'text-muted-foreground transition-colors hover:text-foreground',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
          '[&_svg]:size-4',
        )}
      >
        {visible ? <EyeOff /> : <Eye />}
      </button>
    </div>
  )
})
