import { Copy, Download } from 'lucide-react'
import { useMemo, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { copyText } from '@kutup/ui/lib/clipboard'
import { normalizeMnemonic } from './flows'

/**
 * Step 1: the 24 words, shown once. The phrase is the only way back into the
 * account if the password is lost — the server cannot reset what it cannot
 * read — so this screen says so plainly and offers copy and a text download.
 */
export function ShowRecoveryPhrase({
  mnemonic,
  email,
  onContinue,
}: {
  mnemonic: string
  email: string
  onContinue: () => void
}) {
  const { t } = useTranslation()
  const words = mnemonic.trim().split(/\s+/)

  function download() {
    const text = `${t('recoveryPhrase.fileHeader', { email })}\n\n${words
      .map((word, i) => `${i + 1}. ${word}`)
      .join('\n')}\n`
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'kutup-recovery-phrase.txt'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      <Alert variant="warn" title={t('recoveryPhrase.warningTitle')}>
        {t('recoveryPhrase.warning')}
      </Alert>
      <ol className="grid grid-cols-2 gap-x-6 gap-y-1.5 rounded-md border border-border bg-muted/40 p-4 sm:grid-cols-3">
        {words.map((word, i) => (
          <li key={i} className="flex items-baseline gap-2 font-mono text-sm">
            <span className="w-6 text-right text-xs text-muted-foreground">{i + 1}</span>
            <span>{word}</span>
          </li>
        ))}
      </ol>
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => {
            void copyText(words.join(' ')).then(() => toast.success(t('common.copied')))
          }}
        >
          <Copy />
          {t('common.copy')}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={download}>
          <Download />
          {t('recoveryPhrase.download')}
        </Button>
      </div>
      <Button type="button" className="w-full" onClick={onContinue}>
        {t('recoveryPhrase.saved')}
      </Button>
    </div>
  )
}

function pickPositions(count: number, total: number): number[] {
  const picked = new Set<number>()
  const random = new Uint32Array(1)
  while (picked.size < count) {
    crypto.getRandomValues(random)
    picked.add(random[0] % total)
  }
  return [...picked].sort((a, b) => a - b)
}

/**
 * Step 2: prove the phrase was written down by typing three of its words,
 * chosen at random. Retyping all 24 proves no more and loses people.
 */
export function ConfirmRecoveryPhrase({
  mnemonic,
  pending,
  error,
  onBack,
  onConfirmed,
}: {
  mnemonic: string
  pending: boolean
  error?: string | null
  onBack: () => void
  onConfirmed: () => void
}) {
  const { t } = useTranslation()
  const words = useMemo(() => normalizeMnemonic(mnemonic).split(' '), [mnemonic])
  const positions = useMemo(() => pickPositions(3, words.length), [words.length])
  const [answers, setAnswers] = useState<string[]>(() => positions.map(() => ''))
  const [mismatch, setMismatch] = useState(false)

  function submit(event: FormEvent) {
    event.preventDefault()
    const ok = positions.every((p, i) => (answers[i] ?? '').trim().toLowerCase() === words[p])
    setMismatch(!ok)
    if (ok) onConfirmed()
  }

  return (
    <form className="space-y-4" onSubmit={submit}>
      <p className="text-sm text-muted-foreground">{t('recoveryPhrase.confirmHint')}</p>
      {positions.map((position, i) => (
        <Field key={position} label={t('recoveryPhrase.wordNumber', { n: position + 1 })} required>
          {(field) => (
            <Input
              {...field}
              value={answers[i]}
              onChange={(event) =>
                setAnswers((prev) => prev.map((v, j) => (j === i ? event.target.value : v)))
              }
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              className="font-mono"
              autoFocus={i === 0}
            />
          )}
        </Field>
      ))}
      {mismatch ? <Alert variant="error">{t('recoveryPhrase.mismatch')}</Alert> : null}
      {error ? <Alert variant="error">{error}</Alert> : null}
      <div className="flex gap-2">
        <Button type="button" variant="outline" onClick={onBack} disabled={pending}>
          {t('common.back')}
        </Button>
        <Button type="submit" className="flex-1" loading={pending}>
          {t('recoveryPhrase.confirm')}
        </Button>
      </div>
    </form>
  )
}
