import { Copy, RefreshCw } from 'lucide-react'
import { useEffect, useId, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Tabs, TabsList, TabsTrigger } from '@kutup/ui/components/tabs'
import { copySecret } from '../lib/copySecret'
import { characterSets, entropyBits, EXTRA_GROUPS, generatePassword, groupCharacters, MAX_LENGTH, MIN_LENGTH } from '../lib/generator'
import { generatePassphrase, loadWordlist, MAX_WORDS, MIN_WORDS, passphraseBits, type WordCase } from '../lib/passphrase'
import { loadGeneratorSettings, saveGeneratorSettings, type GeneratorMode, type GeneratorSettings } from '../lib/generatorSettings'
import { useStrength } from '../lib/strength'

/** A value for the options: empty while the word list loads or no character is left. */
function make(settings: GeneratorSettings, words: string[] | null): string {
  if (settings.mode === 'passphrase') return words ? generatePassphrase(words, settings.passphrase) : ''
  return characterSets(settings.password).length > 0 ? generatePassword(settings.password) : ''
}

const TOGGLES = ['lower', 'upper', 'digits', 'symbols', 'avoidLookAlikes'] as const
const CASES: WordCase[] = ['lower', 'first', 'random']

/**
 * The generator (docs/plans/pass-gaps-3.md, A1), KeePassXC's: a password
 * from chosen sets and custom characters, or a passphrase from the EFF
 * list; its strength by zxcvbn. `onUse` hands the value to a field; without
 * it (the standalone page) there is Copy only.
 */
export function GeneratorPanel({ onUse }: { onUse?: (value: string) => void }) {
  const { t } = useTranslation()
  const id = useId()
  const rate = useStrength()
  const [settings, setSettingsState] = useState<GeneratorSettings>(loadGeneratorSettings)
  const [wordlist, setWordlist] = useState<string[] | null>(null)
  const [wordlistFailed, setWordlistFailed] = useState(false)
  const [candidate, setCandidate] = useState(() => make(settings, null))
  // The options as they are now, for the word list arriving later.
  const current = useRef(settings)

  const setSettings = (next: GeneratorSettings) => {
    current.current = next
    setSettingsState(next)
    saveGeneratorSettings(next)
    setCandidate(make(next, wordlist))
  }

  useEffect(() => {
    if (settings.mode !== 'passphrase' || wordlist) return
    let cancelled = false
    setWordlistFailed(false)
    loadWordlist().then(
      (words) => {
        if (cancelled) return
        setWordlist(words)
        if (current.current.mode === 'passphrase') setCandidate(make(current.current, words))
      },
      () => !cancelled && setWordlistFailed(true),
    )
    return () => {
      cancelled = true
    }
  }, [settings.mode, wordlist])

  const password = settings.password
  const phrase = settings.passphrase
  const noSets = settings.mode === 'password' && characterSets(password).length === 0
  const bits = settings.mode === 'password' ? entropyBits(password) : passphraseBits(phrase)
  const strength = candidate ? rate(candidate) : null

  return (
    <div className="space-y-4">
      <Tabs value={settings.mode} onValueChange={(mode) => setSettings({ ...settings, mode: mode as GeneratorMode })}>
        <TabsList>
          <TabsTrigger value="password">{t('generator.password')}</TabsTrigger>
          <TabsTrigger value="passphrase">{t('generator.passphrase')}</TabsTrigger>
        </TabsList>
      </Tabs>
      <div className="flex items-center gap-2">
        <code className="min-h-9 min-w-0 flex-1 break-all rounded bg-muted px-2 py-1.5 font-mono text-sm" aria-live="polite">
          {candidate || ' '}
        </code>
        <Button type="button" variant="ghost" size="icon" onClick={() => setCandidate(make(settings, wordlist))} disabled={noSets || (settings.mode === 'passphrase' && !wordlist)} aria-label={t('generator.again')}>
          <RefreshCw />
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          disabled={!candidate}
          aria-label={t('generator.copy')}
          onClick={() => void copySecret(candidate, t('detail.copied', { what: t('generator.value') }), t('detail.clipboardCleared'), t('detail.clipboardNotCleared'))}
        >
          <Copy />
        </Button>
      </div>
      {strength ? (
        <p className="text-xs text-muted-foreground">
          {t(`strength.${strength}`)} · {t('generator.bits', { bits })}
        </p>
      ) : null}
      {settings.mode === 'password' ? (
        <>
          <div className="space-y-1.5">
            <Label htmlFor={`${id}-length`}>{t('generator.length', { count: password.length })}</Label>
            <input
              id={`${id}-length`}
              type="range"
              min={MIN_LENGTH}
              max={MAX_LENGTH}
              value={password.length}
              onChange={(e) => setSettings({ ...settings, password: { ...password, length: Number(e.target.value) } })}
              className="w-full accent-primary"
            />
          </div>
          <div className="grid grid-cols-2 gap-2">
            {TOGGLES.map((name) => (
              <div key={name} className="flex items-center gap-2">
                <Checkbox id={`${id}-${name}`} checked={password[name]} onCheckedChange={(v) => setSettings({ ...settings, password: { ...password, [name]: v === true } })} />
                <Label htmlFor={`${id}-${name}`} className="text-sm font-normal">
                  {t(`generator.${name}`)}
                </Label>
              </div>
            ))}
          </div>
          {/* KeePassXC's finer groups (its Advanced view). */}
          <details className="text-sm" open={EXTRA_GROUPS.some((name) => password[name])}>
            <summary className="cursor-pointer text-xs text-muted-foreground">{t('generator.moreGroups')}</summary>
            <div className="mt-2 grid grid-cols-2 gap-2">
              {EXTRA_GROUPS.map((name) => (
                <div key={name} className="flex items-center gap-2">
                  <Checkbox id={`${id}-${name}`} checked={password[name]} onCheckedChange={(v) => setSettings({ ...settings, password: { ...password, [name]: v === true } })} />
                  <Label htmlFor={`${id}-${name}`} className="text-sm font-normal">
                    {t(`generator.groups.${name}`)}
                    {name === 'extended' ? null : <code className="ml-1 text-xs text-muted-foreground">{[...groupCharacters(name)].join(' ')}</code>}
                  </Label>
                </div>
              ))}
            </div>
          </details>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label htmlFor={`${id}-custom`} className="text-xs">
                {t('generator.custom')}
              </Label>
              <Input id={`${id}-custom`} value={password.custom} maxLength={128} onChange={(e) => setSettings({ ...settings, password: { ...password, custom: e.target.value } })} />
            </div>
            <div className="space-y-1">
              <Label htmlFor={`${id}-exclude`} className="text-xs">
                {t('generator.exclude')}
              </Label>
              <Input id={`${id}-exclude`} value={password.exclude} maxLength={128} onChange={(e) => setSettings({ ...settings, password: { ...password, exclude: e.target.value } })} />
            </div>
          </div>
          {noSets ? <Alert variant="error">{t('generator.noCharacters')}</Alert> : null}
        </>
      ) : (
        <>
          <div className="space-y-1.5">
            <Label htmlFor={`${id}-words`}>{t('generator.words', { count: phrase.words })}</Label>
            <input
              id={`${id}-words`}
              type="range"
              min={MIN_WORDS}
              max={MAX_WORDS}
              value={phrase.words}
              onChange={(e) => setSettings({ ...settings, passphrase: { ...phrase, words: Number(e.target.value) } })}
              className="w-full accent-primary"
            />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label htmlFor={`${id}-separator`} className="text-xs">
                {t('generator.separator')}
              </Label>
              <Input id={`${id}-separator`} value={phrase.separator} maxLength={8} onChange={(e) => setSettings({ ...settings, passphrase: { ...phrase, separator: e.target.value } })} />
            </div>
            <div className="space-y-1">
              <Label htmlFor={`${id}-case`} className="text-xs">
                {t('generator.case')}
              </Label>
              <Select value={phrase.wordCase} onValueChange={(wordCase) => setSettings({ ...settings, passphrase: { ...phrase, wordCase: wordCase as WordCase } })}>
                <SelectTrigger id={`${id}-case`}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CASES.map((value) => (
                    <SelectItem key={value} value={value}>
                      {t(`generator.cases.${value}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {(['addNumber', 'addSymbol'] as const).map((name) => (
              <div key={name} className="flex items-center gap-2">
                <Checkbox id={`${id}-${name}`} checked={phrase[name]} onCheckedChange={(v) => setSettings({ ...settings, passphrase: { ...phrase, [name]: v === true } })} />
                <Label htmlFor={`${id}-${name}`} className="text-sm font-normal">
                  {t(`generator.${name}`)}
                </Label>
              </div>
            ))}
          </div>
          {wordlistFailed ? <Alert variant="error">{t('generator.wordlistFailed')}</Alert> : null}
          <p className="text-xs text-muted-foreground">
            {t('generator.wordlistCredit')}{' '}
            <a href="https://www.eff.org/dice" target="_blank" rel="noreferrer noopener" className="underline">
              eff.org/dice
            </a>
          </p>
        </>
      )}
      {onUse ? (
        <Button type="button" className="w-full" disabled={!candidate} onClick={() => onUse(candidate)}>
          {t(settings.mode === 'passphrase' ? 'generator.usePassphrase' : 'generator.use')}
        </Button>
      ) : null}
    </div>
  )
}
