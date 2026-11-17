// The generator's options on this device (never a generated value).

import { DEFAULT_OPTIONS, type GeneratorOptions } from './generator'
import { DEFAULT_PASSPHRASE, type PassphraseOptions } from './passphrase'

export type GeneratorMode = 'password' | 'passphrase'

export interface GeneratorSettings {
  mode: GeneratorMode
  password: GeneratorOptions
  passphrase: PassphraseOptions
}

const DEFAULT_SETTINGS: GeneratorSettings = { mode: 'password', password: DEFAULT_OPTIONS, passphrase: DEFAULT_PASSPHRASE }
const STORAGE_KEY = 'kutup-pass-generator'

/** This device's generator options (never a generated value). */
export function loadGeneratorSettings(): GeneratorSettings {
  try {
    const raw = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? 'null') as Partial<GeneratorSettings> | null
    if (!raw) return DEFAULT_SETTINGS
    return {
      mode: raw.mode === 'passphrase' ? 'passphrase' : 'password',
      password: { ...DEFAULT_OPTIONS, ...(raw.password ?? {}) },
      passphrase: { ...DEFAULT_PASSPHRASE, ...(raw.passphrase ?? {}) },
    }
  } catch {
    return DEFAULT_SETTINGS
  }
}

export function saveGeneratorSettings(settings: GeneratorSettings): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
  } catch {
    // Storage off: the options last this page.
  }
}

