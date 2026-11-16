// @vitest-environment node
// Every app that opens Drive objects mounts ManifestSignerWarnings: a
// revision's signer is checked only where the watch is set
// (docs/plans/drive-block-format.md §10 slice 3), so an app that opens
// Drive content without it would never warn of a forged signature.
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const appsDir = new URL('../../../apps/', import.meta.url).pathname

/**
 * What opens a Drive object: the openers themselves, and the modules that
 * hand content to them (the editors, downloads, the keyring that says what
 * a revision must be, thumbnails and originals).
 */
const OPENERS = [
  /\bopenDriveFile\b/,
  /\bopenDriveObject\b/,
  /\bfetchDecryptedChunks\b/,
  /from '@kutup\/editors[/']/,
  /from '@kutup\/files\/download\//,
  /from '@kutup\/files\/zipDownload'/,
  /from '@kutup\/drive-core\/(keyring|original|thumbnails)'/,
]

function sources(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry)
    if (statSync(path).isDirectory()) out.push(...sources(path))
    else if (/\.(ts|tsx)$/.test(entry) && !/\.test\.(ts|tsx)$/.test(entry)) out.push(path)
  }
  return out
}

function appsOpeningDriveObjects(): string[] {
  return readdirSync(appsDir)
    .filter((app) => {
      try {
        return statSync(join(appsDir, app, 'src')).isDirectory()
      } catch {
        return false
      }
    })
    .filter((app) => sources(join(appsDir, app, 'src')).some((file) => OPENERS.some((opener) => opener.test(readFileSync(file, 'utf8')))))
    .sort()
}

describe('ManifestSignerWarnings', () => {
  it('finds the apps that open Drive objects', () => {
    // Drive, its documents, Photos, Pass vaults and Maps' place lists. A new
    // app that opens Drive content joins this list and mounts the warnings.
    expect(appsOpeningDriveObjects()).toEqual(['drive', 'maps', 'office', 'pass', 'photos'])
  })

  it('is mounted in each of them', () => {
    for (const app of appsOpeningDriveObjects()) {
      const root = readFileSync(join(appsDir, app, 'src', 'App.tsx'), 'utf8')
      expect(root, app).toMatch(/import \{ ManifestSignerWarnings \} from '@kutup\/drive-ui\/ManifestSignerWarnings'/)
      expect(root, app).toMatch(/<ManifestSignerWarnings \/>/)
    }
  })
})
