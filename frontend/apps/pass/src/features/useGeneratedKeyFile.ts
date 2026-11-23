import { useCallback, useEffect, useRef, useState } from 'react'
import { generateKeyFile } from '../vault/client'

/** Saves `contents` as a download named `name`; the bytes go nowhere else. */
function download(contents: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([contents as BlobPart], { type: 'application/octet-stream' }))
  try {
    const link = document.createElement('a')
    link.href = url
    link.download = name
    document.body.append(link)
    link.click()
    link.remove()
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 30_000)
  }
}

export interface GeneratedKeyFile {
  /** The key file's bytes, only while the dialog holds them. */
  bytes: () => Uint8Array | null
  /** Its download name, once made. */
  name: string | null
  /** The person said they saved it. */
  saved: boolean
  setSaved: (saved: boolean) => void
  /** Makes a new key file (KeePassXC's XML v2) and downloads it as `name`; false when it could not be made. */
  make: (name: string) => Promise<boolean>
  /** Wipes it. */
  forget: () => void
}

/**
 * A key file generated in a dialog (as KeePassXC's "Generate"): made in the
 * worker, downloaded once, never sent anywhere, and wiped from memory when
 * the dialog forgets it or goes.
 */
export function useGeneratedKeyFile(): GeneratedKeyFile {
  const bytes = useRef<Uint8Array | null>(null)
  const [name, setName] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const forget = useCallback(() => {
    bytes.current?.fill(0)
    bytes.current = null
    setName(null)
    setSaved(false)
  }, [])

  useEffect(
    () => () => {
      bytes.current?.fill(0)
      bytes.current = null
    },
    [],
  )

  const make = useCallback(
    async (fileName: string) => {
      forget()
      try {
        const file = await generateKeyFile()
        bytes.current = file
        setName(fileName)
        download(file, fileName)
        return true
      } catch {
        return false
      }
    },
    [forget],
  )

  return { bytes: () => bytes.current, name, saved, setSaved, make, forget }
}
