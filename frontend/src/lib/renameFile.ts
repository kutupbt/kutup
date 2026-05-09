// Re-encrypt a file's metadata blob with a new name and PUT it to the
// backend. Plaintext name never leaves the browser — the backend stores
// only the AEAD ciphertext + nonce. Extension-lock validation is the
// caller's job (see splitFilename in ./filename.ts).

import api from '@/api/client'
import { encrypt, toBase64 } from '@/crypto'
import type { DecryptedFile } from '@/types/drive'

export async function renameFile(
  file: DecryptedFile,
  newName: string,
  fileKey: Uint8Array,
): Promise<void> {
  const meta = {
    name: newName,
    mimeType: file.decryptedMimeType ?? '',
    size: file.decryptedSize ?? 0,
  }
  const plain = new TextEncoder().encode(JSON.stringify(meta))
  const enc = await encrypt(plain, fileKey)
  await api.put(`/files/${file.id}`, {
    encryptedMetadata: toBase64(enc.ciphertext),
    metadataNonce: toBase64(enc.nonce),
  })
}
