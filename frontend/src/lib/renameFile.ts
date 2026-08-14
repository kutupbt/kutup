// Re-encrypt a file's metadata blob with a new name and PUT it to the
// backend. Plaintext name never leaves the browser — the backend stores
// only the AEAD ciphertext + nonce. Extension-lock validation is the
// caller's job (see splitFilename in ./filename.ts).

import api from '@/api/client'
import { renameFileRecordV1 } from '@/crypto'
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
  const update = await renameFileRecordV1(file, fileKey, meta)
  await api.put(`/files/${file.id}`, update)
  file.metadataEnvelope = update.metadataEnvelope
  file.metadataRevision = update.metadataRevision
}
