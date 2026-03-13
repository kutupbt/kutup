import * as bip39 from 'bip39'

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

export function encodeMnemonic(entropy: Uint8Array): string {
  if (entropy.length !== 32) throw new Error('Entropy must be 32 bytes (256-bit)')
  return bip39.entropyToMnemonic(bytesToHex(entropy))
}

export function decodeMnemonic(mnemonic: string): Uint8Array {
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic phrase')
  }
  return hexToBytes(bip39.mnemonicToEntropy(mnemonic))
}

export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(mnemonic.trim().toLowerCase())
}
