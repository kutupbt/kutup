// Whether this browser runs WebAssembly. Every Kutup app does its
// cryptography in Rust compiled to WebAssembly (docs/cryptographic-dependencies.md),
// with no JavaScript fallback, so without it nothing can be opened or signed
// in. Safari's Lockdown Mode turns WebAssembly off for websites; some
// enterprise policies and hardened browsers do too.

/** The smallest valid module: the magic number and version 1. */
const EMPTY_MODULE = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])

let cached: boolean | null = null

/** Whether WebAssembly is present and compiles and instantiates a module. */
export function webAssemblySupported(): boolean {
  if (cached !== null) return cached
  cached = probe()
  return cached
}

function probe(): boolean {
  try {
    if (typeof WebAssembly !== 'object' || typeof WebAssembly.Module !== 'function') return false
    const module = new WebAssembly.Module(EMPTY_MODULE)
    return new WebAssembly.Instance(module) instanceof WebAssembly.Instance
  } catch {
    return false
  }
}

/** For tests: forget the probe's answer. */
export function resetWebAssemblyProbe(): void {
  cached = null
}
