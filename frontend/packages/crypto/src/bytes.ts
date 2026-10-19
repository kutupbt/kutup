/**
 * Exactly a view's own bytes, copied into a fresh ArrayBuffer of its length.
 *
 * A typed array or DataView is often a view into a larger buffer: one that
 * WASM hands back is a window on the module's whole linear memory (keys,
 * plaintext), and `.subarray()` makes the same kind. Anything that takes
 * `view.buffer` (axios with a typed-array body, a Blob of `.buffer`, a
 * transfer list) takes the whole backing buffer, not the view. Every byte
 * that leaves for the network, storage or another context goes through here.
 */
export function exactBytes(view: ArrayBufferView): ArrayBuffer {
  return new Uint8Array(view.buffer, view.byteOffset, view.byteLength).slice().buffer
}
