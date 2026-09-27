// libheif-js ships its WASM bundle without types; the worker uses only this.
declare module 'libheif-js/libheif-wasm/libheif-bundle.mjs' {
  const factory: () => unknown
  export default factory
}
