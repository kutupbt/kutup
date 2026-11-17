// Vite turns `?url` imports into the emitted file's URL.
declare module '*.json?url' {
  const url: string
  export default url
}

// `?worker&url`: the worker bundled on its own, as its URL.
declare module '*?worker&url' {
  const url: string
  export default url
}
