// Vite turns `?url` imports into the emitted file's URL.
declare module '*.json?url' {
  const url: string
  export default url
}
