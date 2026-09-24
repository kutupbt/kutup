// A poster frame of a video (Drive thumbnails): the browser's own decoder in
// a detached <video>, seeked a little way in, drawn onto a canvas. Decoding
// needs the main thread (workers have no video element); it is one seek and
// one draw, under a deadline. A format the browser cannot play gives null.

/** Seek to 10% of the way in, but no further than this. */
const MAX_SEEK_SECONDS = 5

export async function captureVideoFrameV1(file: Blob, maxEdge: number, timeoutMs = 10_000): Promise<Blob | null> {
  const url = URL.createObjectURL(file)
  const video = document.createElement('video')
  video.muted = true
  video.playsInline = true
  video.preload = 'metadata'
  try {
    const frame = await new Promise<Blob | null>((resolve) => {
      const timer = setTimeout(() => resolve(null), timeoutMs)
      const done = (value: Blob | null) => {
        clearTimeout(timer)
        resolve(value)
      }
      video.onerror = () => done(null)
      video.onloadedmetadata = () => {
        if (!video.videoWidth || !video.videoHeight) return done(null)
        const duration = Number.isFinite(video.duration) ? video.duration : 0
        video.currentTime = Math.min(duration * 0.1, MAX_SEEK_SECONDS)
      }
      video.onseeked = () => {
        const scale = Math.min(1, maxEdge / Math.max(video.videoWidth, video.videoHeight))
        const canvas = document.createElement('canvas')
        canvas.width = Math.max(1, Math.round(video.videoWidth * scale))
        canvas.height = Math.max(1, Math.round(video.videoHeight * scale))
        const context = canvas.getContext('2d', { alpha: false })
        if (!context) return done(null)
        context.drawImage(video, 0, 0, canvas.width, canvas.height)
        canvas.toBlob((blob) => done(blob), 'image/png')
      }
      video.src = url
    })
    return frame
  } finally {
    video.removeAttribute('src')
    video.load()
    URL.revokeObjectURL(url)
  }
}
