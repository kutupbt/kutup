import { useEffect, useRef, useState, type RefObject } from 'react'

interface DetectedBarcode {
  rawValue: string
}

interface BarcodeDetectorInstance {
  detect(source: HTMLVideoElement): Promise<DetectedBarcode[]>
}

type BarcodeDetectorConstructor = new (options: { formats: string[] }) => BarcodeDetectorInstance

function browserBarcodeDetector(): BarcodeDetectorConstructor | undefined {
  return (window as typeof window & { BarcodeDetector?: BarcodeDetectorConstructor }).BarcodeDetector
}

export type QrScanFailure = 'unsupported' | 'camera'

export interface QrScanner {
  videoRef: RefObject<HTMLVideoElement>
  scanning: boolean
  start(): Promise<void>
  stop(): void
}

/**
 * Scan a QR code with the camera (the browser's BarcodeDetector): the first
 * code whose value starts with `prefix` goes to `onScanned`, and the camera
 * stops. A browser without a detector or camera says so through `onFailure`
 * (the person pastes the value instead). The camera is released on unmount.
 */
export function useQrScanner(
  prefix: string,
  onScanned: (value: string) => void,
  onFailure: (failure: QrScanFailure) => void,
): QrScanner {
  const videoRef = useRef<HTMLVideoElement>(null)
  const streamRef = useRef<MediaStream | null>(null)
  const timerRef = useRef<number | null>(null)
  const [scanning, setScanning] = useState(false)

  function stop() {
    if (timerRef.current !== null) window.clearTimeout(timerRef.current)
    timerRef.current = null
    streamRef.current?.getTracks().forEach((track) => track.stop())
    streamRef.current = null
    if (videoRef.current) videoRef.current.srcObject = null
    setScanning(false)
  }

  useEffect(() => stop, [])

  async function start() {
    const Detector = browserBarcodeDetector()
    if (!Detector || !navigator.mediaDevices?.getUserMedia) {
      onFailure('unsupported')
      return
    }
    try {
      stop()
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' } },
        audio: false,
      })
      streamRef.current = stream
      setScanning(true)
      const video = videoRef.current
      if (!video) {
        stop()
        return
      }
      video.srcObject = stream
      await video.play()
      const detector = new Detector({ formats: ['qr_code'] })
      const inspect = async () => {
        if (!streamRef.current || !videoRef.current) return
        try {
          const codes = await detector.detect(videoRef.current)
          const value = codes.find((code) => code.rawValue.startsWith(prefix))?.rawValue
          if (value) {
            stop()
            onScanned(value)
            return
          }
        } catch {
          // A frame may be unavailable while the camera warms up; keep scanning.
        }
        timerRef.current = window.setTimeout(() => void inspect(), 250)
      }
      void inspect()
    } catch {
      stop()
      onFailure('camera')
    }
  }

  return { videoRef, scanning, start, stop }
}
