// The ring of an incoming call, made with Web Audio: two short tones every
// two seconds until stopped.

let context: AudioContext | null = null

export function startRingtone(): () => void {
  let stopped = false
  const ring = () => {
    if (stopped) return
    try {
      context ??= new AudioContext()
      const now = context.currentTime
      for (const offset of [0, 0.4]) {
        const oscillator = context.createOscillator()
        const gain = context.createGain()
        oscillator.frequency.value = 660
        gain.gain.setValueAtTime(0.0001, now + offset)
        gain.gain.exponentialRampToValueAtTime(0.15, now + offset + 0.03)
        gain.gain.exponentialRampToValueAtTime(0.0001, now + offset + 0.35)
        oscillator.connect(gain).connect(context.destination)
        oscillator.start(now + offset)
        oscillator.stop(now + offset + 0.36)
      }
    } catch {
      // No audio: the screen still shows the call.
    }
  }
  ring()
  const timer = setInterval(ring, 2000)
  return () => {
    stopped = true
    clearInterval(timer)
  }
}
