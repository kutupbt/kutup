// A short two-note chime for notifications, made with Web Audio so no sound
// file ships. Browsers allow it once the page has had a user gesture; before
// that the notification simply stays silent.

let context: AudioContext | null = null

export function playNotificationSound(): void {
  try {
    context ??= new AudioContext()
    const now = context.currentTime
    for (const [offset, frequency] of [[0, 880], [0.12, 1320]] as const) {
      const oscillator = context.createOscillator()
      const gain = context.createGain()
      oscillator.type = 'sine'
      oscillator.frequency.value = frequency
      gain.gain.setValueAtTime(0.0001, now + offset)
      gain.gain.exponentialRampToValueAtTime(0.18, now + offset + 0.02)
      gain.gain.exponentialRampToValueAtTime(0.0001, now + offset + 0.3)
      oscillator.connect(gain).connect(context.destination)
      oscillator.start(now + offset)
      oscillator.stop(now + offset + 0.32)
    }
  } catch {
    // No audio here: the notification itself still shows.
  }
}
