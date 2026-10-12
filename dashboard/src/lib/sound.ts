let ctx: AudioContext | null = null;
let closeTimer: ReturnType<typeof setTimeout> | undefined;

export function playAlertSound(urgent: boolean) {
  try {
    ctx ??= new AudioContext();
    const notes = urgent ? [880, 660, 880] : [660, 880];
    notes.forEach((freq, i) => {
      const osc = ctx!.createOscillator();
      const gain = ctx!.createGain();
      const start = ctx!.currentTime + i * 0.16;
      osc.type = 'sine';
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0, start);
      gain.gain.linearRampToValueAtTime(0.12, start + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.14);
      osc.connect(gain).connect(ctx!.destination);
      osc.start(start);
      osc.stop(start + 0.15);
    });
    // An open AudioContext keeps Chromium's audio service process running.
    clearTimeout(closeTimer);
    closeTimer = setTimeout(() => {
      ctx?.close().catch(() => {});
      ctx = null;
    }, 2000);
  } catch {
    // Audio can be unavailable (no output device); alerts still show visually.
  }
}
