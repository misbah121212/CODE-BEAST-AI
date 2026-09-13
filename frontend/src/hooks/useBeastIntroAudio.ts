"use client";
import { useRef, useCallback } from "react";

type AnyAudioNode = AudioNode & { stop?: () => void };

function makeDistortionCurve(amount = 20): Float32Array {
  const n_samples = 44100;
  const curve = new Float32Array(n_samples);
  const deg = Math.PI / 180;
  for (let i = 0; i < n_samples; ++i) {
    const x = (i * 2) / n_samples - 1;
    curve[i] = ((3 + amount) * x * 20 * deg) / (Math.PI + amount * Math.abs(x));
  }
  return curve as any;
}

function makeBrownNoise(ctx: AudioContext, seconds: number): AudioBuffer {
  const sr = ctx.sampleRate;
  const buf = ctx.createBuffer(1, sr * seconds, sr);
  const d = buf.getChannelData(0);
  let last = 0;
  for (let i = 0; i < d.length; i++) {
    const white = Math.random() * 2 - 1;
    last = (last + 0.02 * white) / 1.02;
    d[i] = last * 3.5;
  }
  return buf;
}

export function useBeastIntroAudio() {
  const ctxRef = useRef<AudioContext | null>(null);
  const masterGainRef = useRef<GainNode | null>(null);
  const audioElemRef = useRef<HTMLAudioElement | null>(null);
  const trackedNodesRef = useRef<AnyAudioNode[]>([]);
  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([]);

  const track = <T extends AnyAudioNode>(node: T): T => {
    trackedNodesRef.current.push(node);
    return node;
  };

  const later = (fn: () => void, ms: number) => {
    const id = setTimeout(fn, ms);
    timersRef.current.push(id);
  };

  const cleanup = useCallback(() => {
    timersRef.current.forEach((t) => clearTimeout(t));
    timersRef.current = [];

    if (audioElemRef.current) {
      try {
        audioElemRef.current.pause();
        audioElemRef.current.currentTime = 0;
        audioElemRef.current.src = "";
      } catch {}
      audioElemRef.current = null;
    }

    trackedNodesRef.current.forEach((node) => {
      try {
        if (typeof node.stop === "function") {
          node.stop();
        }
        node.disconnect();
      } catch {}
    });
    trackedNodesRef.current = [];

    if (ctxRef.current) {
      try {
        if (ctxRef.current.state !== "closed") {
          ctxRef.current.close();
        }
      } catch {}
      ctxRef.current = null;
    }
    masterGainRef.current = null;
  }, []);

  const fadeOutAudio = useCallback((durationMs = 1500) => {
    const ctx = ctxRef.current;
    const master = masterGainRef.current;
    const audio = audioElemRef.current;
    const fadeSec = durationMs / 1000;

    if (ctx && master && ctx.state !== "closed") {
      try {
        const now = ctx.currentTime;
        master.gain.cancelScheduledValues(now);
        master.gain.setValueAtTime(master.gain.value, now);
        master.gain.linearRampToValueAtTime(0.0001, now + fadeSec);
      } catch {}
    }

    if (audio) {
      try {
        const startVol = audio.volume;
        const steps = 15;
        const stepTime = durationMs / steps;
        let currentStep = 0;
        const fadeInterval = setInterval(() => {
          currentStep++;
          if (audio) {
            audio.volume = Math.max(0, startVol * (1 - currentStep / steps));
          }
          if (currentStep >= steps) {
            clearInterval(fadeInterval);
            if (audio) {
              audio.pause();
            }
          }
        }, stepTime);
        timersRef.current.push(fadeInterval as unknown as ReturnType<typeof setTimeout>);
      } catch {}
    }
  }, []);

  const startIntroAudio = useCallback(async () => {
    cleanup();

    let ctx: AudioContext;
    try {
      const AudioCtx =
        window.AudioContext ||
        (window as unknown as { webkitAudioContext: typeof AudioContext })
          .webkitAudioContext;
      ctx = new AudioCtx();
      ctxRef.current = ctx;

      if (ctx.state === "suspended") {
        await ctx.resume().catch(() => {});
      }
    } catch {
      return;
    }

    const masterGain = ctx.createGain();
    masterGain.gain.setValueAtTime(0.85, ctx.currentTime);
    masterGain.connect(ctx.destination);
    masterGainRef.current = masterGain;

    // ----------------------------------------------------------------------
    // 1. CINEMATIC LOW BEAST GROWL (0s -> 4.5s)
    // ----------------------------------------------------------------------
    const growlGain = track(ctx.createGain());
    growlGain.gain.setValueAtTime(0.0001, ctx.currentTime);
    // Smooth swell as darkness stirs (0s to 1.4s), peaking as the evil eye awakens
    growlGain.gain.exponentialRampToValueAtTime(0.7, ctx.currentTime + 1.4);
    // Low menacing growl sustain through 3.2s
    growlGain.gain.setValueAtTime(0.65, ctx.currentTime + 3.2);
    // Settles down as full fire takes over (4.5s)
    growlGain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 5.0);

    // Resonant dark acoustic cavity filter
    const growlFilter = track(ctx.createBiquadFilter());
    growlFilter.type = "lowpass";
    growlFilter.Q.value = 4.5;
    growlFilter.frequency.setValueAtTime(140, ctx.currentTime);
    growlFilter.frequency.linearRampToValueAtTime(220, ctx.currentTime + 1.2);
    growlFilter.frequency.exponentialRampToValueAtTime(65, ctx.currentTime + 4.5);

    // Warm harmonic distortion for visceral beast throat texture
    const waveShaper = track(ctx.createWaveShaper());
    waveShaper.curve = makeDistortionCurve(20) as any;
    waveShaper.oversample = "2x";

    // Beast Oscillator 1: Guttural Sawtooth, dropping in pitch (56Hz -> 38Hz)
    const osc1 = track(ctx.createOscillator());
    osc1.type = "sawtooth";
    osc1.frequency.setValueAtTime(56, ctx.currentTime);
    osc1.frequency.exponentialRampToValueAtTime(38, ctx.currentTime + 3.8);

    // Beast Oscillator 2: Sub-triangle for chest-shaking sub-bass (32Hz -> 27Hz)
    const osc2 = track(ctx.createOscillator());
    osc2.type = "triangle";
    osc2.frequency.setValueAtTime(32, ctx.currentTime);
    osc2.frequency.linearRampToValueAtTime(27, ctx.currentTime + 3.5);

    // LFO: Tremulous beast throat modulation (7.2Hz)
    const lfo = track(ctx.createOscillator());
    const lfoGain = track(ctx.createGain());
    lfo.frequency.setValueAtTime(7.2, ctx.currentTime);
    lfoGain.gain.setValueAtTime(12, ctx.currentTime);
    lfo.connect(osc1.frequency);

    // Brown Noise Sub-Rumble
    const brownBuffer = makeBrownNoise(ctx, 6.0);
    const rumbleSource = track(ctx.createBufferSource());
    rumbleSource.buffer = brownBuffer;
    rumbleSource.loop = true;

    const rumbleFilter = track(ctx.createBiquadFilter());
    rumbleFilter.type = "lowpass";
    rumbleFilter.frequency.value = 60;

    const rumbleGain = track(ctx.createGain());
    rumbleGain.gain.setValueAtTime(0.0001, ctx.currentTime);
    rumbleGain.gain.exponentialRampToValueAtTime(0.45, ctx.currentTime + 1.2);
    rumbleGain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 5.0);

    // Connect beast growl graph
    osc1.connect(waveShaper);
    osc2.connect(waveShaper);
    waveShaper.connect(growlFilter);
    growlFilter.connect(growlGain);
    growlGain.connect(masterGain);

    rumbleSource.connect(rumbleFilter);
    rumbleFilter.connect(rumbleGain);
    rumbleGain.connect(masterGain);

    osc1.start(ctx.currentTime);
    osc2.start(ctx.currentTime);
    lfo.start(ctx.currentTime);
    rumbleSource.start(ctx.currentTime);

    later(() => {
      try { osc1.stop(); } catch {}
      try { osc2.stop(); } catch {}
      try { lfo.stop(); } catch {}
      try { rumbleSource.stop(); } catch {}
    }, 5500);

    // ----------------------------------------------------------------------
    // 2. USER'S FIRE CRACKLING AUDIO (/intro-fire.mp3)
    // ----------------------------------------------------------------------
    try {
      const audio = new Audio("/intro-fire.mp3");
      audio.preload = "auto";
      audio.volume = 0;
      audioElemRef.current = audio;

      try {
        const source = track(ctx.createMediaElementSource(audio));
        const fireGain = track(ctx.createGain());
        fireGain.gain.setValueAtTime(0.0001, ctx.currentTime);
        fireGain.gain.exponentialRampToValueAtTime(0.85, ctx.currentTime + 2.0);

        source.connect(fireGain);
        fireGain.connect(masterGain);
        audio.volume = 1.0;
      } catch {
        // Fallback volume ramp directly on HTMLAudioElement
        audio.volume = 0.05;
        let vol = 0.05;
        const rampInterval = setInterval(() => {
          vol = Math.min(0.85, vol + 0.08);
          if (audio) audio.volume = vol;
          if (vol >= 0.85) clearInterval(rampInterval);
        }, 150);
        timersRef.current.push(rampInterval as unknown as ReturnType<typeof setTimeout>);
      }

      const playPromise = audio.play();
      if (playPromise !== undefined) {
        playPromise.catch(() => {
          const unlock = () => {
            if (audioElemRef.current) {
              audioElemRef.current.play().catch(() => {});
            }
            window.removeEventListener("pointerdown", unlock);
            window.removeEventListener("keydown", unlock);
          };
          window.addEventListener("pointerdown", unlock, { once: true });
          window.addEventListener("keydown", unlock, { once: true });
        });
      }
    } catch (e) {
      console.warn("Could not load fire crackle audio:", e);
    }
  }, [cleanup]);

  return { startIntroAudio, fadeOutAudio, cleanup };
}
