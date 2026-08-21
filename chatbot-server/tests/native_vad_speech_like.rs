//! Native VAD: record from speech-like start; barge-in only on real speech.
//! Dual invariant: a cough/"hey" must not stop TTS; sustained noisy speech must,
//! at confirmation (~400 ms, like desktop minSpeechMs), not at end-of-speech.

fn parse_js_number_const(src: &str, name: &str) -> Option<f64> {
    let needle = format!("const {name} = ");
    let start = src.find(&needle)? + needle.len();
    let rest = src[start..].trim_start();
    let token: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    token.parse().ok()
}

fn parse_js_int_const(src: &str, name: &str) -> Option<i32> {
    parse_js_number_const(src, name).map(|v| v as i32)
}

fn pcm16_rms(samples: &[i16]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: f64 = samples.iter().map(|&s| (s as f64) * (s as f64)).sum();
    (sum / samples.len() as f64).sqrt()
}

fn pcm16_zcr(samples: &[i16]) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    let mut crossings = 0u32;
    for i in 1..samples.len() {
        let prev = samples[i - 1];
        let cur = samples[i];
        if (prev >= 0 && cur < 0) || (prev < 0 && cur >= 0) {
            if prev != 0 || cur != 0 {
                crossings += 1;
            }
        }
    }
    crossings as f64 / (samples.len() - 1) as f64
}

fn pcm16_peak_abs(samples: &[i16]) -> i32 {
    samples
        .iter()
        .map(|&s| i32::from(s).abs())
        .max()
        .unwrap_or(0)
}

fn pcm16_is_speech_like(
    samples: &[i16],
    rms_threshold: f64,
    zcr_min: f64,
    zcr_max: f64,
    crest_max: f64,
) -> bool {
    let rms = pcm16_rms(samples);
    if rms < rms_threshold {
        return false;
    }
    let zcr = pcm16_zcr(samples);
    if zcr < zcr_min || zcr > zcr_max {
        return false;
    }
    let crest = pcm16_peak_abs(samples) as f64 / rms;
    crest <= crest_max
}

fn sine_frame(freq_hz: f64, amp: i16, n: usize, sample_rate: f64) -> Vec<i16> {
    (0..n)
        .map(|i| {
            let x = (2.0 * std::f64::consts::PI * freq_hz * (i as f64) / sample_rate).sin();
            (x * f64::from(amp)).round() as i16
        })
        .collect()
}

struct SpeechLikeThresholds {
    rms: f64,
    zcr_min: f64,
    zcr_max: f64,
    crest_max: f64,
    periodicity_min: f64,
    pitch_lag_min: usize,
    pitch_lag_max: usize,
    start_frames: usize,
    miss_frames: usize,
    voiced_window_frames: usize,
    real_speech_ms: u32,
    real_speech_voiced_ms: u32,
}

fn load_thresholds() -> SpeechLikeThresholds {
    let src = include_str!("../../static/native-audio.js");
    SpeechLikeThresholds {
        rms: parse_js_number_const(src, "SPEECH_RMS_THRESHOLD")
            .expect("SPEECH_RMS_THRESHOLD"),
        zcr_min: parse_js_number_const(src, "SPEECH_ZCR_MIN").expect("SPEECH_ZCR_MIN"),
        zcr_max: parse_js_number_const(src, "SPEECH_ZCR_MAX").expect("SPEECH_ZCR_MAX"),
        crest_max: parse_js_number_const(src, "SPEECH_CREST_MAX").expect("SPEECH_CREST_MAX"),
        periodicity_min: parse_js_number_const(src, "SPEECH_PERIODICITY_MIN")
            .expect("SPEECH_PERIODICITY_MIN"),
        pitch_lag_min: parse_js_number_const(src, "SPEECH_PITCH_LAG_MIN")
            .expect("SPEECH_PITCH_LAG_MIN") as usize,
        pitch_lag_max: parse_js_number_const(src, "SPEECH_PITCH_LAG_MAX")
            .expect("SPEECH_PITCH_LAG_MAX") as usize,
        start_frames: parse_js_int_const(src, "SPEECH_START_FRAMES")
            .expect("SPEECH_START_FRAMES") as usize,
        miss_frames: parse_js_int_const(src, "SPEECH_START_MISS_FRAMES")
            .expect("SPEECH_START_MISS_FRAMES") as usize,
        voiced_window_frames: parse_js_int_const(src, "SPEECH_VOICED_WINDOW_FRAMES")
            .expect("SPEECH_VOICED_WINDOW_FRAMES") as usize,
        real_speech_ms: parse_js_int_const(src, "REAL_SPEECH_MS").expect("REAL_SPEECH_MS")
            as u32,
        real_speech_voiced_ms: parse_js_int_const(src, "REAL_SPEECH_VOICED_MS")
            .expect("REAL_SPEECH_VOICED_MS") as u32,
    }
}

fn classify(samples: &[i16], t: &SpeechLikeThresholds) -> bool {
    pcm16_is_speech_like(samples, t.rms, t.zcr_min, t.zcr_max, t.crest_max)
}

/// Normalized autocorrelation peak in the pitch-lag band. Must match
/// `pcm16PitchPeriodicity` in static/native-audio.js.
fn pcm16_pitch_periodicity(samples: &[i16], lag_min: usize, lag_max: usize) -> f64 {
    let n = samples.len();
    if n < 80 {
        return 0.0;
    }
    let max_lag = lag_max.min(n / 2 - 1);
    if max_lag < lag_min {
        return 0.0;
    }
    let mut energy_prefix = vec![0.0_f64; n + 1];
    for i in 0..n {
        let x = samples[i] as f64;
        energy_prefix[i + 1] = energy_prefix[i] + x * x;
    }
    let mut best = 0.0_f64;
    for lag in lag_min..=max_lag {
        let limit = n - lag;
        let mut corr = 0.0;
        for i in 0..limit {
            corr += samples[i] as f64 * samples[i + lag] as f64;
        }
        let e1 = energy_prefix[limit];
        let e2 = energy_prefix[n] - energy_prefix[lag];
        if e1 < 1.0 || e2 < 1.0 {
            continue;
        }
        let norm = corr / (e1 * e2).sqrt();
        if norm > best {
            best = norm;
        }
    }
    best
}

fn pcm16_is_voiced_speech(samples: &[i16], t: &SpeechLikeThresholds) -> bool {
    if samples.len() < 640 {
        return false;
    }
    if pcm16_rms(samples) < t.rms {
        return false;
    }
    pcm16_pitch_periodicity(samples, t.pitch_lag_min, t.pitch_lag_max) >= t.periodicity_min
}

/// Attack impulse + decaying colored noise. Per-frame ZCR and crest of the
/// body look speech-like; the window is not periodic like a vowel.
fn cough_burst(n: usize, sample_rate: f64) -> Vec<i16> {
    let mut lp = 0.0_f64;
    (0..n)
        .map(|i| {
            if i == 0 {
                return 25_000;
            }
            if i == 1 {
                return -20_000;
            }
            let mut bits = (i as u32)
                .wrapping_add(1)
                .wrapping_mul(747_796_405)
                .wrapping_add(2_891_336_453);
            bits ^= bits >> 16;
            bits = bits.wrapping_mul(2_246_822_519);
            bits ^= bits >> 13;
            let white = (bits as f64 / f64::from(u32::MAX)) * 2.0 - 1.0;
            lp = lp * 0.75 + white * 0.25;
            let t = i as f64 / sample_rate;
            let env = (-t / 0.10).exp();
            (lp * env * 16_000.0).round().clamp(-32768.0, 32767.0) as i16
        })
        .collect()
}

#[test]
fn speech_like_thresholds_are_a_speech_band_not_an_energy_gate() {
    let t = load_thresholds();
    assert!(
        (300.0..=800.0).contains(&t.rms),
        "SPEECH_RMS_THRESHOLD={} is not a speakerphone-distance gate",
        t.rms
    );
    assert!(
        (0.005..=0.03).contains(&t.zcr_min),
        "SPEECH_ZCR_MIN={} should reject rumble/DC without cutting low voice",
        t.zcr_min
    );
    assert!(
        (0.2..=0.35).contains(&t.zcr_max),
        "SPEECH_ZCR_MAX={} should reject hiss/noise while allowing unvoiced speech",
        t.zcr_max
    );
    assert!(
        (6.0..=12.0).contains(&t.crest_max),
        "SPEECH_CREST_MAX={} should reject cough/clap impulses",
        t.crest_max
    );
    assert!(
        (0.10..=0.25).contains(&t.periodicity_min),
        "SPEECH_PERIODICITY_MIN={} must accept noisy table vowels, not only clean sines",
        t.periodicity_min
    );
    assert!(
        (350..=500).contains(&t.real_speech_ms),
        "REAL_SPEECH_MS={} must match desktop minSpeechMs (~400), not a 120 ms start-gate",
        t.real_speech_ms
    );
    assert!(
        (80..=200).contains(&t.real_speech_voiced_ms),
        "REAL_SPEECH_VOICED_MS={} should require some voicing without needing a full vowel hold",
        t.real_speech_voiced_ms
    );
    assert!(
        (4..=6).contains(&t.voiced_window_frames),
        "SPEECH_VOICED_WINDOW_FRAMES={} should be ~80–120 ms",
        t.voiced_window_frames
    );
    assert_eq!(
        t.pitch_lag_min, 40,
        "SPEECH_PITCH_LAG_MIN={} is not 400 Hz at 16 kHz",
        t.pitch_lag_min
    );
    assert_eq!(
        t.pitch_lag_max, 200,
        "SPEECH_PITCH_LAG_MAX={} is not 80 Hz at 16 kHz",
        t.pitch_lag_max
    );
}

#[test]
fn voiced_sine_is_speech_like_impulse_hiss_and_silence_are_not() {
    let t = load_thresholds();
    const N: usize = 320; // 20 ms @ 16 kHz
    const SR: f64 = 16_000.0;

    let voiced = sine_frame(200.0, 4000, N, SR);
    assert!(
        classify(&voiced, &t),
        "200 Hz voiced-like frame must start recording (onSpeechStart analog)"
    );

    let mid_voice = sine_frame(400.0, 2500, N, SR);
    assert!(
        classify(&mid_voice, &t),
        "400 Hz voiced-like frame must count as speech"
    );

    let quiet = sine_frame(200.0, 80, N, SR);
    assert!(
        !classify(&quiet, &t),
        "below-threshold energy must not count as speech"
    );

    let hiss = sine_frame(4000.0, 4000, N, SR);
    assert!(!classify(&hiss, &t), "high-frequency hiss must not barge in");

    let noise: Vec<i16> = (0..N)
        .map(|i| if i % 2 == 0 { 3000 } else { -3000 })
        .collect();
    assert!(
        !classify(&noise, &t),
        "Nyquist toggle (white-ish noise) must not barge in"
    );

    let mut impulse = vec![0_i16; N];
    impulse[0] = 20_000;
    impulse[1] = -18_000;
    assert!(
        !classify(&impulse, &t),
        "impulse (cough/clap onset) must not barge in"
    );

    let silence = vec![0_i16; N];
    assert!(!classify(&silence, &t), "silence is not speech");
}

fn lcg_white(i: usize) -> f64 {
    let mut bits = (i as u32)
        .wrapping_add(1)
        .wrapping_mul(747_796_405)
        .wrapping_add(2_891_336_453);
    bits ^= bits >> 16;
    bits = bits.wrapping_mul(2_246_822_519);
    bits ^= bits >> 13;
    (bits as f64 / f64::from(u32::MAX)) * 2.0 - 1.0
}

/// Table-distance vowel + room/AEC-ish noise. Must still count as speech.
fn noisy_vowel(freq_hz: f64, amp: i16, n: usize, sample_rate: f64, noise_gain: f64) -> Vec<i16> {
    let mut lp = 0.0_f64;
    (0..n)
        .map(|i| {
            let t = i as f64 / sample_rate;
            let s = (2.0 * std::f64::consts::PI * freq_hz * t).sin() * f64::from(amp);
            lp = lp * 0.75 + lcg_white(i.wrapping_add(99)) * 0.25;
            (s + lp * noise_gain * 8_000.0)
                .round()
                .clamp(-32768.0, 32767.0) as i16
        })
        .collect()
}

fn pcm16_voiced_ms_from_chunks(chunks: &[Vec<i16>], t: &SpeechLikeThresholds, frame_ms: u32) -> u32 {
    let w = t.voiced_window_frames;
    if chunks.len() < w {
        return 0;
    }
    let mut voiced_ms = 0u32;
    for i in w..=chunks.len() {
        let mut merged = Vec::new();
        for c in &chunks[i - w..i] {
            merged.extend_from_slice(c);
        }
        if pcm16_is_voiced_speech(&merged, t) {
            voiced_ms += frame_ms;
        }
    }
    voiced_ms
}

fn real_speech_detected(speech_like_ms: u32, voiced_ms: u32, t: &SpeechLikeThresholds) -> bool {
    speech_like_ms >= t.real_speech_ms && voiced_ms >= t.real_speech_voiced_ms
}

/// Mirrors NativeMicUtteranceVAD: record at speech-like start; barge-in only
/// on pcm16RealSpeechDetected (desktop onSpeechRealStart analog).
struct NativeVadSim {
    tts: bool,
    in_speech: bool,
    speech_above: usize,
    non_speech_like: usize,
    start_gate: Vec<Vec<i16>>,
    speech_like_ms: u32,
    voiced_ms: u32,
    voiced_window: Vec<Vec<i16>>,
    barge_in: bool,
    silence_ms: u32,
}

impl NativeVadSim {
    fn new(tts: bool) -> Self {
        Self {
            tts,
            in_speech: false,
            speech_above: 0,
            non_speech_like: 0,
            start_gate: Vec::new(),
            speech_like_ms: 0,
            voiced_ms: 0,
            voiced_window: Vec::new(),
            barge_in: false,
            silence_ms: 0,
        }
    }

    fn maybe_barge_in(&mut self, t: &SpeechLikeThresholds) {
        if self.barge_in || !self.tts {
            return;
        }
        if real_speech_detected(self.speech_like_ms, self.voiced_ms, t) {
            self.barge_in = true;
        }
    }

    fn note_voiced_frame(&mut self, frame: &[i16], t: &SpeechLikeThresholds, frame_ms: u32) {
        self.voiced_window.push(frame.to_vec());
        let w = t.voiced_window_frames;
        if self.voiced_window.len() > w {
            self.voiced_window.remove(0);
        }
        if self.voiced_window.len() >= w {
            let mut merged = Vec::new();
            for c in &self.voiced_window {
                merged.extend_from_slice(c);
            }
            if pcm16_is_voiced_speech(&merged, t) {
                self.voiced_ms += frame_ms;
            }
        }
    }

    fn begin(&mut self, t: &SpeechLikeThresholds) {
        if self.in_speech {
            return;
        }
        self.in_speech = true;
        let start = std::mem::take(&mut self.start_gate);
        self.speech_above = 0;
        self.non_speech_like = 0;
        self.speech_like_ms = (start.len() as u32) * 20;
        self.voiced_ms = pcm16_voiced_ms_from_chunks(&start, t, 20);
        let w = t.voiced_window_frames;
        self.voiced_window = if start.len() > w {
            start[start.len() - w..].to_vec()
        } else {
            start
        };
        self.maybe_barge_in(t);
    }

    fn maybe_start(&mut self, frame: &[i16], rms: f64, t: &SpeechLikeThresholds) {
        if self.in_speech {
            return;
        }
        if classify(frame, t) {
            self.start_gate.push(frame.to_vec());
            self.speech_above += 1;
            self.non_speech_like = 0;
            if self.speech_above >= t.start_frames {
                self.begin(t);
            }
        } else if rms > t.rms {
            self.non_speech_like += 1;
            if self.non_speech_like >= t.miss_frames {
                self.speech_above = 0;
                self.start_gate.clear();
            }
        } else {
            self.speech_above = 0;
            self.non_speech_like = 0;
            self.start_gate.clear();
        }
    }

    fn accumulate(&mut self, frame: &[i16], rms: f64, t: &SpeechLikeThresholds) {
        if classify(frame, t) {
            self.silence_ms = 0;
            self.speech_like_ms += 20;
            self.note_voiced_frame(frame, t, 20);
        } else if rms > t.rms {
            self.silence_ms = 0;
        } else {
            self.silence_ms += 20;
            self.voiced_window.clear();
        }
        self.maybe_barge_in(t);
    }

    fn feed(&mut self, frame: &[i16], t: &SpeechLikeThresholds) {
        let rms = pcm16_rms(frame);
        self.maybe_start(frame, rms, t);
        if self.in_speech {
            self.accumulate(frame, rms, t);
        }
    }
}

#[test]
fn cough_and_hey_do_not_barge_in_sustained_noisy_speech_does() {
    let t = load_thresholds();
    const SR: f64 = 16_000.0;
    const FRAME: usize = 320;

    let cough = cough_burst(FRAME * 16, SR);
    let mut speech_like_body = 0usize;
    for frame in cough.chunks(FRAME).skip(1).take(8) {
        if classify(frame, &t) {
            speech_like_body += 1;
        }
    }
    assert!(
        speech_like_body >= 6,
        "cough body still looks speech-like ({speech_like_body}/8); duration+voicing must reject it, not the start-gate"
    );

    let cough_win = &cough[FRAME..FRAME + FRAME * t.voiced_window_frames];
    assert!(
        !pcm16_is_voiced_speech(cough_win, &t),
        "cough rolling window must not look voiced (periodicity={})",
        pcm16_pitch_periodicity(cough_win, t.pitch_lag_min, t.pitch_lag_max)
    );

    let mut cough_vad = NativeVadSim::new(true);
    for frame in cough.chunks(FRAME) {
        cough_vad.feed(frame, &t);
        assert!(
            !cough_vad.barge_in,
            "cough must not barge in (likeMs={} voicedMs={})",
            cough_vad.speech_like_ms, cough_vad.voiced_ms
        );
    }

    let speech = noisy_vowel(200.0, 1200, FRAME * 30, SR, 0.35);
    let hey: Vec<&[i16]> = speech.chunks(FRAME).take(10).collect();
    assert_eq!(hey.len() * 20, 200, "hey fixture is ~200 ms");
    for frame in &hey {
        assert!(
            classify(frame, &t),
            "noisy table vowel frame must be speech-like so recording can start"
        );
    }
    let hey_win = &speech[..FRAME * t.voiced_window_frames];
    assert!(
        pcm16_is_voiced_speech(hey_win, &t),
        "noisy table vowel must still look voiced (periodicity={})",
        pcm16_pitch_periodicity(hey_win, t.pitch_lag_min, t.pitch_lag_max)
    );

    let mut hey_vad = NativeVadSim::new(true);
    for frame in hey {
        hey_vad.feed(frame, &t);
    }
    assert!(
        hey_vad.in_speech,
        "a short hey must still start recording (pre-roll / STT)"
    );
    assert!(
        !hey_vad.barge_in,
        "a short hey must not stop TTS (likeMs={} voicedMs={} real={} voicedNeed={})",
        hey_vad.speech_like_ms,
        hey_vad.voiced_ms,
        t.real_speech_ms,
        t.real_speech_voiced_ms
    );

    let mut talk_vad = NativeVadSim::new(true);
    let mut barge_at_ms: Option<u32> = None;
    for (i, frame) in speech.chunks(FRAME).enumerate() {
        talk_vad.feed(frame, &t);
        if talk_vad.barge_in && barge_at_ms.is_none() {
            barge_at_ms = Some(((i + 1) as u32) * 20);
        }
    }
    let barge_at = barge_at_ms.expect("sustained noisy speech must barge in");
    assert!(
        (t.real_speech_ms.saturating_sub(40)..=t.real_speech_ms + 120).contains(&barge_at),
        "barge-in at {barge_at} ms must be at real-speech confirm (~{}), not utterance start (~120) or end-of-speech (1500)",
        t.real_speech_ms
    );

    let mut idle = NativeVadSim::new(false);
    for frame in speech.chunks(FRAME).take(10) {
        idle.feed(frame, &t);
    }
    assert!(
        idle.in_speech && !idle.barge_in,
        "idle listen must record a short utterance without barging in"
    );
}

#[test]
fn native_audio_js_exports_real_speech_gate() {
    let src = include_str!("../../static/native-audio.js");
    assert!(
        src.contains("function pcm16PitchPeriodicity")
            && src.contains("function pcm16IsVoicedSpeech")
            && src.contains("function pcm16RealSpeechDetected")
            && src.contains("function pcm16VoicedMsFromChunks")
            && src.contains("REAL_SPEECH_MS")
            && src.contains("pcm16RealSpeechDetected: pcm16RealSpeechDetected"),
        "native-audio.js must expose record-vs-real-speech helpers, not only ZCR+crest"
    );
}
