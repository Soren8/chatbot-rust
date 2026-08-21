//! Speech-like VAD gate used by native barge-in (static/native-audio.js).
//! RMS energy alone treats coughs and hiss as speech; ZCR + crest reject
//! impulses and hiss, but cough *body* still looks speech-like. Pitch
//! periodicity on the start-gate window is what separates real speech.

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
        (0.2..=0.45).contains(&t.periodicity_min),
        "SPEECH_PERIODICITY_MIN={} should reject aperiodic coughs without cutting vowels",
        t.periodicity_min
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
        "200 Hz voiced-like frame must start an utterance / barge-in"
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

#[test]
fn cough_body_can_look_speech_like_but_must_not_count_as_voiced() {
    let t = load_thresholds();
    const SR: f64 = 16_000.0;
    const FRAME: usize = 320;
    let cough = cough_burst(FRAME * 8, SR);

    let mut speech_like_body_frames = 0usize;
    for frame in cough.chunks(FRAME).skip(1).take(6) {
        if classify(frame, &t) {
            speech_like_body_frames += 1;
        }
    }
    assert!(
        speech_like_body_frames >= 6,
        "cough body must still pass per-frame ZCR+crest ({speech_like_body_frames}/6); that is why barge-in needs a voiced window"
    );

    let start_gate = &cough[FRAME..FRAME * 7];
    assert_eq!(start_gate.len(), FRAME * 6);
    assert!(
        !pcm16_is_voiced_speech(start_gate, &t),
        "120 ms cough window must not barge in (periodicity={})",
        pcm16_pitch_periodicity(start_gate, t.pitch_lag_min, t.pitch_lag_max)
    );

    let vowel = sine_frame(200.0, 4000, FRAME * 6, SR);
    assert!(
        pcm16_is_voiced_speech(&vowel, &t),
        "120 ms 200 Hz vowel must barge in immediately (periodicity={})",
        pcm16_pitch_periodicity(&vowel, t.pitch_lag_min, t.pitch_lag_max)
    );

    let mid = sine_frame(120.0, 2500, FRAME * 6, SR);
    assert!(
        pcm16_is_voiced_speech(&mid, &t),
        "120 ms low male vowel must barge in (periodicity={})",
        pcm16_pitch_periodicity(&mid, t.pitch_lag_min, t.pitch_lag_max)
    );
}

#[test]
fn native_audio_js_exports_voiced_speech_gate() {
    let src = include_str!("../../static/native-audio.js");
    assert!(
        src.contains("function pcm16PitchPeriodicity")
            && src.contains("function pcm16IsVoicedSpeech")
            && src.contains("SPEECH_PERIODICITY_MIN")
            && src.contains("pcm16IsVoicedSpeech: pcm16IsVoicedSpeech"),
        "native-audio.js must expose a voiced/periodic gate, not only ZCR+crest"
    );
}
