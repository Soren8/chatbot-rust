//! Speech-like VAD gate used by native barge-in (static/native-audio.js).
//! RMS energy alone treats coughs and hiss as speech; ZCR + crest reject them.

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
}

fn load_thresholds() -> SpeechLikeThresholds {
    let src = include_str!("../../static/native-audio.js");
    SpeechLikeThresholds {
        rms: parse_js_number_const(src, "SPEECH_RMS_THRESHOLD")
            .expect("SPEECH_RMS_THRESHOLD"),
        zcr_min: parse_js_number_const(src, "SPEECH_ZCR_MIN").expect("SPEECH_ZCR_MIN"),
        zcr_max: parse_js_number_const(src, "SPEECH_ZCR_MAX").expect("SPEECH_ZCR_MAX"),
        crest_max: parse_js_number_const(src, "SPEECH_CREST_MAX").expect("SPEECH_CREST_MAX"),
    }
}

fn classify(samples: &[i16], t: &SpeechLikeThresholds) -> bool {
    pcm16_is_speech_like(samples, t.rms, t.zcr_min, t.zcr_max, t.crest_max)
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
