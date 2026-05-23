//! Contract tests for PCM16 WAV encoding used by static/native-audio.js (Capacitor STT).

fn pcm16_to_wav_bytes(samples: &[i16], sample_rate: u32) -> Vec<u8> {
    let data_len = samples.len() * 2;
    let mut out = Vec::with_capacity(44 + data_len);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36_u32 + data_len as u32).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16_u32.to_le_bytes());
    out.extend_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(&sample_rate.to_le_bytes());
    out.extend_from_slice(&(sample_rate * 2).to_le_bytes());
    out.extend_from_slice(&2_u16.to_le_bytes());
    out.extend_from_slice(&16_u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(data_len as u32).to_le_bytes());
    for &s in samples {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

#[test]
fn pcm16_wav_preserves_sample_amplitude() {
    // Regression: Int16 samples must not be clamped to ±1 float before encoding.
    let samples = [0_i16, 1000, -2500, 5000, -12000, 32767, -32768];
    let wav = pcm16_to_wav_bytes(&samples, 16000);
    assert!(wav.starts_with(b"RIFF"));
    assert_eq!(&wav[36..40], b"data");

    let data = &wav[44..];
    assert_eq!(data.len(), samples.len() * 2);
    for (i, &expected) in samples.iter().enumerate() {
        let got = i16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
        assert_eq!(got, expected, "sample {i} distorted");
    }
}

#[test]
fn pcm16_wav_header_sample_rate() {
    let wav = pcm16_to_wav_bytes(&[1, 2, 3], 16000);
    let rate = u32::from_le_bytes(wav[24..28].try_into().unwrap());
    assert_eq!(rate, 16000);
}
