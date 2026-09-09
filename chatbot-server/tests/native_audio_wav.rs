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

fn create_adts_header(data_length: usize, sample_rate: u32, channels: u8) -> [u8; 7] {
    let frame_length = 7 + data_length;
    let rate_idx: u8 = match sample_rate {
        96000 => 0,
        88200 => 1,
        64000 => 2,
        48000 => 3,
        44100 => 4,
        32000 => 5,
        24000 => 6,
        22050 => 7,
        16000 => 8,
        12000 => 9,
        11025 => 10,
        8000 => 11,
        7350 => 12,
        _ => 8,
    };
    let mut header = [0u8; 7];
    header[0] = 0xFF;
    header[1] = 0xF1;
    header[2] = (1 << 6) | ((rate_idx & 0x0F) << 2) | ((channels >> 2) & 1);
    header[3] = ((channels & 3) << 6) | (((frame_length >> 11) & 0x03) as u8);
    header[4] = ((frame_length >> 3) & 0xFF) as u8;
    header[5] = (((frame_length & 7) << 5) as u8) | 0x1F;
    header[6] = 0xFC;
    header
}

#[test]
fn adts_header_16khz_mono_structure() {
    let header = create_adts_header(100, 16000, 1);
    // Syncword 0xFFF + MPEG-4 + layer 0 + protection absent 1
    assert_eq!(header[0], 0xFF);
    assert_eq!(header[1], 0xF1);
    // AAC-LC (01) + 16kHz (1000) + chan MSB (0) -> 0b01100000 = 0x60
    assert_eq!(header[2], 0x60);
    // chan LSB (01) -> 0x40 | frame_length MSBs
    assert_eq!(header[3] & 0xC0, 0x40);
    // Total frame length = 107
    let frame_len = (((header[3] & 0x03) as usize) << 11)
        | ((header[4] as usize) << 3)
        | (((header[5] & 0xE0) as usize) >> 5);
    assert_eq!(frame_len, 107);
}
