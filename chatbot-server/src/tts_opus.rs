//! Server-side Opus encoding for `/tts_stream` responses.
//!
//! TTS backends produce PCM; serving it as WAV costs ~400 kbps, which stalls
//! voice mode for tens of seconds on relayed/degraded links. Encoding each
//! clip to Ogg-Opus (~24 kbps mono, ~11x smaller) moves the downlink out of
//! the critical path. Encode cost is single-digit milliseconds per sentence
//! (libopus SIMD), negligible next to synthesis itself.
//!
//! Resampling is deliberately linear-interpolation only: Opus accepts just
//! 8/12/16/24/48 kHz, and our backends sit at 24 kHz (kokoro, passthrough) or
//! 25.2 kHz (legacy, ratio 1.05). At such narrow ratios linear error sits far
//! below Opus coding noise, so a full resampling dependency is not worth it.

use anyhow::{Context, Result};
use audiopus::{Application, Bitrate, Channels, SampleRate};
use audiopus::coder::Encoder;

/// Opus wire rate: 24 kHz mono, the voice-optimized sweet spot.
pub const OPUS_SAMPLE_RATE_HZ: u32 = 24_000;
/// Target bitrate: 24 kbps CBR-ish for clean TTS speech.
pub const OPUS_BITRATE_BPS: i32 = 24_000;
/// 20 ms frames at 24 kHz.
const OPUS_FRAME_SAMPLES: usize = 480;
/// Max Opus packet is 1275 bytes; 4000 leaves ample headroom.
const OPUS_MAX_PACKET_BYTES: usize = 4000;

/// Linear-interpolation resample of mono i16 to 24 kHz. Exact passthrough
/// when already at 24 kHz (the kokoro case); 25.2 kHz legacy input shifts by
/// a 1.05 ratio with inaudible error.
pub fn resample_mono_i16_to_24k(input: &[i16], from_rate: u32) -> Vec<i16> {
    if input.is_empty() || from_rate == OPUS_SAMPLE_RATE_HZ {
        return input.to_vec();
    }
    let out_len = ((input.len() as u64 * u64::from(OPUS_SAMPLE_RATE_HZ)
        + u64::from(from_rate) / 2)
        / u64::from(from_rate)) as usize;
    let out_len = out_len.max(1);
    let last = input.len() - 1;
    let mut out = Vec::with_capacity(out_len);
    for i in 0..out_len {
        let pos = i as f64 * f64::from(from_rate) / f64::from(OPUS_SAMPLE_RATE_HZ);
        let idx = (pos.floor() as usize).min(last);
        let frac = (pos - idx as f64) as f32;
        let a = f32::from(input[idx]);
        let b = f32::from(input[(idx + 1).min(last)]);
        out.push(
            (a + (b - a) * frac)
                .round()
                .clamp(f32::from(i16::MIN), f32::from(i16::MAX)) as i16,
        );
    }
    out
}

/// 19-byte OpusHead identification header (mono, mapping family 0).
/// Pre-skip is 0, matching the client's STT upload framing: the clips start
/// with fades/silence, so the ~6 ms encoder delay is inaudible, and every
/// decoder we target (browsers, ffmpeg, concentus) accepts it.
fn opus_head_packet() -> [u8; 19] {
    let mut pkt = [0_u8; 19];
    pkt[0..8].copy_from_slice(b"OpusHead");
    pkt[8] = 1; // version
    pkt[9] = 1; // channel count
                 // bytes 10..12: pre-skip (0)
    pkt[12..16].copy_from_slice(&OPUS_SAMPLE_RATE_HZ.to_le_bytes());
    // bytes 16..18: output gain (0); byte 18: mapping family (0)
    pkt
}

/// OpusTags comment header with an empty user-comment list.
fn opus_tags_packet() -> Vec<u8> {
    let vendor = b"chatbot-tts";
    let mut pkt = Vec::with_capacity(8 + 4 + vendor.len() + 4);
    pkt.extend_from_slice(b"OpusTags");
    pkt.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    pkt.extend_from_slice(vendor);
    pkt.extend_from_slice(&0_u32.to_le_bytes());
    pkt
}

/// Encode mono i16 PCM at `from_rate` Hz into a complete Ogg-Opus stream.
pub fn encode_pcm_to_opus_ogg(pcm: &[i16], from_rate: u32) -> Result<Vec<u8>> {
    let packets = encode_pcm_to_opus_packets(pcm, from_rate)?;
    mux_ogg_opus(&packets)
}

/// Encode to raw Opus packets (head/tags excluded), one per 20 ms frame.
/// Split out so tests can decode packets without an Ogg demuxer.
fn encode_pcm_to_opus_packets(pcm: &[i16], from_rate: u32) -> Result<Vec<Vec<u8>>> {
    let pcm24 = resample_mono_i16_to_24k(pcm, from_rate);
    let mut encoder = Encoder::new(SampleRate::Hz24000, Channels::Mono, Application::Audio)
        .context("create opus encoder")?;
    encoder
        .set_bitrate(Bitrate::BitsPerSecond(OPUS_BITRATE_BPS))
        .context("set opus bitrate")?;

    // Always emit at least one audio packet so the stream ends with EOS even
    // for empty input.
    let frame_count = (pcm24.len() + OPUS_FRAME_SAMPLES - 1) / OPUS_FRAME_SAMPLES;
    let frame_count = frame_count.max(1);
    let mut packet = [0_u8; OPUS_MAX_PACKET_BYTES];
    let mut packets = Vec::with_capacity(frame_count);
    for i in 0..frame_count {
        let mut frame = [0_i16; OPUS_FRAME_SAMPLES];
        let start = i * OPUS_FRAME_SAMPLES;
        if start < pcm24.len() {
            let take = (pcm24.len() - start).min(OPUS_FRAME_SAMPLES);
            frame[..take].copy_from_slice(&pcm24[start..start + take]);
        }
        let n = encoder
            .encode(&frame, &mut packet)
            .context("opus encode frame")?;
        packets.push(packet[..n].to_vec());
    }
    Ok(packets)
}

fn mux_ogg_opus(packets: &[Vec<u8>]) -> Result<Vec<u8>> {
    let serial = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() ^ (d.as_secs() as u32)) | 1)
        .unwrap_or(0xC0FFEE);
    let mut writer = ogg::PacketWriter::new(Vec::new());
    let head = opus_head_packet();
    writer
        .write_packet(
            &head[..],
            serial,
            ogg::PacketWriteEndInfo::NormalPacket,
            0,
        )
        .context("write OpusHead")?;
    writer
        .write_packet(
            opus_tags_packet(),
            serial,
            ogg::PacketWriteEndInfo::NormalPacket,
            0,
        )
        .context("write OpusTags")?;

    // Granule position counts 48 kHz samples for Opus regardless of rate.
    let mut granule: u64 = 0;
    for (i, packet) in packets.iter().enumerate() {
        granule += (OPUS_FRAME_SAMPLES as u64) * 2;
        let end = if i + 1 == packets.len() {
            ogg::PacketWriteEndInfo::EndStream
        } else {
            ogg::PacketWriteEndInfo::NormalPacket
        };
        writer
            .write_packet(&packet[..], serial, end, granule)
            .context("write opus packet")?;
    }
    Ok(writer.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resample_passthrough_at_24k() {
        let input: Vec<i16> = (0..480).map(|i| i as i16 - 240).collect();
        assert_eq!(resample_mono_i16_to_24k(&input, 24_000), input);
    }

    #[test]
    fn resample_25200_preserves_length_and_level() {
        let input: Vec<i16> = (0..2520)
            .map(|i| ((i as f32 * 0.1).sin() * 10000.0) as i16)
            .collect();
        let out = resample_mono_i16_to_24k(&input, 25_200);
        assert_eq!(out.len(), 2400);
        let rms = |s: &[i16]| {
            (s.iter().map(|&x| f64::from(x) * f64::from(x)).sum::<f64>() / s.len() as f64)
                .sqrt()
        };
        let ratio = rms(&out) / rms(&input);
        assert!(
            (ratio - 1.0).abs() < 0.05,
            "resample must preserve level, got ratio {ratio}"
        );
    }

    #[test]
    fn encode_produces_valid_ogg_opus_much_smaller_than_wav() {
        let pcm: Vec<i16> = (0..12_000)
            .map(|i| ((i as f32 * 0.05).sin() * 8000.0) as i16)
            .collect();
        let ogg = encode_pcm_to_opus_ogg(&pcm, 24_000).expect("encode must succeed");
        assert!(ogg.starts_with(b"OggS"), "must start with Ogg page magic");
        // Small clips legitimately share one page; require the headers by magic.
        assert!(
            ogg.windows(8).any(|w| w == b"OpusHead"),
            "stream must contain the OpusHead packet"
        );
        assert!(
            ogg.windows(8).any(|w| w == b"OpusTags"),
            "stream must contain the OpusTags packet"
        );
        assert!(
            ogg.len() < 12_000,
            "opus must beat raw PCM size, got {}",
            ogg.len()
        );
    }

    #[test]
    fn silence_round_trips_to_silence() {
        use audiopus::coder::Decoder;
        // 0.1 s of digital silence, the SILENT path payload shape.
        let pcm = vec![0_i16; 2400];
        let packets = encode_pcm_to_opus_packets(&pcm, 24_000).expect("encode must succeed");
        assert!(!packets.is_empty());
        let mut decoder =
            Decoder::new(SampleRate::Hz24000, Channels::Mono).expect("decoder must build");
        let mut out = [0_i16; 2880]; // max 120 ms @ 24 kHz
        let n = decoder
            .decode(Some(&packets[0][..]), &mut out[..], false)
            .expect("decode must succeed");
        assert!(n > 0);
        // Encoder delay pads the start; only the steady-state tail must be
        // silent, with generous headroom for codec noise.
        let tail = &out[n.saturating_sub(480)..n];
        assert!(
            tail.iter().all(|&s| s.abs() < 500),
            "decoded silence must stay near zero"
        );
    }
    #[test]
    fn encode_resamples_legacy_rate() {
        let pcm: Vec<i16> = (0..2520)
            .map(|i| ((i as f32 * 0.05).sin() * 8000.0) as i16)
            .collect();
        let ogg = encode_pcm_to_opus_ogg(&pcm, 25_200).expect("encode must succeed");
        assert!(ogg.starts_with(b"OggS"));
    }

    #[test]
    fn encode_empty_input_still_terminates_stream() {
        let ogg = encode_pcm_to_opus_ogg(&[], 24_000).expect("encode must succeed");
        assert!(ogg.starts_with(b"OggS"));
        // Last page must carry the EOS flag (header_type byte 5, bit 0x04).
        let mut last_page = None;
        for i in 0..ogg.len().saturating_sub(3) {
            if &ogg[i..i + 4] == b"OggS" {
                last_page = Some(i);
            }
        }
        let last_page = last_page.expect("must have pages");
        assert!(
            ogg[last_page + 5] & 0x04 != 0,
            "final page must set end-of-stream"
        );
    }

    #[test]
    fn opus_round_trip_preserves_speech_level() {
        use audiopus::coder::Decoder;
        use std::io::Cursor;
        // 1 s tone at TTS-like level. A phone playing this back must be
        // loud: level lost here would arrive as a whisper no volume
        // setting can fix.
        let pcm: Vec<i16> = (0..24_000)
            .map(|i| ((i as f32 * 0.05).sin() * 20000.0) as i16)
            .collect();
        let ogg = encode_pcm_to_opus_ogg(&pcm, 24_000).expect("encode must succeed");
        // Demux exactly like a client: head + tags, then audio in order.
        let mut reader = ogg::PacketReader::new(Cursor::new(&ogg[..]));
        let head = reader
            .read_packet()
            .expect("head readable")
            .expect("head packet");
        assert!(head.data.starts_with(b"OpusHead"));
        reader
            .read_packet()
            .expect("tags readable")
            .expect("tags packet");
        let mut decoder =
            Decoder::new(SampleRate::Hz24000, Channels::Mono).expect("decoder must build");
        let mut decoded = Vec::new();
        let mut out = [0_i16; 2880]; // max 120 ms @ 24 kHz
        let mut audio_packets = 0;
        while let Some(packet) = reader.read_packet().expect("audio readable") {
            let n = decoder
                .decode(Some(&packet.data), &mut out[..], false)
                .expect("decode must succeed");
            decoded.extend_from_slice(&out[..n]);
            audio_packets += 1;
        }
        assert!(audio_packets > 0, "stream must carry audio packets");
        assert!(
            decoded.len().abs_diff(pcm.len()) <= 960,
            "decode must run for the clip's duration: {} vs {} samples",
            decoded.len(),
            pcm.len()
        );
        // Skip the first frame: codec delay/transient, not steady level.
        let steady = &decoded[480.min(decoded.len())..];
        let rms = |s: &[i16]| {
            (s.iter().map(|&x| f64::from(x) * f64::from(x)).sum::<f64>() / s.len() as f64)
                .sqrt()
        };
        let want = rms(&pcm[480.min(pcm.len())..]);
        let ratio = rms(steady) / want;
        assert!(
            (0.7..=1.4).contains(&ratio),
            "round trip must preserve speech level within 3 dB, got ratio {ratio}"
        );
    }

    #[test]
    fn opus_pitch_survives_encode_decode() {
        use audiopus::coder::Decoder;
        // 440 Hz sine at 24 kHz. Level checks cannot catch a sample-rate
        // mix-up; a phone playing these bytes at the wrong rate hears the
        // voice pitched/shifted ("muffled/wrong"), so pin the pitch too.
        let rate = OPUS_SAMPLE_RATE_HZ as f32;
        let pcm: Vec<i16> = (0..12_000)
            .map(|i| ((i as f32 / rate * 440.0 * std::f32::consts::TAU).sin() * 8000.0) as i16)
            .collect();
        let packets = encode_pcm_to_opus_packets(&pcm, 24_000).expect("encode must succeed");
        let mut decoder =
            Decoder::new(SampleRate::Hz24000, Channels::Mono).expect("decoder must build");
        let mut decoded = Vec::new();
        let mut out = [0_i16; 2880]; // max 120 ms @ 24 kHz
        for packet in &packets {
            let n = decoder
                .decode(Some(&packet[..]), &mut out[..], false)
                .expect("decode must succeed");
            decoded.extend_from_slice(&out[..n]);
        }
        // Skip codec edges; count zero crossings over the steady middle.
        let mid = &decoded[2400..decoded.len().saturating_sub(2400)];
        assert!(mid.len() > 4800, "decode must yield steady audio");
        let crossings = mid
            .windows(2)
            .filter(|w| (w[0] < 0) != (w[1] < 0))
            .count();
        let freq = crossings as f32 / (mid.len() as f32 / rate) / 2.0;
        assert!(
            (freq - 440.0).abs() < 25.0,
            "pitch must survive the round trip, got {freq} Hz"
        );
    }
}
