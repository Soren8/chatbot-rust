//! Offline fixture encoder for the trusted `android-opus-decoder-check`
//! builder (see `.devcontainer/test-executor/trusted/audio-decoder-check/`).
//!
//! Reads raw mono PCM16 little-endian and writes Ogg-Opus using the exact
//! production server encoder (`tts_opus::encode_pcm_to_opus_ogg`). The Android
//! decoder comparison must exercise the real wire format, so this intentionally
//! reuses the server module via `#[path]` rather than reimplementing encoding.
//!
//! It ships as a cargo example: the production image builds only the
//! `chatbot-server` binary, never examples. `cargo test` compiles it to keep it
//! from rotting, but never runs it.
//!
//! `tts_opus` is a private module of the `chatbot-server` library
//! (`src/lib.rs`), so an example cannot reach it through the public crate API.
//! This `#[path]` include compiles the exact production source without
//! widening the library's public visibility for a test-only caller.

#[path = "../src/tts_opus.rs"]
mod tts_opus;

use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: tts_opus_fixture <pcm16le-input> <sample-rate-hz> <out.ogg>");
        return ExitCode::from(2);
    }
    let raw = match fs::read(&args[1]) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("read {}: {err}", args[1]);
            return ExitCode::FAILURE;
        }
    };
    if raw.len() % 2 != 0 {
        eprintln!("PCM byte count must be even, got {}", raw.len());
        return ExitCode::FAILURE;
    }
    let from_rate: u32 = match args[2].parse() {
        Ok(rate) => rate,
        Err(err) => {
            eprintln!("invalid sample rate {:?}: {err}", args[2]);
            return ExitCode::FAILURE;
        }
    };
    let samples: Vec<i16> = raw
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    match tts_opus::encode_pcm_to_opus_ogg(&samples, from_rate) {
        Ok(ogg) => match fs::write(&args[3], &ogg) {
            Ok(()) => {
                println!(
                    "encoded {} samples at {from_rate} Hz -> {} bytes",
                    samples.len(),
                    ogg.len()
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("write {}: {err}", args[3]);
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            eprintln!("encode failed: {err:#}");
            ExitCode::FAILURE
        }
    }
}
