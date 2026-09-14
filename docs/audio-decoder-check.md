# Android Opus decoder check (pre-AudioTrack, off-device)

`android-opus-decoder-check` is a trusted host-executor artifact operation that
verifies the **decode path that runs immediately before `AudioTrack`**: the
production Android `OggOpusStreamDecoder` (Concentus 1.0.2, pure Java) versus a
libopus reference decode of the same Ogg-Opus packets. It exists because the
WebView/browser path and the native path can diverge, and because neither
`cargo test` nor the Android APK build decodes a real server-encoded clip on the
wire format the phone receives.

**This is not part of `cargo test` or the ordinary test suite.** It runs only as
the `android-opus-decoder-check` executor operation, so it needs the executor
image rolled out on the host (see [Running it](#running-it)). The Rust suite
compiles the fixture-encoder example, but it never runs Java or decodes a clip.

Scope: **pre-AudioTrack only.** It does not exercise `AudioTrack` playback,
device routing, audio focus, volume, or the native download/queue logic, and it
does not claim identical on-device media behaviour. A green run means "the phone
decoder turns the server's bytes into the expected PCM", not "voice playback
works".

## Pipeline

1. Two fixtures are generated inside the trusted builder image:
   - a deterministic 440 Hz tone (24 kHz mono PCM16);
   - **eSpeak-ng** synthetic speech (`en-us`, speed 150; no external or private
     recordings), resampled by the server encoder from its native 22050 Hz.
2. Each fixture is encoded to a complete Ogg-Opus clip by the **actual** Rust
   server encoder — `chatbot-server`'s `tts_opus::encode_pcm_to_opus_ogg`
   (libopus), invoked through a cargo example that includes the production
   module, not a reimplementation.
3. The same clip is decoded to 24 kHz PCM16 by:
   - **libopus** (`opusdec --rate 24000`) — the reference; and
   - the production `OggOpusStreamDecoder` **from the snapshot** (whatever the
     app would run), fed through the decoder's `feed()` in several network
     shapes: whole clip, fixed chunk sizes `1`, `4`, `27`, `64`, `4096`, and
     `split-headers` (each 27-byte Ogg page header delivered in pieces).
4. Decoded PCM and the decoder's reported state are compared per
   fixture/chunk case. The operation returns a bounded ZIP with the input Ogg,
   reference WAV, every captured Concentus WAV, `metrics.json`, `summary.txt`,
   and `verdict.txt`.

## What makes a case fail (`compare.py`)

- **decoder state**: the decoded sample rate must be 24 kHz, and the production
  decoder must report `sawOpusHead`, `sawEndOfStream`, and no incomplete data.
  Missing headers/EOS or a truncated stream fails even if the PCM it did emit
  looks plausible.
- **chunk invariance (exact)**: every chunk shape must produce **byte-identical
  PCM** to the single all-at-once feed. The same Java decoder is deterministic,
  so this is an exact check, not a tolerance.

Fixed signal tolerances rather than per-fixture tuning:

| Check | Bound | Why |
|---|---|---|
| sample count | ±240 samples (±½ frame) | independent integer decoders may round the final frame; a dropped 20 ms frame still fails |
| level (RMS) | ±3 dB | codec noise + i16 rounding |
| correlation | ≥ 0.90 over the **full clip** | same packets and rate; the lag is found on a bounded prefix, but the score is measured over the whole overlap so distortion after the opening second is caught |
| pitch | ≤ 5% error | enforced on the pure-tone fixture only; speech is recorded but informational because a fundamental estimate on a chopped speech window is inherently ambiguous |

## Concentus 1.0.2 hybrid bug and the 48 kHz decode path

The check exists because of a real library defect it caught. In Concentus 1.0.2,
`CeltCommon.deemphasis` ignores its `accum` flag on the resampling path
(`downsample > 1`, i.e. any output rate below 48 kHz): libopus **adds** the
downsampled CELT signal to the SILK PCM already in the output buffer, while the
port overwrites it. Opus `OpusDecoder` runs hybrid (SILK+CELT) packets in this
accumulate mode, so at 24 kHz every hybrid packet loses its SILK layer and
decodes to near silence. The server's 24 kbps mono stream is hybrid, so the phone
path was silent while the browser (native Ogg-Opus) played fine. Upstream
`lostromb/concentus` master has the same code and the last Maven release is
1.0.2, so there is no fixed artifact to depend on.

`OggOpusStreamDecoder` therefore decodes at 48 kHz — the one supported output
rate where Concentus does not resample, so the accumulate branch is correct — and
downsamples to the OpusHead rate with its own anti-aliasing FIR. The captured
`concentus/*.wav` files are these resampled outputs; the app reports the
OpusHead rate (`sampleRate()`), and the decoder-state and chunk-invariance checks
are unchanged. If a future Concentus release fixes `deemphasis`, the decode rate
can return to the OpusHead rate and the FIR can be dropped.

## Status contract

The operation is an `artifact`: **`status=artifact` means the ZIP was produced,
not that the comparison passed.** A signal failure still returns the ZIP so the
captured WAVs remain available for inspection; the real verdict is in
`metrics.json` / `verdict.txt` and the tagged `AUDIO-DECODER-CHECK verdict=...`
stdout line. Read the metrics.

## Running it

The operation is defined in `test-executor/trusted/audio-decoder-check/` and is
baked into the host executor image. **It requires executor rollout** (a human
runs this on the host; the agent sandbox cannot reach the Docker daemon):

```bash
cd /home/malakar/github/.devcontainer && docker compose up --build -d
```

Then, from the sandbox:

```bash
testctl --project chatbot-rust --operation artifact \
  --suite android-opus-decoder-check \
  --repo /workspace/chatbot-rust \
  --artifact-out ./android-opus-decoder-comparison.zip

python3 -m zipfile -e ./android-opus-decoder-comparison.zip ./audio-check-out
python3 -c "import json;print(json.load(open('./audio-check-out/metrics.json'))['verdict'])"
```

The ordinary Rust/Android suite remains the project's normal gate and runs with:

```bash
testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust
```
