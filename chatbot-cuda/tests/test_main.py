"""CPU ownership tests for the FastAPI voice service (MOD-015).

Given independently built apps with injected fake inference services, when
lifespan runs and TTS/STT routes are called over real HTTP, then lifespan
loads the injected service on the same startup path, health and every route
resolve that same owner, two apps stay isolated, startup failures propagate,
and error mapping plus WAV tempfile cleanup hold. No torch/numpy/nemo/kokoro
imports; ``fastapi``/``httpx``/``yaml`` are required.
"""

import os
import unittest

from fastapi.testclient import TestClient  # noqa: F401 (required; fail fast)

from src.main import create_app
from src.service import InferenceService
from src.settings import VoiceSettings


def _settings(provider="kokoro"):
    return VoiceSettings(
        device="cpu",
        stt_model_id="test/stt",
        tts_provider=provider,
    )


class FakeKokoroPipeline:
    """Stdlib fake for KPipeline: yields configured audio objects."""

    def __init__(self, script, fail=None):
        self.script = list(script)
        self.fail = fail
        self.calls = []

    def __call__(self, text, voice="af_heart"):
        self.calls.append((text, voice))
        if self.fail is not None:
            raise self.fail
        for audio in self.script:
            yield (None, None, audio)


class FakeSttModel:
    def __init__(self, result):
        self.result = result
        self.paths = []

    def transcribe(self, paths):
        self.paths.append(list(paths))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _service(provider="kokoro", kokoro_script=("a", "b"), stt_result=None):
    """Build an unloaded service; lifespan loads it on TestClient entry."""
    pipeline = FakeKokoroPipeline(list(kokoro_script))
    model = FakeSttModel(["hello"] if stt_result is None else stt_result)
    service = InferenceService(
        _settings(provider),
        kokoro_factory=lambda device: pipeline,
        stt_factory=lambda model_id: model,
        pcm_converter=lambda audio: ("pcm:" + str(audio)).encode(),
    )
    return service, pipeline, model


def _converter_returning_wav_bytes(raw, target_sr=16000):
    assert target_sr == 16000
    return b"WAV:" + bytes(raw)


class TestLifespanOwnership(unittest.TestCase):
    def test_health_reflects_the_same_lifespan_owned_service(self):
        service, _, _ = _service()
        app = create_app(inference_service=service)

        with TestClient(app) as client:
            self.assertIs(app.state.inference_service, service)
            self.assertTrue(service.kokoro_loaded)
            self.assertTrue(service.stt_loaded)
            response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"status": "ok", "kokoro_loaded": True, "stt_loaded": True},
        )

    def test_two_independent_apps_do_not_share_state_or_audio(self):
        first, _, _ = _service(kokoro_script=("one",))
        second, _, _ = _service(provider="fish", stt_result=["second"])
        first_app = create_app(inference_service=first)
        second_app = create_app(
            inference_service=second,
            audio_converter=_converter_returning_wav_bytes,
        )

        with TestClient(first_app) as first_client:
            with TestClient(second_app) as second_client:
                first_health = first_client.get("/health").json()
                second_health = second_client.get("/health").json()

                first_tts = first_client.post(
                    "/v1/tts/kokoro", json={"text": "hi"}
                )
                second_stt = second_client.post(
                    "/v1/stt",
                    files={"audio": ("r.webm", b"bytes", "audio/webm")},
                )

        self.assertEqual(
            first_health,
            {"status": "ok", "kokoro_loaded": True, "stt_loaded": True},
        )
        self.assertEqual(
            second_health,
            {"status": "ok", "kokoro_loaded": False, "stt_loaded": True},
        )
        self.assertEqual(first_tts.status_code, 200)
        self.assertEqual(first_tts.content, b"pcm:one")
        self.assertEqual(second_stt.status_code, 200)
        self.assertEqual(second_stt.json(), {"text": "second"})
        self.assertIs(first_app.state.inference_service, first)
        self.assertIs(second_app.state.inference_service, second)

    def test_startup_failure_propagates_without_starting_the_app(self):
        # No injected service and no GPU deps in the test image: lifespan
        # must attempt the real load and fail instead of serving degraded.
        app = create_app(settings=_settings("kokoro"))

        with self.assertRaises(Exception):
            with TestClient(app):
                pass

    def test_injected_service_failure_propagates_through_lifespan(self):
        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: (_ for _ in ()).throw(
                RuntimeError("lifespan boom")
            ),
            stt_factory=lambda model_id: FakeSttModel(["hi"]),
            pcm_converter=lambda audio: b"x",
        )
        app = create_app(inference_service=service)

        with self.assertRaisesRegex(Exception, "lifespan boom"):
            with TestClient(app):
                pass

        self.assertFalse(service.kokoro_loaded)
        self.assertFalse(service.stt_loaded)

    def test_shipped_app_serves_all_routes_with_injected_service(self):
        import src.main as voice_main

        service, pipeline, _ = _service(kokoro_script=("z",))
        shipped = voice_main.app
        prev_service = shipped.state.pending_service
        prev_settings = shipped.state.pending_settings
        prev_converter = shipped.state.audio_converter
        shipped.state.pending_service = service
        shipped.state.pending_settings = None
        shipped.state.audio_converter = _converter_returning_wav_bytes
        try:
            with TestClient(shipped) as client:
                pipeline.calls.clear()
                health = client.get("/health")
                tts = client.post("/v1/tts/kokoro", json={"text": "hi"})
                stream = client.post("/v1/tts/kokoro/stream", json={"text": "hi"})
                blank = client.post("/v1/tts/kokoro", json={"text": ""})
                stt = client.post(
                    "/v1/stt", files={"audio": ("r.webm", b"raw", "audio/webm")}
                )
                empty = client.post(
                    "/v1/stt", files={"audio": ("e.webm", b"", "audio/webm")}
                )
        finally:
            shipped.state.pending_service = prev_service
            shipped.state.pending_settings = prev_settings
            shipped.state.audio_converter = prev_converter

        self.assertEqual(
            health.json(),
            {"status": "ok", "kokoro_loaded": True, "stt_loaded": True},
        )
        self.assertEqual(tts.status_code, 200)
        self.assertEqual(tts.content, b"pcm:z")
        self.assertEqual(tts.headers["X-Sample-Rate"], "24000")
        self.assertEqual(stream.status_code, 200)
        self.assertEqual(stream.content, b"pcm:z")
        self.assertEqual(blank.status_code, 400)
        self.assertEqual(stt.json(), {"text": "hello"})
        self.assertEqual(empty.status_code, 400)


class TestTtsRoutes(unittest.TestCase):
    def test_tts_rejects_blank_text_without_synthesizing(self):
        service, pipeline, _ = _service()
        app = create_app(inference_service=service)

        with TestClient(app) as client:
            pipeline.calls.clear()
            response = client.post("/v1/tts/kokoro", json={"text": "  "})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "text is required")
        self.assertEqual(pipeline.calls, [])

    def test_tts_returns_pcm_with_sample_rate_header(self):
        service, pipeline, _ = _service(kokoro_script=("a", "b"))
        app = create_app(inference_service=service)

        with TestClient(app) as client:
            pipeline.calls.clear()
            response = client.post(
                "/v1/tts/kokoro", json={"text": "hello", "voice": "af_heart"}
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"pcm:apcm:b")
        self.assertEqual(response.headers["X-Sample-Rate"], "24000")
        self.assertIn("application/octet-stream", response.headers["content-type"])
        self.assertEqual(pipeline.calls, [("hello", "af_heart")])

    def test_tts_maps_synthesis_failure_to_500(self):
        pipeline = FakeKokoroPipeline([], fail=RuntimeError("synth boom"))
        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: pipeline,
            stt_factory=lambda model_id: FakeSttModel(["hi"]),
            pcm_converter=lambda audio: b"x",
        )
        app = create_app(inference_service=service)

        with TestClient(app) as client:
            response = client.post("/v1/tts/kokoro", json={"text": "hi"})

        self.assertEqual(response.status_code, 500)
        self.assertIn("synth boom", response.json()["detail"])

    def test_tts_stream_delivers_sentence_chunks_with_rate(self):
        service, _, _ = _service(kokoro_script=("x", "y"))
        app = create_app(inference_service=service)

        with TestClient(app) as client:
            response = client.post("/v1/tts/kokoro/stream", json={"text": "hi"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"pcm:xpcm:y")
        self.assertEqual(response.headers["X-Sample-Rate"], "24000")

    def test_tts_stream_rejects_blank_text(self):
        service, _, _ = _service()
        app = create_app(inference_service=service)

        with TestClient(app) as client:
            response = client.post("/v1/tts/kokoro/stream", json={"text": ""})

        self.assertEqual(response.status_code, 400)


class TestSttRoutes(unittest.TestCase):
    def test_stt_rejects_empty_upload(self):
        service, _, _ = _service()
        app = create_app(
            inference_service=service, audio_converter=_converter_returning_wav_bytes
        )

        with TestClient(app) as client:
            response = client.post(
                "/v1/stt", files={"audio": ("empty.webm", b"", "audio/webm")}
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "audio file is empty")

    def test_stt_maps_conversion_failure_to_422(self):
        service, _, _ = _service()

        def _failing(raw, target_sr=16000):
            raise RuntimeError("ffmpeg gone")

        app = create_app(inference_service=service, audio_converter=_failing)

        with TestClient(app) as client:
            response = client.post(
                "/v1/stt", files={"audio": ("r.webm", b"data", "audio/webm")}
            )

        self.assertEqual(response.status_code, 422)
        self.assertIn("ffmpeg gone", response.json()["detail"])

    def test_stt_returns_text_and_cleans_staging_wav(self):
        seen = {}

        class _RecordingStt:
            def transcribe(self, paths):
                seen["path"] = paths[0]
                seen["existed"] = os.path.exists(paths[0])
                return ["  hello world  "]

        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: FakeKokoroPipeline(["w"]),
            stt_factory=lambda model_id: _RecordingStt(),
            pcm_converter=lambda audio: b"x",
        )
        app = create_app(
            inference_service=service, audio_converter=_converter_returning_wav_bytes
        )

        with TestClient(app) as client:
            response = client.post(
                "/v1/stt", files={"audio": ("r.webm", b"raw", "audio/webm")}
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"text": "hello world"})
        self.assertTrue(seen["existed"], "WAV staging file must exist during transcribe")
        self.assertFalse(
            os.path.exists(seen["path"]),
            "WAV staging file must be unlinked after the request",
        )

    def test_stt_maps_transcription_failure_to_500(self):
        service, _, _ = _service(stt_result=RuntimeError("decode boom"))
        app = create_app(
            inference_service=service, audio_converter=_converter_returning_wav_bytes
        )

        with TestClient(app) as client:
            response = client.post(
                "/v1/stt", files={"audio": ("r.webm", b"raw", "audio/webm")}
            )

        self.assertEqual(response.status_code, 500)
        self.assertIn("decode boom", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
