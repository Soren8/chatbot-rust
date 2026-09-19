"""Non-streaming inference job and staging-file lifetime (MOD-015-A).

Given the real InferenceService with event-gated fake pipelines plus the
real FastAPI TTS/STT routes, when full synthesis or transcription blocks in
its worker while the awaiting coroutine is cancelled or the service shuts
down, then cancellation stays cooperative (worker runs to exit, no forced
GPU interrupt), the STT staging file stays usable until the worker actually
finishes and is then removed, shutdown accounts for live jobs and rejects
new admission under one bounded off-loop deadline while the event loop stays
responsive, and worker errors or failed starts still clean up. No
torch/numpy/GPU; coordination via threading events only.
"""

import asyncio
import os
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from src.main import KokoroTtsRequest, kokoro_tts, stt
from src.service import InferenceService
from src.settings import VoiceSettings


def _settings(provider="kokoro"):
    return VoiceSettings(
        device="cpu",
        stt_model_id="test/stt",
        tts_provider=provider,
    )


class FakeSttModel:
    def __init__(self, result):
        self.result = result

    def transcribe(self, paths):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class FakeKokoroPipeline:
    """Stdlib fake for KPipeline: yields configured audio objects."""

    def __init__(self, script):
        self.script = list(script)

    def __call__(self, text, voice="af_heart"):
        for audio in self.script:
            yield (None, None, audio)


def _tts_stub(service):
    return SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(inference_service=service)
        )
    )


def _stt_stub(service, converter):
    return SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                inference_service=service,
                audio_converter=converter,
            )
        )
    )


class _FakeAudio:
    def __init__(self, payload):
        self._payload = payload

    async def read(self):
        return self._payload


def _wav_converter(raw, target_sr=16000):
    assert target_sr == 16000
    return b"WAV:" + bytes(raw)


class TestBlockedTtsBlocksShutdown(unittest.TestCase):
    def test_blocked_production_tts_holds_shutdown_until_release(self):
        entered = threading.Event()
        release = threading.Event()

        class GatedPipeline:
            def __call__(self, text, voice="af_heart"):
                entered.set()
                self_saw_release = release.wait(timeout=5.0)
                assert self_saw_release, "test must release the worker"
                yield (None, None, "one")

        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: GatedPipeline(),
            stt_factory=lambda model_id: FakeSttModel(["hi"]),
            pcm_converter=lambda audio: ("pcm:" + str(audio)).encode(),
        )
        service.load_models()
        try:

            async def run():
                route_task = asyncio.create_task(
                    kokoro_tts(
                        KokoroTtsRequest(text="hi"), _tts_stub(service)
                    )
                )
                entered_ok = await asyncio.to_thread(entered.wait, 5.0)
                self.assertTrue(entered_ok, "worker must block in synthesis")
                shutdown_task = asyncio.create_task(service.aclose())

                async def _probe():
                    return "alive"

                probe_task = asyncio.create_task(_probe())
                self.assertEqual(
                    await asyncio.wait_for(probe_task, timeout=5.0), "alive"
                )
                await asyncio.sleep(0.05)
                self.assertFalse(
                    shutdown_task.done(),
                    "shutdown must account for live production TTS work",
                )
                release.set()
                response = await asyncio.wait_for(route_task, timeout=5.0)
                self.assertEqual(response.body, b"pcm:one")
                await asyncio.wait_for(shutdown_task, timeout=5.0)
                self.assertEqual(service.active_stream_count(), 0)

            asyncio.run(run())
        finally:
            release.set()


class TestCancelledSttKeepsStagingFile(unittest.TestCase):
    def test_cancelled_waiter_keeps_file_until_worker_exit(self):
        entered = threading.Event()
        release = threading.Event()
        seen = {}

        class BlockingStt:
            def transcribe(self, paths):
                seen["path"] = paths[0]
                seen["existed_during"] = os.path.exists(paths[0])
                entered.set()
                self_saw_release = release.wait(timeout=5.0)
                assert self_saw_release, "test must release the worker"
                seen["existed_before_return"] = os.path.exists(paths[0])
                return ["hello"]

        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: FakeKokoroPipeline(["w"]),
            stt_factory=lambda model_id: BlockingStt(),
            pcm_converter=lambda audio: b"x",
        )
        # Fake pipeline for kokoro load (unused by STT route).
        service._kokoro_pipeline = FakeKokoroPipeline(["w"])
        service._kokoro_loaded = True
        service.load_stt()
        try:

            async def run():
                route_task = asyncio.create_task(
                    stt(
                        _stt_stub(service, _wav_converter),
                        _FakeAudio(b"raw"),
                    )
                )
                entered_ok = await asyncio.to_thread(entered.wait, 5.0)
                self.assertTrue(entered_ok, "worker must block in transcribe")
                self.assertTrue(
                    seen["existed_during"],
                    "WAV staging file must exist during transcribe",
                )
                route_task.cancel()
                try:
                    await route_task
                except asyncio.CancelledError:
                    pass
                self.assertTrue(
                    os.path.exists(seen["path"]),
                    "staging file must survive waiter cancel until worker exit",
                )
                release.set()
                deadline = time.monotonic() + 5.0
                while (
                    os.path.exists(seen["path"])
                    and time.monotonic() < deadline
                ):
                    await asyncio.sleep(0.02)
                self.assertFalse(
                    os.path.exists(seen["path"]),
                    "staging file must be removed after worker exit",
                )
                self.assertTrue(
                    seen["existed_before_return"],
                    "file must stay usable until the worker returns",
                )
                await asyncio.wait_for(service.aclose(), timeout=5.0)

            asyncio.run(run())
        finally:
            release.set()


class TestShutdownRejectsNewAdmission(unittest.TestCase):
    def test_new_production_tts_rejected_after_shutdown(self):
        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: FakeKokoroPipeline(["a"]),
            stt_factory=lambda model_id: FakeSttModel(["hi"]),
            pcm_converter=lambda audio: b"x",
        )
        service.load_models()
        asyncio.run(service.aclose())

        async def run():
            with self.assertRaisesRegex(Exception, "shut"):
                await kokoro_tts(
                    KokoroTtsRequest(text="hi"), _tts_stub(service)
                )

        asyncio.run(run())

    def test_new_production_stt_rejected_after_shutdown(self):
        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: FakeKokoroPipeline(["a"]),
            stt_factory=lambda model_id: FakeSttModel(["hi"]),
            pcm_converter=lambda audio: b"x",
        )
        service.load_models()
        asyncio.run(service.aclose())

        async def run():
            with self.assertRaisesRegex(Exception, "shut"):
                await stt(
                    _stt_stub(service, _wav_converter),
                    _FakeAudio(b"raw"),
                )

        asyncio.run(run())


class TestWorkerErrorCleansStagingFile(unittest.TestCase):
    def test_transcription_failure_removes_staging_file(self):
        seen = {}

        class FailingStt:
            def transcribe(self, paths):
                seen["path"] = paths[0]
                seen["existed"] = os.path.exists(paths[0])
                raise RuntimeError("decode boom")

        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: FakeKokoroPipeline(["w"]),
            stt_factory=lambda model_id: FailingStt(),
            pcm_converter=lambda audio: b"x",
        )
        service._kokoro_pipeline = FakeKokoroPipeline(["w"])
        service._kokoro_loaded = True
        service.load_stt()

        async def run():
            from fastapi import HTTPException

            with self.assertRaisesRegex(HTTPException, "decode boom"):
                await stt(
                    _stt_stub(service, _wav_converter),
                    _FakeAudio(b"raw"),
                )

        asyncio.run(run())
        self.assertTrue(seen["existed"], "file must exist during transcribe")
        self.assertFalse(
            os.path.exists(seen["path"]),
            "staging file must be removed after worker error",
        )
        asyncio.run(service.aclose())


class TestFailedStartCleansUp(unittest.TestCase):
    def test_thread_start_failure_rejects_tts_without_leak(self):
        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: FakeKokoroPipeline(["a"]),
            stt_factory=lambda model_id: FakeSttModel(["hi"]),
            pcm_converter=lambda audio: b"x",
        )
        service.load_models()

        async def run():
            with self.assertRaisesRegex(Exception, "no threads|shut|500"):
                await kokoro_tts(
                    KokoroTtsRequest(text="hi"), _tts_stub(service)
                )

        loop = asyncio.new_event_loop()
        try:
            with mock.patch.object(
                threading.Thread,
                "start",
                side_effect=RuntimeError("no threads"),
            ):
                loop.run_until_complete(run())
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            loop.close()
        self.assertEqual(service.active_stream_count(), 0)
        asyncio.run(service.aclose())


if __name__ == "__main__":
    unittest.main()
