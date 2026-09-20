"""Settle-after-cleanup ordering for non-streaming jobs (MOD-015-A review).

Given the real InferenceService plus the real TTS/STT routes with
event-gated fakes, when a worker finishes its inference call, then the
waiter result must settle only after staging-file cleanup and
unregistration (never while the file is retained). No torch/numpy/GPU;
coordination via threading events only.
"""

import asyncio
import os
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import src.service as voice_service
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


def _tts_stub(service):
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(inference_service=service))
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


def _gated_unlink(original, entered, release):
    def _wrapper(*args):
        path = args[-1]
        if isinstance(path, str) and path.endswith(".wav"):
            entered.set()
            assert release.wait(timeout=5.0), "test must release cleanup"
        return original(*args)

    return _wrapper


class TestSuccessSettlesAfterCleanup(unittest.TestCase):
    def test_waiter_pending_until_cleanup_done_then_result(self):
        entered = threading.Event()
        release = threading.Event()
        seen = {}

        class RecordingStt:
            def transcribe(self, paths):
                seen["path"] = paths[0]
                return ["hello"]

        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: FakeSttModel(["hi"]),
            stt_factory=lambda model_id: RecordingStt(),
            pcm_converter=lambda audio: b"x",
        )
        service._kokoro_pipeline = FakeSttModel(["hi"])
        service._kokoro_loaded = True
        service.load_stt()
        original = InferenceService._unlink_quietly
        try:

            async def run():
                route_task = asyncio.create_task(
                    stt(_stt_stub(service, _wav_converter), _FakeAudio(b"raw"))
                )
                entered_ok = await asyncio.to_thread(entered.wait, 5.0)
                self.assertTrue(entered_ok, "worker must reach cleanup")
                await asyncio.sleep(0.05)
                self.assertFalse(
                    route_task.done(),
                    "waiter must not settle before cleanup finishes",
                )
                self.assertEqual(service.active_job_count(), 1)
                release.set()
                response = await asyncio.wait_for(route_task, timeout=5.0)
                self.assertEqual(response, {"text": "hello"})
                self.assertEqual(service.active_job_count(), 0)
                return response

            with mock.patch.object(
                InferenceService,
                "_unlink_quietly",
                side_effect=_gated_unlink(original, entered, release),
            ):
                asyncio.run(run())
            self.assertFalse(
                os.path.exists(seen["path"]),
                "staging file must be gone when the waiter settles",
            )
            asyncio.run(service.aclose())
        finally:
            release.set()


class TestErrorSettlesAfterCleanup(unittest.TestCase):
    def test_error_pending_until_cleanup_done_then_raises(self):
        entered = threading.Event()
        release = threading.Event()
        seen = {}

        class RecordingFailingStt:
            def transcribe(self, paths):
                seen["path"] = paths[0]
                raise RuntimeError("decode boom")

        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: FakeSttModel(["hi"]),
            stt_factory=lambda model_id: RecordingFailingStt(),
            pcm_converter=lambda audio: b"x",
        )
        service._kokoro_pipeline = FakeSttModel(["hi"])
        service._kokoro_loaded = True
        service.load_stt()
        original = InferenceService._unlink_quietly
        try:

            async def run():
                from fastapi import HTTPException

                route_task = asyncio.create_task(
                    stt(_stt_stub(service, _wav_converter), _FakeAudio(b"raw"))
                )
                entered_ok = await asyncio.to_thread(entered.wait, 5.0)
                self.assertTrue(entered_ok, "worker must reach cleanup")
                await asyncio.sleep(0.05)
                self.assertFalse(
                    route_task.done(),
                    "error must not settle before cleanup finishes",
                )
                self.assertEqual(service.active_job_count(), 1)
                release.set()
                with self.assertRaisesRegex(HTTPException, "decode boom"):
                    await asyncio.wait_for(route_task, timeout=5.0)
                self.assertEqual(service.active_job_count(), 0)

            with mock.patch.object(
                InferenceService,
                "_unlink_quietly",
                side_effect=_gated_unlink(original, entered, release),
            ):
                asyncio.run(run())
            self.assertFalse(
                os.path.exists(seen["path"]),
                "staging file must be gone when the error settles",
            )
            asyncio.run(service.aclose())
        finally:
            release.set()


class TestSttStartFailureCleansFile(unittest.TestCase):
    def test_stt_thread_start_failure_removes_staging_file(self):
        created = []
        unlinked = []
        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: FakeSttModel(["hi"]),
            stt_factory=lambda model_id: FakeSttModel(["hi"]),
            pcm_converter=lambda audio: b"x",
        )
        service._kokoro_pipeline = FakeSttModel(["hi"])
        service._kokoro_loaded = True
        service.load_stt()
        import src.main as voice_main

        real_tmp = tempfile.NamedTemporaryFile
        real_unlink = InferenceService._unlink_quietly

        def _recording_tmp(*args, **kwargs):
            tmp = real_tmp(*args, **kwargs)
            created.append(tmp.name)
            return tmp

        def _recording_unlink(path):
            unlinked.append(path)
            return real_unlink(path)

        async def run():
            from fastapi import HTTPException

            with self.assertRaisesRegex(HTTPException, "no threads"):
                await stt(_stt_stub(service, _wav_converter), _FakeAudio(b"r"))

        loop = asyncio.new_event_loop()
        try:
            with (
                mock.patch.object(
                    threading.Thread,
                    "start",
                    side_effect=RuntimeError("no threads"),
                ),
                mock.patch.object(
                    voice_main.tempfile, "NamedTemporaryFile", _recording_tmp
                ),
                mock.patch.object(
                    InferenceService,
                    "_unlink_quietly",
                    staticmethod(_recording_unlink),
                ),
            ):
                loop.run_until_complete(run())
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            loop.close()
        self.assertEqual(len(created), 1)
        self.assertIn(created[0], unlinked)
        self.assertFalse(os.path.exists(created[0]))
        self.assertEqual(service.active_job_count(), 0)
        asyncio.run(service.aclose())


class TestSttAdmissionRejectionCleansFile(unittest.TestCase):
    def test_rejected_stt_after_shutdown_removes_staging_file(self):
        created = []
        unlinked = []
        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: FakeSttModel(["hi"]),
            stt_factory=lambda model_id: FakeSttModel(["hi"]),
            pcm_converter=lambda audio: b"x",
        )
        service._kokoro_pipeline = FakeSttModel(["hi"])
        service._kokoro_loaded = True
        service.load_stt()
        asyncio.run(service.aclose())
        import src.main as voice_main

        real_tmp = tempfile.NamedTemporaryFile
        real_unlink = InferenceService._unlink_quietly

        def _recording_tmp(*args, **kwargs):
            tmp = real_tmp(*args, **kwargs)
            created.append(tmp.name)
            return tmp

        def _recording_unlink(path):
            unlinked.append(path)
            return real_unlink(path)

        async def run():
            with self.assertRaisesRegex(Exception, "shut"):
                await stt(_stt_stub(service, _wav_converter), _FakeAudio(b"r"))

        with (
            mock.patch.object(
                voice_main.tempfile, "NamedTemporaryFile", _recording_tmp
            ),
            mock.patch.object(
                InferenceService,
                "_unlink_quietly",
                staticmethod(_recording_unlink),
            ),
        ):
            asyncio.run(run())
        self.assertEqual(len(created), 1)
        self.assertIn(created[0], unlinked)
        self.assertFalse(os.path.exists(created[0]))


class TestCancelledTtsShutdownAccounting(unittest.TestCase):
    def test_cancelled_tts_worker_still_held_by_shutdown(self):
        entered = threading.Event()
        release = threading.Event()

        class GatedPipeline:
            def __call__(self, text, voice="af_heart"):
                if text.startswith("Hello"):
                    yield (None, None, "warm")
                    return
                entered.set()
                assert release.wait(timeout=5.0), "test must release"
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
                    kokoro_tts(KokoroTtsRequest(text="hi"), _tts_stub(service))
                )
                entered_ok = await asyncio.to_thread(entered.wait, 5.0)
                self.assertTrue(entered_ok, "worker must block")
                self.assertEqual(service.active_job_count(), 1)
                route_task.cancel()
                try:
                    await route_task
                except asyncio.CancelledError:
                    pass
                self.assertEqual(service.active_job_count(), 1)
                shutdown_task = asyncio.create_task(service.aclose())

                async def _probe():
                    return "alive"

                self.assertEqual(
                    await asyncio.wait_for(_probe(), timeout=5.0), "alive"
                )
                await asyncio.sleep(0.05)
                self.assertFalse(
                    shutdown_task.done(), "shutdown must hold live job"
                )
                release.set()
                await asyncio.wait_for(shutdown_task, timeout=5.0)
                self.assertEqual(service.active_job_count(), 0)

            asyncio.run(run())
        finally:
            release.set()


class TestCombinedStreamJobShutdown(unittest.TestCase):
    def _pipeline(self, entered_stream, entered_job, release):
        class SharedGatedPipeline:
            def __call__(self, text, voice="af_heart"):
                if text.startswith("Hello"):
                    yield (None, None, "warm")
                    return
                if text == "stream":
                    yield (None, None, "s1")
                    entered_stream.set()
                    assert release.wait(timeout=5.0), "release stream"
                    yield (None, None, "s2")
                else:
                    entered_job.set()
                    assert release.wait(timeout=5.0), "release job"
                    yield (None, None, "j1")

        return SharedGatedPipeline()

    def test_shutdown_waits_for_stream_and_job(self):
        entered_stream = threading.Event()
        entered_job = threading.Event()
        release = threading.Event()
        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: self._pipeline(
                entered_stream, entered_job, release
            ),
            stt_factory=lambda model_id: FakeSttModel(["hi"]),
            pcm_converter=lambda audio: ("pcm:" + str(audio)).encode(),
        )
        service.load_models()
        try:

            async def run():
                gen = service.synthesize_kokoro_stream("stream")
                first = await asyncio.wait_for(gen.__anext__(), timeout=5.0)
                self.assertEqual(first, b"pcm:s1")
                route_task = asyncio.create_task(
                    kokoro_tts(KokoroTtsRequest(text="job"), _tts_stub(service))
                )
                self.assertTrue(
                    await asyncio.to_thread(entered_job.wait, 5.0),
                    "job worker must block",
                )
                self.assertEqual(service.active_stream_count(), 1)
                self.assertEqual(service.active_job_count(), 1)
                shutdown_task = asyncio.create_task(service.aclose())

                async def _probe():
                    return "alive"

                self.assertEqual(
                    await asyncio.wait_for(_probe(), timeout=5.0), "alive"
                )
                await asyncio.sleep(0.05)
                self.assertFalse(
                    shutdown_task.done(), "shutdown must hold both"
                )
                release.set()
                response = await asyncio.wait_for(route_task, timeout=5.0)
                self.assertEqual(response.body, b"pcm:j1")
                rest = [chunk async for chunk in gen]
                self.assertEqual(
                    rest,
                    [],
                    "shutdown cancels the stream at the sentence boundary "
                    "while the job runs to completion",
                )
                await asyncio.wait_for(shutdown_task, timeout=5.0)
                self.assertEqual(service.active_stream_count(), 0)
                self.assertEqual(service.active_job_count(), 0)

            asyncio.run(run())
        finally:
            release.set()

    def test_shared_deadline_bounds_and_retains_busy_workers(self):
        entered_stream = threading.Event()
        entered_job = threading.Event()
        release = threading.Event()
        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: self._pipeline(
                entered_stream, entered_job, release
            ),
            stt_factory=lambda model_id: FakeSttModel(["hi"]),
            pcm_converter=lambda audio: ("pcm:" + str(audio)).encode(),
        )
        service.load_models()
        try:

            async def run():
                gen = service.synthesize_kokoro_stream("stream")
                first = await asyncio.wait_for(gen.__anext__(), timeout=5.0)
                self.assertEqual(first, b"pcm:s1")
                route_task = asyncio.create_task(
                    kokoro_tts(KokoroTtsRequest(text="job"), _tts_stub(service))
                )
                self.assertTrue(
                    await asyncio.to_thread(entered_job.wait, 5.0),
                    "job worker must block",
                )
                start = time.monotonic()
                await asyncio.wait_for(service.aclose(), timeout=5.0)
                elapsed = time.monotonic() - start
                self.assertLess(
                    elapsed, 2.0, "shared deadline must bound shutdown"
                )
                self.assertEqual(service.active_stream_count(), 1)
                self.assertEqual(service.active_job_count(), 1)
                release.set()
                response = await asyncio.wait_for(route_task, timeout=5.0)
                self.assertEqual(response.body, b"pcm:j1")
                rest = [chunk async for chunk in gen]
                self.assertEqual(
                    rest,
                    [],
                    "timed-out shutdown cancels the stream at the boundary "
                    "while the job runs to completion",
                )
                deadline = time.monotonic() + 5.0
                while (
                    service.active_stream_count()
                    + service.active_job_count()
                    > 0
                    and time.monotonic() < deadline
                ):
                    await asyncio.sleep(0.02)
                self.assertEqual(service.active_stream_count(), 0)
                self.assertEqual(service.active_job_count(), 0)

            with mock.patch.object(
                voice_service, "_SHUTDOWN_JOIN_TIMEOUT", 0.3
            ):
                asyncio.run(run())
        finally:
            release.set()


if __name__ == "__main__":
    unittest.main()
