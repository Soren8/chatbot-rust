"""Bounded streaming lifecycle ownership (MOD-015).

Given explicit settings plus event-gated stdlib fakes, when a Kokoro stream
consumer disconnects, stalls, fails, or the service shuts down, then the
service-owned producer work must cancel cooperatively with bounded buffering,
propagate errors/sentinel, survive loop-close, and reject starts after
shutdown. No torch/numpy/GPU; coordination via threading events only.
"""

import asyncio
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from src.main import create_app
from src.service import InferenceService
from src.settings import VoiceSettings

try:
    from fastapi.testclient import TestClient  # noqa: F401 (required; fail fast)
except Exception:  # pragma: no cover
    TestClient = None  # type: ignore


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
        return self.result


class FakeKokoroPipeline:
    """Yields configured audio objects immediately."""

    def __init__(self, script):
        self.script = list(script)

    def __call__(self, text, voice="af_heart"):
        for audio in self.script:
            yield (None, None, audio)


def _service(pipeline, converter):
    return InferenceService(
        _settings("kokoro"),
        kokoro_factory=lambda device: pipeline,
        stt_factory=lambda model_id: FakeSttModel(["hi"]),
        pcm_converter=converter,
    )


class TestDisconnectCancellation(unittest.TestCase):
    def test_disconnect_stops_producer_before_next_sentence(self):
        gate = threading.Event()
        converted_two = threading.Event()

        def converter(audio):
            if audio == "two":
                converted_two.set()
            return ("pcm:" + str(audio)).encode()

        class GatedPipeline:
            def __call__(self, text, voice="af_heart"):
                yield (None, None, "one")
                gate.wait(timeout=5.0)
                yield (None, None, "two")
                yield (None, None, "three")

        service = _service(GatedPipeline(), converter)
        service.load_models()

        async def consume():
            gen = service.synthesize_kokoro_stream("hi")
            first = await gen.__anext__()
            self.assertEqual(first, b"pcm:one")
            await gen.aclose()
            gate.set()
            did_convert = await asyncio.to_thread(converted_two.wait, 1.0)
            self.assertFalse(
                did_convert,
                "disconnect must cancel the producer before the next sentence",
            )

        asyncio.run(consume())


class TestBoundedBackpressure(unittest.TestCase):
    def test_slow_consumer_blocks_producer_with_bounded_buffer(self):
        reached_five = threading.Event()
        reached_twenty = threading.Event()
        count = []

        def converter(audio):
            count.append(audio)
            if len(count) >= 5:
                reached_five.set()
            if len(count) >= 20:
                reached_twenty.set()
            return ("pcm:" + str(audio)).encode()

        pipeline = FakeKokoroPipeline([str(i) for i in range(20)])
        service = _service(pipeline, converter)
        service.load_models()

        async def consume():
            gen = service.synthesize_kokoro_stream("hi")
            first = await gen.__anext__()
            self.assertEqual(first, b"pcm:0")
            got_five = await asyncio.to_thread(reached_five.wait, 5.0)
            self.assertTrue(got_five, "producer must fill the bounded buffer")
            got_twenty = await asyncio.to_thread(reached_twenty.wait, 0.5)
            self.assertFalse(
                got_twenty,
                "bounded buffer must backpressure a slow consumer",
            )
            await gen.aclose()

        asyncio.run(consume())


class TestShutdownOwnership(unittest.TestCase):
    def test_shutdown_cancels_active_stream_and_joins_off_loop(self):
        gate = threading.Event()
        entered = threading.Event()

        def converter(audio):
            return ("pcm:" + str(audio)).encode()

        class GatedPipeline:
            def __call__(self, text, voice="af_heart"):
                yield (None, None, "one")
                entered.set()
                gate.wait(timeout=5.0)
                yield (None, None, "two")

        service = _service(GatedPipeline(), converter)
        service.load_models()

        async def consume():
            gen = service.synthesize_kokoro_stream("hi")
            first = await gen.__anext__()
            self.assertEqual(first, b"pcm:one")
            entered_ok = await asyncio.to_thread(entered.wait, 5.0)
            self.assertTrue(entered_ok, "producer must block in the gate")
            shutdown_task = asyncio.create_task(service.aclose())

            async def _probe():
                return "alive"

            probe_task = asyncio.create_task(_probe())
            self.assertEqual(
                await asyncio.wait_for(probe_task, timeout=5.0), "alive"
            )
            self.assertFalse(
                shutdown_task.done(),
                "shutdown join must wait off-loop for in-flight work",
            )
            gate.set()
            await asyncio.wait_for(shutdown_task, timeout=5.0)
            self.assertEqual(service.active_stream_count(), 0)
            with self.assertRaisesRegex(RuntimeError, "shut"):
                async for _ in service.synthesize_kokoro_stream("hi"):
                    pass
            await gen.aclose()

        asyncio.run(consume())

    def test_lifespan_teardown_rejects_new_streams(self):
        service = _service(
            FakeKokoroPipeline(["a"]),
            lambda audio: ("pcm:" + str(audio)).encode(),
        )
        app = create_app(inference_service=service)

        with TestClient(app):
            self.assertTrue(service.kokoro_loaded)

        async def after():
            with self.assertRaisesRegex(RuntimeError, "shut"):
                async for _ in service.synthesize_kokoro_stream("hi"):
                    pass

        asyncio.run(after())


class TestErrorAndLoopClose(unittest.TestCase):
    def test_pipeline_error_reaches_consumer_in_order(self):
        class FailingPipeline:
            def __call__(self, text, voice="af_heart"):
                yield (None, None, "a")
                yield (None, None, "b")
                raise RuntimeError("gpu gone")

        service = _service(
            FailingPipeline(),
            lambda audio: ("pcm:" + str(audio)).encode(),
        )
        service.load_models()

        async def consume():
            chunks = []
            with self.assertRaisesRegex(RuntimeError, "gpu gone"):
                async for chunk in service.synthesize_kokoro_stream("hi"):
                    chunks.append(chunk)
            self.assertEqual(chunks, [b"pcm:a", b"pcm:b"])

        asyncio.run(consume())

    def test_producer_handles_loop_closed_without_thread_errors(self):
        errors = []
        orig_hook = threading.excepthook

        def _hook(args):
            errors.append(args)

        threading.excepthook = _hook
        gate = threading.Event()

        class GatedPipeline:
            def __call__(self, text, voice="af_heart"):
                yield (None, None, "one")
                gate.wait(timeout=5.0)
                yield (None, None, "two")

        service = _service(
            GatedPipeline(),
            lambda audio: ("pcm:" + str(audio)).encode(),
        )
        service.load_models()
        try:
            before = set(threading.enumerate())

            async def consume():
                gen = service.synthesize_kokoro_stream("hi")
                first = await gen.__anext__()
                self.assertEqual(first, b"pcm:one")
                await gen.aclose()

            asyncio.run(consume())
            producers = [t for t in threading.enumerate() if t not in before]
            gate.set()
            for thread in producers:
                thread.join(timeout=5.0)
            self.assertEqual(
                [t for t in producers if t.is_alive()],
                [],
                "producer must finish after release even when the loop is closed",
            )
        finally:
            threading.excepthook = orig_hook
        self.assertEqual(errors, [])


class TestFullBufferKeepsEveryChunk(unittest.TestCase):
    def test_stalled_success_delivers_all_buffered_chunks_in_order(self):
        script = ["a", "b", "c", "d", "e"]
        service = _service(
            FakeKokoroPipeline(script),
            lambda audio: ("pcm:" + str(audio)).encode(),
        )
        service.load_models()

        async def consume():
            gen = service.synthesize_kokoro_stream("hi")
            first = await gen.__anext__()
            await asyncio.sleep(0.3)
            rest = [chunk async for chunk in gen]
            return [first] + rest

        self.assertEqual(
            asyncio.run(consume()),
            [("pcm:" + audio).encode() for audio in script],
        )

    def test_stalled_error_delivers_all_buffered_chunks_before_failure(self):
        class FailingPipeline:
            def __call__(self, text, voice="af_heart"):
                for audio in ("a", "b", "c", "d", "e"):
                    yield (None, None, audio)
                raise RuntimeError("gpu gone")

        service = _service(
            FailingPipeline(),
            lambda audio: ("pcm:" + str(audio)).encode(),
        )
        service.load_models()

        async def consume():
            gen = service.synthesize_kokoro_stream("hi")
            first = await gen.__anext__()
            await asyncio.sleep(0.3)
            chunks = [first]
            with self.assertRaisesRegex(RuntimeError, "gpu gone"):
                async for chunk in gen:
                    chunks.append(chunk)
            return chunks

        self.assertEqual(
            asyncio.run(consume()),
            [b"pcm:a", b"pcm:b", b"pcm:c", b"pcm:d", b"pcm:e"],
        )


class TestOnePendingOffer(unittest.TestCase):
    def test_loop_stall_delivers_each_chunk_exactly_once(self):
        service = _service(
            FakeKokoroPipeline(["x", "y"]),
            lambda audio: ("pcm:" + str(audio)).encode(),
        )
        service.load_models()

        async def consume():
            gen = service.synthesize_kokoro_stream("hi")
            first = await gen.__anext__()
            time.sleep(0.3)
            rest = [chunk async for chunk in gen]
            return [first] + rest

        self.assertEqual(asyncio.run(consume()), [b"pcm:x", b"pcm:y"])


class TestCloseWhileProducerBlocked(unittest.TestCase):
    def test_consumer_close_keeps_shutdown_ownership_until_release(self):
        gate = threading.Event()
        entered = threading.Event()

        class GatedPipeline:
            def __call__(self, text, voice="af_heart"):
                yield (None, None, "one")
                entered.set()
                gate.wait(timeout=5.0)
                yield (None, None, "two")

        service = _service(
            GatedPipeline(),
            lambda audio: ("pcm:" + str(audio)).encode(),
        )
        service.load_models()

        async def consume():
            gen = service.synthesize_kokoro_stream("hi")
            self.assertEqual(await gen.__anext__(), b"pcm:one")
            entered_ok = await asyncio.to_thread(entered.wait, 5.0)
            self.assertTrue(entered_ok, "producer must block in the gate")
            await gen.aclose()
            self.assertEqual(service.active_stream_count(), 1)
            shutdown_task = asyncio.create_task(service.aclose())
            await asyncio.sleep(0.05)
            self.assertFalse(shutdown_task.done())
            gate.set()
            await asyncio.wait_for(shutdown_task, timeout=5.0)
            self.assertEqual(service.active_stream_count(), 0)

        try:
            asyncio.run(consume())
        finally:
            gate.set()


class TestRouteGeneratorClose(unittest.TestCase):
    def test_closing_response_body_closes_service_stream(self):
        from src.main import KokoroTtsRequest, kokoro_tts_stream

        finalized = []
        inners = []

        class ClosingService:
            def synthesize_kokoro_stream(self, text, voice="af_heart"):
                async def _inner():
                    try:
                        yield b"pcm:1"
                        yield b"pcm:2"
                    finally:
                        finalized.append(True)

                gen = _inner()
                inners.append(gen)
                return gen

            def kokoro_sample_rate(self):
                return 24000

        stub = SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(inference_service=ClosingService())
            )
        )

        async def consume():
            resp = await kokoro_tts_stream(KokoroTtsRequest(text="hi"), stub)
            body = resp.body_iterator
            self.assertEqual(await body.__anext__(), b"pcm:1")
            await body.aclose()
            self.assertEqual(finalized, [True])

        asyncio.run(consume())


class TestThreadStartFailure(unittest.TestCase):
    def test_start_failure_registers_no_work_and_shutdown_succeeds(self):
        service = _service(
            FakeKokoroPipeline(["a"]),
            lambda audio: ("pcm:" + str(audio)).encode(),
        )
        service.load_models()

        async def consume():
            with self.assertRaisesRegex(RuntimeError, "no threads"):
                async for _ in service.synthesize_kokoro_stream("hi"):
                    pass

        with mock.patch.object(
            threading.Thread, "start", side_effect=RuntimeError("no threads")
        ):
            asyncio.run(consume())

        self.assertEqual(service.active_stream_count(), 0)
        asyncio.run(service.aclose())


if __name__ == "__main__":
    unittest.main()
