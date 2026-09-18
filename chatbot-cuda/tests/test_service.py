"""CPU characterization of the owned InferenceService (MOD-015).

Given an explicit VoiceSettings plus injected stdlib fakes, when the service
loads/synthesizes/transcribes, then model choice, readiness, concatenation,
streaming order, failure propagation, and instance isolation must match the
historical globals behavior. No torch/numpy/nemo/kokoro/GPU imports.
"""

import asyncio
import unittest

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
        return self.result


class FakeHypothesis:
    def __init__(self, text):
        self.text = text


def _service(provider="kokoro", kokoro_script=("s1", "s2"), stt_result="hello"):
    pipeline = FakeKokoroPipeline(list(kokoro_script))
    model = FakeSttModel(stt_result)

    service = InferenceService(
        _settings(provider),
        kokoro_factory=lambda device: pipeline,
        stt_factory=lambda model_id: model,
        pcm_converter=lambda audio: ("pcm:" + str(audio)).encode(),
    )
    return service, pipeline, model


class TestModelChoice(unittest.TestCase):
    def test_kokoro_provider_loads_both_models(self):
        service, _, _ = _service(provider="kokoro")

        service.load_models()

        self.assertTrue(service.kokoro_loaded)
        self.assertTrue(service.stt_loaded)

    def test_non_kokoro_provider_skips_kokoro_but_loads_stt(self):
        service, pipeline, _ = _service(provider="fish")

        service.load_models()

        self.assertFalse(service.kokoro_loaded)
        self.assertTrue(service.stt_loaded)
        self.assertEqual(pipeline.calls, [])


class TestStartupFailure(unittest.TestCase):
    def test_kokoro_factory_failure_propagates_and_stays_unloaded(self):
        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: (_ for _ in ()).throw(RuntimeError("boom")),
            stt_factory=lambda model_id: FakeSttModel("hi"),
            pcm_converter=lambda audio: b"x",
        )

        with self.assertRaisesRegex(RuntimeError, "boom"):
            service.load_models()

        self.assertFalse(service.kokoro_loaded)
        self.assertFalse(service.stt_loaded)


class TestReadiness(unittest.TestCase):
    def test_new_service_reports_not_ready_before_load(self):
        service, _, _ = _service()

        readiness = service.readiness()

        self.assertFalse(readiness["kokoro_loaded"])
        self.assertFalse(readiness["stt_loaded"])

    def test_readiness_reflects_owned_instance_after_load(self):
        service, _, _ = _service()

        service.load_models()
        readiness = service.readiness()

        self.assertTrue(readiness["kokoro_loaded"])
        self.assertTrue(readiness["stt_loaded"])

    def test_independent_services_do_not_share_loaded_state(self):
        first, _, _ = _service()
        second, _, _ = _service()

        first.load_models()

        self.assertTrue(first.kokoro_loaded)
        self.assertFalse(second.kokoro_loaded)
        self.assertFalse(second.stt_loaded)


class TestSynthesisGuards(unittest.TestCase):
    def test_synthesize_without_load_raises(self):
        service, _, _ = _service()

        with self.assertRaisesRegex(RuntimeError, "Kokoro TTS not loaded"):
            service.synthesize_kokoro("hi")

    def test_transcribe_without_load_raises(self):
        service, _, _ = _service()

        with self.assertRaisesRegex(RuntimeError, "STT model not loaded"):
            service.transcribe("/tmp/audio.wav")

    def test_stream_without_load_raises(self):
        service, _, _ = _service()

        async def consume():
            async for _ in service.synthesize_kokoro_stream("hi"):
                pass

        with self.assertRaisesRegex(RuntimeError, "Kokoro TTS not loaded"):
            asyncio.run(consume())


class TestSynthesisBehavior(unittest.TestCase):
    def test_synthesize_concatenates_sentence_chunks_with_rate(self):
        service, _, _ = _service(kokoro_script=("a", "b"))

        service.load_models()

        pcm, rate = service.synthesize_kokoro("hello", voice="af_heart")

        self.assertEqual(pcm, b"pcm:apcm:b")
        self.assertEqual(rate, 24000)

    def test_stream_yields_sentence_chunks_in_order(self):
        service, _, _ = _service(kokoro_script=("one", "two", "three"))
        service.load_models()

        async def consume():
            return [
                chunk
                async for chunk in service.synthesize_kokoro_stream("hi")
            ]

        chunks = asyncio.run(consume())

        self.assertEqual(chunks, [b"pcm:one", b"pcm:two", b"pcm:three"])

    def test_stream_forwards_pipeline_failure_to_consumer(self):
        pipeline = FakeKokoroPipeline([], fail=RuntimeError("gpu gone"))
        service = InferenceService(
            _settings("kokoro"),
            kokoro_factory=lambda device: pipeline,
            stt_factory=lambda model_id: FakeSttModel("hi"),
            pcm_converter=lambda audio: b"x",
        )
        service.load_stt()
        # Mark kokoro loaded via a successful empty load, then fail on stream.
        service._kokoro_pipeline = pipeline
        service._kokoro_loaded = True

        async def consume():
            async for _ in service.synthesize_kokoro_stream("hi"):
                pass

        with self.assertRaisesRegex(RuntimeError, "gpu gone"):
            asyncio.run(consume())

    def test_kokoro_sample_rate_matches_settings(self):
        service, _, _ = _service()

        self.assertEqual(service.kokoro_sample_rate(), 24000)


class TestTranscriptionMapping(unittest.TestCase):
    def _loaded_service_with(self, result):
        service, _, model = _service(stt_result=result)
        service.load_models()
        return service, model

    def test_string_hypothesis_is_stripped(self):
        service, model = self._loaded_service_with(["  hello world  "])

        text = service.transcribe("/tmp/fake.wav")

        self.assertEqual(text, "hello world")
        self.assertEqual(model.paths, [["/tmp/fake.wav"]])

    def test_hypothesis_object_text_is_stripped(self):
        service, _ = self._loaded_service_with([FakeHypothesis("  hi there  ")])

        self.assertEqual(service.transcribe("/tmp/f.wav"), "hi there")

    def test_empty_results_return_empty_string(self):
        service, _ = self._loaded_service_with([])

        self.assertEqual(service.transcribe("/tmp/f.wav"), "")


if __name__ == "__main__":
    unittest.main()
