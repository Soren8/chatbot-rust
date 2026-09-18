"""CPU characterization of explicit voice-service settings (MOD-015).

Given raw YAML/env inputs, when settings are resolved at startup, then the
device/provider/STT values must match the historical import-time behavior
with no ``${VAR}`` substitution (unlike Rust). Requires ``yaml`` in the
supported suite; a missing ``yaml`` import fails instead of skipping.
"""

import os
import tempfile
import unittest

import yaml  # noqa: F401  (required; fail fast when absent)

from src.settings import (
    DEFAULT_STT_MODEL_ID,
    resolve_device,
    resolve_settings,
    read_tts_provider,
)


def _missing_path():
    return os.path.join(tempfile.gettempdir(), "chatbot-voice-missing-config.yml")


class TestDeviceResolution(unittest.TestCase):
    def test_cpu_without_cuda_resolves_to_cpu(self):
        device = resolve_device(env={}, cuda_available=lambda: False)

        self.assertEqual(device, "cpu")

    def test_cuda_without_visible_devices_resolves_to_first_gpu(self):
        device = resolve_device(env={}, cuda_available=lambda: True)

        self.assertEqual(device, "cuda:0")

    def test_cuda_with_visible_devices_uses_value_verbatim(self):
        device = resolve_device(
            env={"CUDA_VISIBLE_DEVICES": "2"}, cuda_available=lambda: True
        )

        self.assertEqual(device, "cuda:2")


class TestStartupDefaults(unittest.TestCase):
    def test_missing_config_and_empty_env_resolves_documented_defaults(self):
        settings = resolve_settings(
            env={}, config_path=_missing_path(), cuda_available=lambda: False
        )

        self.assertEqual(settings.tts_provider, "kokoro")
        self.assertEqual(settings.stt_model_id, DEFAULT_STT_MODEL_ID)
        self.assertEqual(settings.device, "cpu")
        self.assertEqual(settings.kokoro_sample_rate, 24000)
        self.assertEqual(settings.parakeet_sample_rate, 16000)

    def test_stt_model_id_env_override_is_used_verbatim(self):
        settings = resolve_settings(
            env={"STT_MODEL_ID": "custom/stt-model"},
            config_path=_missing_path(),
            cuda_available=lambda: False,
        )

        self.assertEqual(settings.stt_model_id, "custom/stt-model")

    def test_missing_config_reads_fallback_provider(self):
        self.assertEqual(read_tts_provider(_missing_path()), "kokoro")


class TestRawYamlInterpretation(unittest.TestCase):
    def _write_config(self, text):
        tmp = tempfile.NamedTemporaryFile(
            suffix=".yml", delete=False, mode="w", encoding="utf-8"
        )
        try:
            tmp.write(text)
            tmp.flush()
            return tmp.name
        finally:
            tmp.close()

    def test_tts_provider_is_read_raw_and_lowercased(self):
        path = self._write_config('tts_provider: "Fish"\n')
        try:
            settings = resolve_settings(
                env={}, config_path=path, cuda_available=lambda: False
            )

            self.assertEqual(settings.tts_provider, "fish")
        finally:
            os.unlink(path)

    def test_tts_provider_keeps_substitution_syntax_verbatim(self):
        # Rust expands ${VAR}/vars: references; Python keeps them raw.
        path = self._write_config('tts_provider: "${TTS_PROVIDER}"\n')
        try:
            provider = read_tts_provider(path)

            self.assertEqual(provider, "${tts_provider}")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
