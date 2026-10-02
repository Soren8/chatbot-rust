import os
import unittest
from unittest import mock

from src.audio_utils import webm_to_wav_bytes


class WebmToWavBytesTests(unittest.TestCase):
    def test_success_converts_at_target_sample_rate_and_removes_temp_files(self):
        audio = b"webm input bytes"
        wav = b"wav output bytes"
        captured_paths = []

        def fake_run(argv, capture_output):
            self.assertEqual(argv[0], "ffmpeg")
            self.assertEqual(argv[1], "-y")
            input_path = argv[argv.index("-i") + 1]
            output_path = argv[-1]
            captured_paths.extend((input_path, output_path))
            with open(input_path, "rb") as input_file:
                self.assertEqual(input_file.read(), audio)
            self.assertEqual(argv[argv.index("-ar") + 1], "22050")
            self.assertEqual(capture_output, True)
            with open(output_path, "wb") as output_file:
                output_file.write(wav)
            return mock.Mock(returncode=0)

        with mock.patch("subprocess.run", side_effect=fake_run):
            result = webm_to_wav_bytes(audio, target_sr=22050)

        self.assertEqual(result, wav)
        self.assertEqual(len(captured_paths), 2)
        self.assertTrue(all(not os.path.exists(path) for path in captured_paths))

    def test_nonzero_exit_truncates_stderr_and_removes_temp_files(self):
        captured_paths = []
        stderr = b"x" * 700

        def fake_run(argv, capture_output):
            captured_paths.extend((argv[argv.index("-i") + 1], argv[-1]))
            return mock.Mock(returncode=1, stderr=stderr)

        with mock.patch("subprocess.run", side_effect=fake_run):
            with self.assertRaises(RuntimeError) as raised:
                webm_to_wav_bytes(b"invalid audio")

        message = str(raised.exception)
        self.assertTrue(message.startswith("ffmpeg exited 1:"))
        self.assertTrue(message.endswith(stderr[-500:].decode()))
        self.assertEqual(message, "ffmpeg exited 1: " + stderr[-500:].decode())
        self.assertTrue(all(not os.path.exists(path) for path in captured_paths))

    def test_run_exception_propagates_and_removes_input_temp_file(self):
        captured_paths = []

        def fake_run(argv, capture_output):
            captured_paths.append(argv[argv.index("-i") + 1])
            raise FileNotFoundError("ffmpeg not found")

        with mock.patch("subprocess.run", side_effect=fake_run):
            with self.assertRaisesRegex(FileNotFoundError, "ffmpeg not found"):
                webm_to_wav_bytes(b"input")

        self.assertEqual(len(captured_paths), 1)
        self.assertFalse(os.path.exists(captured_paths[0]))


if __name__ == "__main__":
    unittest.main()
