# TTS API Documentation

This document provides detailed information about the Text-to-Speech (TTS) API endpoints and their usage.

## Base URL
```
http://localhost:5000
```

## API Endpoints

### 1. Status Check
Check if the service is running and get device information.

**Endpoint:** `GET /api/status`

**Response:**
```json
{
    "status": "running",
    "device": "cuda|cpu"
}
```

### 2. Text-to-Speech (Single File)
Generate audio from text and return a complete WAV file.

**Endpoint:** `POST /api/tts`

**Request Body:**
```json
{
    "text": "Your text here",
    "voice_file": "path/to/voice.wav"  // Optional, defaults to 'voices/default.wav'
}
```

**Response:**
- Success: Returns WAV audio file
- Error: Returns JSON with error message

### 3. Text-to-Speech (Streaming)
Generate audio from text and stream WAV chunks sentence by sentence.

**Endpoint:** `POST /api/tts/stream`

**Request Body:**
```json
{
    "text": "Your text here",
    "voice_file": "path/to/voice.wav"  // Optional, defaults to 'voices/default.wav'
}
```

**Response:**
- Success: Streams WAV audio chunks
- Error: Returns JSON with error message

## Example Usage

### Python Example (Single File)
```python
import requests

url = "http://localhost:5000/api/tts"
payload = {
    "text": "Hello world! This is a test.",
    "voice_file": "voices/default.wav"
}

response = requests.post(url, json=payload)
if response.status_code == 200:
    with open("output.wav", "wb") as f:
        f.write(response.content)
    print("Audio saved to output.wav")
else:
    print("Error:", response.json())
```

### Python Example (Streaming)
```python
import requests

url = "http://localhost:5000/api/tts/stream"
payload = {
    "text": "Hello world! This is a test.",
    "voice_file": "voices/default.wav"
}

response = requests.post(url, json=payload, stream=True)
if response.status_code == 200:
    with open("output.wav", "wb") as f:
        for chunk in response.iter_content(chunk_size=None):
            if chunk:
                f.write(chunk)
    print("Audio saved to output.wav")
else:
    print("Error:", response.json())
```

## Error Handling

The API returns standard HTTP status codes:

- `200 OK`: Success
- `400 Bad Request`: Invalid request (e.g., missing text)
- `500 Internal Server Error`: Server-side error

Error responses include a JSON object with an error message:
```json
{
    "error": "Error description"
}
```

## Text Processing

The API automatically:
1. Removes extra whitespace and newlines
2. Splits text into sentences
3. Normalizes audio levels
4. Converts to 16-bit PCM WAV format

## Voice Files

- Place custom voice files in the `voices/` directory
- Supported formats: WAV (16-bit PCM recommended)
- Default voice: `voices/default.wav`

## Requirements

- Python 3.8+
- Flask
- TTS library
- NumPy
- Wave

## Troubleshooting

1. **No audio output:**
   - Check if the service is running
   - Verify text input is not empty
   - Ensure voice file exists and is accessible

2. **Poor audio quality:**
   - Use high-quality voice samples
   - Ensure text is properly formatted

3. **Long processing times:**
   - Use streaming endpoint for long texts
   - Verify GPU is being used if available
