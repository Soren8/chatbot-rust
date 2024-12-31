import json
import requests

def generate_text_stream(prompt, system_prompt, model_name, session_history, memory_text):
    # Truncate memory if too long
    max_memory_length = 2000
    memory_text = memory_text[:max_memory_length]

    if not session_history:
        history_text = f"### System: {system_prompt}\n\n"
    else:
        history_text = ""

    if memory_text.strip():
        history_text += f"### Memory:\n{memory_text}\n\n"

    for user_input, assistant_response in session_history:
        history_text += f"### User:\n{user_input}\n\n### Assistant:\n{assistant_response}\n\n"

    # Append the latest user prompt
    history_text += f"### User:\n{prompt}\n\n### Assistant:\n"

    data = {
        "model": model_name,
        "prompt": history_text,
        "system": system_prompt,
        "stream": True,
    }

    url = "http://localhost:11434/api/generate"
    with requests.post(url, json=data, stream=True) as response:
        if response.status_code == 200:
            for line in response.iter_lines():
                if line:
                    json_response = json.loads(line)
                    if 'response' in json_response:
                        yield json_response['response']
        else:
            yield f"\n[Error] Error: {response.status_code}, {response.text}"
