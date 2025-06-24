import logging
import json
from openai import OpenAI
from app.llm.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)

class OpenaiProvider(BaseLLMProvider):
    """
    Provider for OpenAI or OpenAI-compatible endpoints.
    """

    def __init__(self, config):
        # Validate required fields
        required_keys = ['api_key']
        missing = [key for key in required_keys if key not in config]
        if missing:
            raise ValueError(f"Missing required keys in provider config: {missing}")

        # Store masked API key for logging purposes
        self.masked_api_key = config['api_key'][:8] + "..." if config['api_key'] else ""
        self.base_url = config.get('base_url', 'https://api.openai.com/v1')
        self.timeout = config.get('request_timeout', 300.0)
        
        # Log configuration with masked API key
        logger.debug(
            "OpenAI Provider Configuration:\n"
            f"Base URL: {self.base_url}\n"
            f"API Key: {self.masked_api_key}\n"
            f"Timeout: {self.timeout}s"
        )

        # Initialize the client with the config
        self.client = OpenAI(
            api_key=config['api_key'],
            base_url=self.base_url,
            timeout=self.timeout
        )
        self.model = config.get('model_name', config.get('model', 'gpt-4'))

    def generate_text_stream(self, prompt, system_prompt, session_history, memory_text):
        # Log request details
        logger.debug(
            f"OpenAI request initiated:\n"
            f"Model: {self.model}\n"
            f"Base URL: {self.base_url}\n"
            f"System prompt length: {len(system_prompt)} chars\n"
            f"User prompt: {prompt[:50]}...\n"
            f"Memory text length: {len(memory_text)} chars\n"
            f"Session history items: {len(session_history)}"
        )
        
        messages = [{"role": "system", "content": system_prompt}]

        if memory_text.strip():
            messages.append({"role": "system", "content": f"Memory:\n{memory_text[:2000]}"})

        for user_in, assistant_res in session_history:
            messages.append({"role": "user", "content": user_in})
            if assistant_res:  # Allow empty responses in history
                messages.append({"role": "assistant", "content": assistant_res})

        messages.append({"role": "user", "content": prompt})

        # Log the messages being sent (truncate long content)
        truncated_messages = []
        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            if len(content) > 200:
                truncated_messages.append({"role": role, "content": content[:200] + "..."})
            else:
                truncated_messages.append(msg)
        logger.debug(f"Sending messages to OpenAI API: {json.dumps(truncated_messages, indent=2)}")

        try:
            logger.debug(f"Sending request to OpenAI API, message count: {len(messages)}")
            
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7,
                stream=True
            )
            
            response_text = ""
            for chunk in stream:
                content = chunk.choices[0].delta.content
                if content is not None:
                    response_text += content
                    yield content
            
            logger.debug(f"OpenAI request completed, total response length: {len(response_text)} chars")

        except Exception as e:
            logger.error(
                f"OpenAI API error: {str(e)}\n"
                f"Model: {self.model}\n"
                f"Base URL: {self.base_url}"
            )
            yield f"\n[Error]: {str(e)}"
