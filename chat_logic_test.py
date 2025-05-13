import logging
import time
from app.chat_logic import generate_text_stream  # Adjust the import based on your project structure

# Configure logging to ensure all DEBUG messages are printed.
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def main():
    # Static test parameters.
    prompt = "Test prompt from chat_logic_test.py."
    system_prompt = "You are an assistant that answers everything."
    model_name = "Local Ollama"  # Must match your configuration exactly.
    session_history = []         # Static, empty session history.
    memory_text = ""             # Static, empty memory text.

    logger.debug("chat_logic_test.py starting: about to call generate_text_stream")
    start_time = time.time()

    # Call the generate_text_stream function from chat_logic.
    try:
        stream = generate_text_stream(
            prompt,
            system_prompt,
            model_name,
            session_history,
            memory_text
        )
        logger.debug(f"Stream object obtained: {stream}")
    except Exception as e:
        logger.exception("Exception when calling generate_text_stream:")
        return

    # Iterate over the stream and print out each chunk.
    response_text = ""
    try:
        for chunk in stream:
            logger.debug(f"Received chunk: {chunk}")
            response_text += chunk
            print(chunk, end="", flush=True)
    except Exception as e:
        logger.exception("Exception during streaming iteration:")
        print(f"\n[Error] Exception during iteration: {str(e)}")

    end_time = time.time()
    logger.debug(f"Total response length: {len(response_text)} characters")
    logger.debug(f"Iteration completed in {end_time - start_time:.2f} seconds")
    print("\n--- Test execution complete ---")

if __name__ == "__main__":
    main()