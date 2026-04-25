import os

from tp2.utils.config import logger

if __name__ == "__main__":
    if os.getenv("OPENAI_KEY"):
        logger.info("OpenAI key loaded successfully")
    else:
        logger.error("OpenAI key missing")