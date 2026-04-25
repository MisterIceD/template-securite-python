import argparse
import os

from tp2.utils.config import logger
from tp2.utils.shellcode_analyzer import ShellcodeAnalyzer


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    args = parser.parse_args()

    if os.getenv("OPENAI_KEY"):
        logger.info("OpenAI key loaded successfully")
    else:
        logger.warning("OpenAI key missing")

    analyzer = ShellcodeAnalyzer(args.file)
    result = analyzer.run()

    print(result)


if __name__ == "__main__":
    main()