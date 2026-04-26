import argparse

from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


def main():
    logger.info("Starting TP3")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--challenge",
        default="1",
        choices=["1", "2", "3", "4", "5", "all"],
    )
    args = parser.parse_args()

    ip = "31.220.95.27:9002"
    challenges = {
        "1": f"http://{ip}/captcha1/",
        "2": f"http://{ip}/captcha2/",
        "3": f"http://{ip}/captcha3/",
        "4": f"http://{ip}/captcha4/",
        "5": f"http://{ip}/captcha5/",
    }

    if args.challenge == "all":
        selected_challenges = challenges
    else:
        selected_challenges = {args.challenge: challenges[args.challenge]}

    for i, url in selected_challenges.items():
        session = Session(url, i)
        attempts = 0

        while attempts < 10000:
            session.prepare_request()
            session.submit_request()

            if session.process_response():
                break

            attempts += 1

        if session.get_flag():
            logger.info("Smell good !")
            logger.info(f"Flag for {url} : {session.get_flag()}")
            return
        else:
            logger.error(f"No flag found for {url}")


if __name__ == "__main__":
    main()