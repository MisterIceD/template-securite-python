from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


def main():
    logger.info("Starting TP3")

    ip = "31.220.95.27:9002"
    challenges = {
        "1": f"http://{ip}/captcha1/",
        "2": f"http://{ip}/captcha2/",
    }

    for i in challenges:
        url = challenges[i]
        session = Session(url, i)

        attempts = 0

        while not session.process_response() and attempts < 10000:
            session.prepare_request()
            session.submit_request()
            attempts += 1

        if session.get_flag():
            logger.info("Smell good !")
            logger.info(f"Flag for {url} : {session.get_flag()}")
        else:
            logger.error(f"No flag found for {url}")


if __name__ == "__main__":
    main()