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

    def __init__(self, url, challenge="1"):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url = url
        self.challenge = challenge
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.http = requests.Session()
        self.response = None
        self.next_captcha = ""

        if challenge == "1":
            self.current_flag = 1000
            self.max_flag = 2000
        elif challenge == "2":
            self.current_flag = 2000
            self.max_flag = 3000
        elif challenge == "3":
            self.current_flag = 3000
            self.max_flag = 4000
        else:
            self.current_flag = 1000
            self.max_flag = 9999

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        if self.challenge == "2" and self.next_captcha != "":
            self.captcha_value = self.next_captcha
            self.next_captcha = ""
        else:
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

        print(f"Try challenge={self.challenge} flag={self.flag_value} captcha={self.captcha_value}")

        self.response = self.http.post(self.url, data=data, timeout=10)

    def process_response(self):
        """
        Processes the response.
        """
        if self.response is None:
            return False

        text = self.response.text
        lowered = text.lower()

        flag = self._extract_flag(text)
        if flag != "":
            self.valid_flag = flag
            print(f"Flag trouve : {self.valid_flag}")
            return True

        if "invalid captcha" in lowered or "incorrect captcha" in lowered:
            print(f"Captcha incorrect pour flag={self.flag_value}")
            return False

        if "incorrect flag" in lowered:
            print(f"Flag incorrect : {self.flag_value}")
            self.current_flag += 1
            return False

        if self.challenge == "2":
            next_code = self._extract_next_captcha_from_hex(text)

            if next_code != "":
                print(f"Captcha suivant depuis hex = {next_code}")
                print(f"Flag incorrect : {self.flag_value}")
                self.next_captcha = next_code
                self.current_flag += 1
                return False

        if self.challenge == "3":
            print(f"Flag incorrect : {self.flag_value}")
            self.current_flag += 1
            return False

        if self.current_flag > self.max_flag:
            print("Aucun flag trouve")
            return True

        print("Réponse inconnue du serveur :")
        print(self._extract_text_preview(text))
        return False

    def _extract_flag(self, text):
        normal_flag = re.search(r"FLAG-\d+\{[^}]+\}", text)
        if normal_flag:
            return normal_flag.group(0)

        spaced_flag = re.search(
            r"F\s*L\s*A\s*G\s*-\s*(\d+)\s*\{\s*([^}]+?)\s*\}",
            text,
            re.IGNORECASE,
        )

        if spaced_flag:
            number = spaced_flag.group(1)
            value = spaced_flag.group(2).replace(" ", "")
            return f"FLAG-{number}{{{value}}}"

        return ""

    def _extract_next_captcha_from_hex(self, text):
        matches = re.findall(r"\b[0-9a-fA-F]{6}\b", text)

        for value in matches:
            if any(c in "abcdefABCDEF" for c in value):
                return value

        return ""

    def _extract_text_preview(self, text):
        clean = re.sub(r"<[^>]+>", " ", text)
        clean = re.sub(r"\s+", " ", clean)
        return clean[:500]

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag