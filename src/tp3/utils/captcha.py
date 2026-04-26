import os
from io import BytesIO
from urllib.parse import urljoin

import pytesseract
from bs4 import BeautifulSoup
from PIL import Image, ImageOps, ImageFilter
from pytesseract import TesseractNotFoundError


tesseract_cmd = os.getenv("TESSERACT_CMD")
if tesseract_cmd:
    pytesseract.pytesseract.tesseract_cmd = tesseract_cmd


class Captcha:
    def __init__(self, url, session=None):
        self.url = url
        self.image = ""
        self.value = ""
        self.session = session

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        if self.image == "":
            self.value = ""
            print("Aucune image captcha récupérée")
            return

        try:
            image = Image.open(BytesIO(self.image)).convert("RGB")
            image.save("captcha_raw.png")

            cleaned = Image.new("L", image.size, 255)

            for y in range(image.height):
                for x in range(image.width):
                    r, g, b = image.getpixel((x, y))

                    # Le texte du captcha est très clair/blanc sur fond bleu.
                    # On garde les pixels clairs et on supprime le fond.
                    if r > 150 and g > 150 and b > 150:
                        cleaned.putpixel((x, y), 0)
                    else:
                        cleaned.putpixel((x, y), 255)

            cleaned = cleaned.resize((cleaned.width * 6, cleaned.height * 6))
            cleaned = cleaned.filter(ImageFilter.MedianFilter(size=3))
            cleaned = ImageOps.expand(cleaned, border=30, fill=255)
            cleaned.save("captcha_clean.png")

            text = pytesseract.image_to_string(
                cleaned,
                config="--psm 8 --oem 3 -c tessedit_char_whitelist=0123456789",
            )

            self.value = "".join(c for c in text if c.isdigit())

            print(f"OCR brut = {repr(text)}")
            print(f"OCR captcha = {self.value}")

        except TesseractNotFoundError:
            self.value = ""
            print("ERREUR: Tesseract n'est pas installé ou pas dans le PATH")

        except Exception as error:
            self.value = ""
            print(f"ERREUR OCR: {error}")

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """
        if self.session is None:
            return

        response = self.session.get(self.url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        image = soup.find("img")
        if image is None or not image.get("src"):
            print("Balise img introuvable")
            return

        image_url = urljoin(self.url, image.get("src"))
        image_response = self.session.get(image_url, timeout=10)

        if image_response.status_code != 200:
            print(f"Erreur récupération captcha: {image_response.status_code}")
            return

        self.image = image_response.content

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value