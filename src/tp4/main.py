import base64
import string

from pwn import remote


MORSE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e",
    "..-.": "f", "--.": "g", "....": "h", "..": "i", ".---": "j",
    "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o",
    ".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t",
    "..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y",
    "--..": "z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def decode_morse(message):
    resultat = ""

    morceaux = message.split(" ")

    for morceau in morceaux:
        if morceau in MORSE:
            resultat += MORSE[morceau]

    return resultat


def detect_and_decode(message):
    message = message.strip()

    # morse
    is_morse = True
    for c in message:
        if c not in ".- /":
            is_morse = False

    if is_morse:
        return decode_morse(message)

    # hex
    is_hex = True
    for c in message:
        if c not in string.hexdigits:
            is_hex = False

    if is_hex and len(message) % 2 == 0:
        return bytes.fromhex(message).decode(errors="ignore")

    # si ce n'est pas du morse ou du hex, je tente base64
    return base64.b64decode(message).decode(errors="ignore")


def main():
    host = "31.220.95.27"
    port = 13337

    io = remote(host, port)

    while True:
        try:
            line = io.recvline(timeout=5)
        except EOFError:
            break

        if not line:
            break

        line = line.decode(errors="ignore").strip()
        print(line)

        if "flag" in line.lower():
            break

        if "A décoder:" in line:
            message = line.split("A décoder:")[1].strip()

            try:
                reponse = detect_and_decode(message)
                print("reponse =", reponse)
                io.sendline(reponse.encode())
            except Exception as e:
                print("erreur :", e)
                break

    io.close()


if __name__ == "__main__":
    main()