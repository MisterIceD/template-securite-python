import re
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from tp2.utils.config import logger


class ShellcodeAnalyzer:
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.shellcode = self.load_shellcode()

    def load_shellcode(self) -> bytes:
        data = Path(self.filename).read_text(encoding="utf-8")

        values = re.findall(r"\\x([0-9a-fA-F]{2})", data)
        if not values:
            raise ValueError("Aucun shellcode trouve dans le fichier")

        return bytes(int(x, 16) for x in values)

    def get_shellcode_strings(self) -> str:
        result = ""
        current = ""

        for b in self.shellcode:
            char = chr(b)

            if 32 <= b <= 126:
                current += char
            else:
                if len(current) >= 4:
                    result += current + "\n"
                current = ""

        if len(current) >= 4:
            result += current + "\n"

        if result == "":
            return "Aucune chaine lisible trouvee"

        return result

    def get_capstone_analysis(self) -> str:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        result = ""

        for instr in md.disasm(self.shellcode, 0x1000):
            result += f"0x{instr.address:x}: {instr.mnemonic} {instr.op_str}\n"

        if result == "":
            return "Aucune instruction desassemblee"

        return result

    def get_pylibemu_analysis(self) -> str:
        try:
            import pylibemu
        except ImportError:
            return "pylibemu non installe sur cette machine"

        emulator = pylibemu.Emulator()
        offset = emulator.shellcode_getpc_test(self.shellcode)

        if offset < 0:
            return "Aucun pattern GetPC detecte"

        emulator.prepare(self.shellcode, offset)
        emulator.test()

        return str(emulator.emu_profile_output)

    def get_llm_analysis(self) -> str:
        strings = self.get_shellcode_strings()

        text = "Analyse manuelle :\n"
        text += "Le shellcode contient les chaines suivantes :\n"
        text += strings + "\n"
        text += "Il faut verifier les appels systeme/API et les instructions importantes "
        text += "dans la sortie Capstone pour comprendre son comportement."

        return text

    def run(self) -> str:
        logger.info(f"Testing shellcode of size {len(self.shellcode)}B")

        output = ""
        output += "===== STRINGS =====\n"
        output += self.get_shellcode_strings()
        output += "\n===== CAPSTONE =====\n"
        output += self.get_capstone_analysis()
        output += "\n===== PYLIBEMU =====\n"
        output += self.get_pylibemu_analysis()
        output += "\n===== ANALYSE =====\n"
        output += self.get_llm_analysis()

        logger.info("Shellcode analysed !")

        return output