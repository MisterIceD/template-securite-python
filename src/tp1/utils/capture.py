from collections import Counter
from scapy.sendrecv import sniff
from scapy.layers.l2 import ARP
from scapy.layers.inet import TCP, IP
from scapy.packet import Raw
from tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from typing import Any


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []
        self.protocol_counter = Counter()
        self.suspicious_events = []

    def capture_traffic(self, packet_count: int = 50) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")

        self.packets = sniff(iface=interface, count=packet_count, store=True)

        for pkt in self.packets:
            proto = self._identify_protocol(pkt)
            if proto:
                self.protocol_counter[proto] += 1

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        sorted_protocols = sorted(
            self.protocol_counter.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return ", ".join([f"{proto}({count})" for proto, count in sorted_protocols])

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        return ", ".join(
            [f"{proto}: {count}" for proto, count in self.protocol_counter.items()]
        )

    def analyse(self, protocols: str = "") -> None:
        """
        Analyse captured data for suspicious patterns
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()

        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        for pkt in self.packets:
            self._detect_arp_spoof(pkt)
            self._detect_sql_injection(pkt)

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        """
        return self.summary

    # =========================
    # Private helpers
    # =========================

    def _identify_protocol(self, pkt: Any) -> str:
        if pkt.haslayer(ARP):
            return "ARP"
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(IP):
            return "IP"
        return "OTHER"

    def _detect_arp_spoof(self, pkt: Any) -> None:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP Reply
            attacker_ip = pkt[ARP].psrc
            attacker_mac = pkt[ARP].hwsrc

            message = (
                f"[ALERTE] Possible ARP Spoofing from "
                f"IP={attacker_ip}, MAC={attacker_mac}"
            )
            self.suspicious_events.append(message)
            logger.warning(message)

    def _detect_sql_injection(self, pkt: Any) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        payload = pkt[Raw].load.decode(errors="ignore").lower()

        sql_patterns = ["' or 1=1", "union select", "select * from"]
        if any(p in payload for p in sql_patterns):
            src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
            message = f"[ALERTE] Possible SQL Injection from IP={src_ip}"
            self.suspicious_events.append(message)
            logger.warning(message)

    def _gen_summary(self) -> str:
        if not self.packets:
            return ""

        summary = "===== PETITE SUMMARY =====\n"
        summary += f"Interface: {self.interface}\n"
        summary += f"Total packets: {len(self.packets)}\n"
        summary += f"Protocols: {self.get_all_protocols()}\n"
        summary += "\n"

        if self.suspicious_events:
            summary += "Suspicious activity detected.\n"
        else:
            summary += "No suspicious activity detected.\n"

        return summary