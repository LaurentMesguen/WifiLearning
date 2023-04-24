from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt


def wifiEnumeration(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode()

        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")

        if "WPA/PSK" in crypto or "WPA2/PSK" in crypto:
            print(f"SSID: {ssid} | BSSID: {bssid} | Channel: {channel} | Crypto: {crypto}")


if __name__ == '__main__':
    sniff(prn=wifiEnumeration, iface="en6", timeout=5)

