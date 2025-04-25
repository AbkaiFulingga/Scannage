import argparse
from scapy.all import ARP, Ether, srp
from manuf import manuf
import requests


def get_vendor_from_mac(mac_address):
    # Normalize MAC address to lowercase to avoid parsing errors when checking MANUF/macvendors DB
    mac_address = mac_address.lower()

    # First, try using manuf
    parser = manuf.MacParser()
    vendor = parser.get_manuf(mac_address)

    # API in case of MANUF db failure
    if not vendor:
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_address}")
            if response.status_code == 200:
                vendor = response.text.strip()
            else:
                vendor = "Unknown"
        except requests.RequestException as e:
            vendor = "Unknown"
            print(f"[ERROR] Error contacting macvendors.com: {e}")

    return vendor


def scan_network(target_ip):
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]
    seen_macs = set()
    ip_mac_map = {}

    print("IP Address        MAC Address         Vendor               Suspicious?")
    print("-" * 65)

    for sent, received in result:
        mac = received.hwsrc
        ip = received.psrc

        # Check for vendor using manuf or fallback to macvendors.com if not found
        vendor = get_vendor_from_mac(mac)

        suspicious = False

        # Case 1: Unknown vendor
        if vendor == "Unknown":
            suspicious = True

        # Case 2: Locally administered MAC address
        first_octet = int(mac.split(":")[0], 16)
        if first_octet & 0b10:  # Check if the second bit is set (locally administered)
            suspicious = True

        # Case 3: Duplicate MAC with different IP
        if mac in seen_macs and ip_mac_map.get(mac) != ip:
            suspicious = True

        seen_macs.add(mac)
        ip_mac_map[mac] = ip

        print(f"{ip:16} {mac:18} {vendor:20} {'YES' if suspicious else 'NO'}")


def main():
    parser = argparse.ArgumentParser(description="Network scanner with spoof detection")
    parser.add_argument("target", help="Target IP range (e.g. 192.168.1.1/24)")
    args = parser.parse_args()

    scan_network(args.target)


if __name__ == "__main__":
    main()
