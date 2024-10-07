import scapy.all as scapy

# Function to scan the network
def scan(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device_info)
    
    return devices

# Main program
if __name__ == "__main__":
    ip_range = input("Enter the IP range (e.g., 192.168.1.1/24): ")
    print("Scanning the network... Please wait.")
    devices = scan(ip_range)
    
    print("Devices found:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
