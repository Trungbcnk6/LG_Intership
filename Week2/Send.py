# control_client.py
import socket
import json
import random
import os
import hmac
import hashlib
from scapy.all import *

# =======================================================
# === Cấu hình Client ===
# =======================================================
PI_HOST_IPv6 = "fd53:aaaa:bbb:5::14"
PI_HOST_MAC = "D8:3A:DD:A4:BF:A8"
PI_CONTROL_PORT = 13344

MY_IFACE = "enp1s0"
# ĐỊA CHỈ HỢP LỆ (WHITELISTED)
MY_MAC = "2c:58:b9:8b:54:69"
MY_IPv6 = "fd53:aaaa:bbb:5::10"

# ĐỊA CHỈ GIẢ MẠO (SPOOFED) DÙNG ĐỂ KIỂM TRA TƯỜNG LỬA
SPOOFED_MAC = "DE:AD:BE:EF:CA:FE"
SPOOFED_IPv6 = "fd53:aaaa:bbb:5::bad1"

# KHÓA BÍ MẬT - Phải giống hệt với khóa ở server
SHARED_SECRET_KEY = b"MySuperSecretKeyForLGCars_v2"


# =======================================================
# === Hàm Gửi Lệnh (Hỗ trợ Giả mạo Nguồn) ===
# =======================================================
def send_structured_payload(payload_json, src_mac=MY_MAC, src_ipv6=MY_IPv6):
    """
    Thực hiện kết nối TCP, gửi payload JSON đã được ký.
    Không chờ phản hồi từ server (Fire-and-Forget).
    """
    print(f"--- Sending command from SRC_MAC: {src_mac}, SRC_IPv6: {src_ipv6} ---")
    # 1. Tạo chữ ký và đóng gói (giữ nguyên)
    payload_str = json.dumps(payload_json, sort_keys=True).encode('utf-8')
    signature = hmac.new(SHARED_SECRET_KEY, payload_str, hashlib.sha256).hexdigest()
    final_package = {"payload": payload_json, "signature": signature}
    final_package_str = json.dumps(final_package)

    # 2. Thực hiện kết nối và gửi đi
    src_port = random.randint(30000, 40000)
    # Quy tắc iptables vẫn cần thiết để hoàn tất handshake
    iptables_rule = f"ip6tables -A OUTPUT -p tcp --tcp-flags RST RST --sport {src_port} -j DROP"
    iptables_rule_delete = f"ip6tables -D OUTPUT -p tcp --tcp-flags RST RST --sport {src_port} -j DROP"
    
    try:
        os.system(iptables_rule)
        
        eth = Ether(src=src_mac, dst=PI_HOST_MAC)
        ip = IPv6(src=src_ipv6, dst=PI_HOST_IPv6)
        
        # Handshake (vẫn cần thiết để server chấp nhận kết nối)
        syn = eth / ip / TCP(sport=src_port, dport=PI_CONTROL_PORT, flags='S', seq=RandInt())
        ans, _ = srp(syn, iface=MY_IFACE, timeout=2, verbose=0)
        if not ans:
            print("\n[ERROR] Handshake failed: No SYN-ACK received. (Check firewall or server status)")
            return # Thoát sớm
        
        syn_ack = ans[0][1]
        ack = eth / ip / TCP(sport=src_port, dport=PI_CONTROL_PORT, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)
        sendp(ack, iface=MY_IFACE, verbose=0)
        
        # Gửi dữ liệu JSON
        data_pkt = eth / ip / TCP(sport=src_port, dport=PI_CONTROL_PORT, flags='PA', seq=ack.seq, ack=ack.ack) / final_package_str
        # Chúng ta dùng sendp thay vì srp vì không cần chờ phản hồi
        sendp(data_pkt, iface=MY_IFACE, verbose=0)
        
        print("\n--- COMMAND STATUS ---")
        print("Command sent successfully to the server.")
        print("Check the server console for execution results.")
        print("----------------------")

    except Exception as e:
        print(f"\nAN ERROR OCCURRED: {e}")
    finally:
        os.system(iptables_rule_delete)


def main_menu():
    while True:
        print("\n===== Remote Pi Configurator  =====")
        print("--- Normal Commands (from whitelisted source) ---")
        print("1. Get current network config (eth0)")
        print("2. Set new IPv6 address for eth0")
        print("3. Set new MAC address for eth0")
        print("4. Set VLAN ID for eth0 (0 to remove VLAN)")
        print("5. Set new IPv4 address for eth0")
        print("\n--- Firewall Source Filtering Tests (should be DROPPED) ---")
        print("6. Send 'get_config' from SPOOFED MAC address")
        print("7. Send 'get_config' from SPOOFED IPv6 address")
        print("8. Send 'get_config' from BOTH SPOOFED MAC and IPv6")
        print("---------------------------------------------------------")
        print("0. Exit")
        choice = input("Enter your choice: ")
        
        payload = None
        # Biến cờ để xác định xem có cần giả mạo không
        spoof_mac = False
        spoof_ipv6 = False
        
        if choice == '1':
            payload = {"command": "get_config", "params": {"iface": "eth0"}}
        elif choice == '2':
            ip = input("  Enter new IPv6 address: ")
            payload = {"command": "set_ipv6", "params": {"ip": ip}}
        elif choice == '3':
            mac = input("  Enter new MAC address: ")
            payload = {"command": "set_mac", "params": {"mac": mac}}
        elif choice == '4':
            try:
                vlan_id = int(input("  Enter new VLAN ID (e.g., 5, or 0 to remove): "))
                payload = {"command": "set_vlan", "params": {"vlan_id": vlan_id}}
            except ValueError:
                print("Invalid VLAN ID. Please enter a number.")
                continue
        elif choice == '5':
            try:
                ip = input("  Enter new IPv4 address: ")
                prefix = int(input("  Enter prefix length (e.g., 24 for 255.255.255.0): "))
                payload = {"command": "set_ipv4", "params": {"ip": ip, "prefix": prefix}}
            except ValueError:
                print("Invalid Prefix. Please enter a number.")
                continue
        elif choice == '6':
            print("\n>>> CONFIGURING TEST: Send from a spoofed MAC. This should fail.")
            payload = {"command": "get_config", "params": {"iface": "eth0"}}
            spoof_mac = True
        elif choice == '7':
            print("\n>>> CONFIGURING TEST: Send from a spoofed IPv6. This should fail.")
            payload = {"command": "get_config", "params": {"iface": "eth0"}}
            spoof_ipv6 = True
        elif choice == '8':
            print("\n>>> CONFIGURING TEST: Send from a spoofed MAC & IPv6. This should fail.")
            payload = {"command": "get_config", "params": {"iface": "eth0"}}
            spoof_mac = True
            spoof_ipv6 = True
        elif choice == '0':
            break
        else:
            print("Invalid choice.")
            continue
            
        # Nếu payload đã được tạo, tiến hành gửi đi
        if payload:
            # Xác định địa chỉ nguồn dựa trên các cờ đã đặt
            source_mac = SPOOFED_MAC if spoof_mac else MY_MAC
            source_ipv6 = SPOOFED_IPv6 if spoof_ipv6 else MY_IPv6
            
            # Gọi hàm gửi với các địa chỉ nguồn thích hợp
            send_structured_payload(payload, src_mac=source_mac, src_ipv6=source_ipv6)

if __name__ == "__main__":
    main_menu()