# receive_10.py (Fixed Syntax & Improved)

import socket
import json
import subprocess
import shlex
import hmac
import hashlib
import sys # Thêm import sys để thoát chương trình

# =======================================================
# === Cấu hình Server ===
# =======================================================
LISTEN_IPv6 = "fd53:aaaa:bbb:5::14"
LISTEN_PORT = 13344
BUFFER_SIZE = 4096
SHARED_SECRET_KEY = b"MySuperSecretKeyForLGCars_v2" 

# =======================================================
# === Các Hàm Thực Thi Lệnh (Action Handlers) ===
# =======================================================

def run_shell_command(command_str):
    """Hàm phụ trợ để chạy lệnh shell an toàn và trả về kết quả."""
    print(f"    - Executing: '{command_str}'")
    
    # Mặc định, không dùng shell
    use_shell = False
    
    # Kiểm tra xem chuỗi lệnh có chứa các ký tự cần shell để diễn giải không
    if "shutdown" in command_str or ">" in command_str or "|" in command_str:
        use_shell = True

    try:
        # Chỉ sử dụng shell=True khi thực sự cần thiết
        if use_shell:
            print("    (Running with shell=True)")
            proc = subprocess.run(command_str, shell=True, capture_output=True, text=True, timeout=15)
        else:
            proc = subprocess.run(shlex.split(command_str), capture_output=True, text=True, timeout=15)

        output = proc.stdout + proc.stderr
        
        # Chỉ in output nếu có nội dung
        if output.strip():
            print("    - Command Output:")
            print("    -------------------------------------")
            for line in output.strip().split('\n'):
                print(f"      {line}")
            print("    -------------------------------------")

        return {"status": "success", "output": output.strip()}
    except Exception as e:
        print(f"    - Command Error: {e}")
        return {"status": "error", "output": str(e)}

# HÀM MỚI BẮT ĐẦU TỪ ĐÂY
def set_ipv4_action(params):
    """Thực thi việc thay đổi địa chỉ IPv4."""
    ip = params.get("ip")
    prefix = params.get("prefix", 24) # Prefix 24 (255.255.255.0) là một giá trị mặc định phổ biến cho IPv4
    iface = params.get("iface", "eth0")
    if not ip: return {"status": "error", "output": "Missing 'ip' parameter."}
    
    # Xóa các địa chỉ IPv4 cũ trên interface để tránh xung đột
    run_shell_command(f"ip -4 addr flush dev {iface}")
    # Thêm địa chỉ IPv4 mới
    return run_shell_command(f"ip addr add {ip}/{prefix} dev {iface}")


def set_ipv6_action(params):
    """Thực thi việc thay đổi địa chỉ IPv6."""
    ip = params.get("ip")
    prefix = params.get("prefix", 64)
    iface = params.get("iface", "eth0")
    if not ip: return {"status": "error", "output": "Missing 'ip' parameter."}
    
    run_shell_command(f"ip -6 addr flush dev {iface}")
    return run_shell_command(f"ip -6 addr add {ip}/{prefix} dev {iface}")

def set_mac_action(params):
    """Lên lịch thay đổi MAC và reboot."""
    mac = params.get("mac")
    iface = params.get("iface", "eth0")
    if not mac: return {"status": "error", "output": "Missing 'mac' parameter in request."}

    service_name = "change-mac-on-boot.service"
    service_path = f"/etc/systemd/system/{service_name}"
    
    service_content = f"""
[Unit]
Description=One-time script to change MAC address for {iface}
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set dev {iface} address {mac}
ExecStartPost=/usr/bin/systemctl disable {service_name}

[Install]
WantedBy=multi-user.target
"""
    try:
        print(f"    - Creating systemd service file at: {service_path}")
        with open(service_path, "w") as f:
            f.write(service_content)
        
        enable_result = run_shell_command(f"systemctl enable {service_name}")
        if "error" in enable_result.get("status", ""):
             # Kiểm tra lỗi chung chung hơn
             return {"status": "error", "output": f"Failed to enable systemd service: {enable_result['output']}"}

        # SỬA LỖI Ở ĐÂY: Thay '+0.25' bằng 'now'
        print("    - Scheduling reboot NOW...")
        run_shell_command("shutdown -r now")

        return {"status": "success", "output": f"MAC change for {iface} scheduled. Device will reboot now."}

    except PermissionError:
        return {"status": "error", "output": "Permission denied. Server must be run with sudo."}
    except Exception as e:
        return {"status": "error", "output": f"Failed to schedule MAC change: {str(e)}"}

def set_vlan_action(params):
    """Thực thi việc thay đổi VLAN."""
    vlan_id = params.get("vlan_id")
    iface = params.get("iface", "eth0")
    if vlan_id is None: return {"status": "error", "output": "Missing 'vlan_id' parameter."}
    
    # Cố gắng xóa sub-interface cũ trước khi tạo mới. 2>/dev/null sẽ ẩn lỗi nếu nó không tồn tại.
    run_shell_command(f"ip link del {iface}.{vlan_id} 2>/dev/null")
    
    if vlan_id == 0:
        return {"status": "success", "output": "VLAN removed. Interface is now untagged."}
    else:
        return run_shell_command(f"ip link add link {iface} name {iface}.{vlan_id} type vlan id {vlan_id}")

def get_config_action(params):
    """Lấy cấu hình mạng hiện tại."""
    iface = params.get("iface", "eth0")
    return run_shell_command(f"ip addr show dev {iface}")

# =======================================================
# === Bộ Điều Khiển Chính (Main Controller) ===
# =======================================================
COMMAND_HANDLERS = {
    "set_ipv4": set_ipv4_action,
    "set_ipv6": set_ipv6_action,
    "set_mac": set_mac_action,
    "set_vlan": set_vlan_action,
    "get_config": get_config_action,
}

def process_request(data_json):
    """Xác thực và điều phối lệnh."""
    try:
        signature = data_json["signature"]
        payload_str = json.dumps(data_json["payload"], sort_keys=True).encode('utf-8')
        expected_signature = hmac.new(SHARED_SECRET_KEY, payload_str, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return {"status": "error", "output": "Authentication failed: Invalid signature."}
    except KeyError:
        return {"status": "error", "output": "Authentication failed: Missing signature or payload."}

    payload = data_json["payload"]
    command = payload.get("command")
    handler = COMMAND_HANDLERS.get(command)
    
    if handler:
        print(f"--> Dispatching command '{command}'...")
        return handler(payload.get("params", {}))
    else:
        return {"status": "error", "output": f"Unknown command: '{command}'"}

# =======================================================
# === Vòng Lặp Server ===
# =======================================================
def run_server():
    print("--- Remote Control Protocol Receive ---")
    print(f"Listening on: [{LISTEN_IPv6}]:{LISTEN_PORT}")
    
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LISTEN_IPv6, LISTEN_PORT))
        s.listen(5)
    except OSError as e:
        print(f"[FATAL] Could not start server: {e}")
        sys.exit(1)

    try:
        while True:
            print("\nWaiting for a command...")
            try:
                conn, addr = s.accept()
                with conn:
                    print(f"✅ Connection accepted from: [{addr[0]}]:{addr[1]}")
                    data_raw = conn.recv(BUFFER_SIZE)
                    if not data_raw:
                        print("   Connection closed by client with no data.")
                        continue
                    
                    try:
                        data_json = json.loads(data_raw.decode('utf-8'))
                        
                        # ======== THAY ĐỔI CHÍNH Ở ĐÂY ========
                        # 1. Nhận kết quả trả về từ process_request
                        response = process_request(data_json)
                        
                        # 2. Kiểm tra xem có lỗi xác thực không
                        if response and response.get("status") == "error":
                            # In ra lỗi một cách rõ ràng
                            print(f"   [AUTH_ERROR] Request from {addr[0]} rejected.")
                            print(f"   Reason: {response.get('output')}")
                        else:
                            # Nếu không có lỗi, chỉ cần thông báo đã xử lý
                            print("<-- Command processed successfully. No response sent.")
                        # =====================================

                    except json.JSONDecodeError:
                        print("   [ERROR] Invalid JSON format received.")
                    except Exception as e:
                        print(f"   [ERROR] Server-side exception: {e}")
            except socket.error as e:
                print(f"Socket error during accept/recv: {e}")

    except KeyboardInterrupt:
        print("\nCtrl+C detected. Shutting down server.")
    finally:
        print("Closing server socket.")
        s.close()


if __name__ == '__main__':
    run_server()