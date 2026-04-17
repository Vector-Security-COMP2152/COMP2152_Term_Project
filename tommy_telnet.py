# Author: Tommy
# Vulnerability: Telnet Exposed on Non-Standard Port
# Target: telnet.0x10.cloud

import socket
import time

target = "telnet.0x10.cloud"
port = 2323

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)

try:
    # connect to telnet on non-standard port 2323
    sock.connect((target, port))
    print(f"Connected to {target}:{port}")
    
    time.sleep(2)
    
    # grab the banner
    banner = sock.recv(4096).decode(errors="ignore")
    print(f"Banner: {banner}")
    
    print("VULNERABILITY: Telnet is open on port 2323!")
    print("Telnet sends ALL data including passwords in cleartext.")
    print("Anyone on the network can intercept credentials.")
    print("This service should be replaced with SSH.")

except Exception as e:
    print(f"Error: {e}")

finally:
    sock.close()