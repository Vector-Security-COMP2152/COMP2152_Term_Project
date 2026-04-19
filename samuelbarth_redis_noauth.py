# samuelbarth's vulnerability script
"""
Author: samuelbarth
Vulnerability: Redis service accessible without authentication
Scope: Only scans subdomains of 0x10.cloud

Pattern: connect -> check -> report
"""

import socket
import time

PORT = 6379
TIMEOUT = 4
RATE_DELAY = 0.15

# Keep targets in-scope only (*.0x10.cloud)
CANDIDATE_TARGETS = [
    "redis.0x10.cloud",
    "cache.0x10.cloud",
    "db.0x10.cloud",
    "data.0x10.cloud",
    "api.0x10.cloud",
]


def send_redis_command(sock: socket.socket, command: str) -> str:
    payload = f"*1\r\n${len(command)}\r\n{command}\r\n".encode()
    sock.sendall(payload)
    data = sock.recv(4096)
    return data.decode(errors="ignore")


def check_target(target: str) -> bool:
    print("\n" + "-" * 60)
    print(f"Checking {target}:{PORT}")

    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        # connect
        result = sock.connect_ex((target, PORT))
        if result != 0:
            print("  Port closed/unreachable.")
            return False

        print("  Connected.")
        time.sleep(RATE_DELAY)

        # check
        ping_reply = send_redis_command(sock, "PING").strip()
        print(f"  PING reply: {ping_reply}")
        time.sleep(RATE_DELAY)

        info_reply = send_redis_command(sock, "INFO")
        info_line = info_reply.splitlines()[0] if info_reply else "(empty)"
        print(f"  INFO reply: {info_line}")

        noauth_markers = ("-NOAUTH", "Authentication required")
        is_exposed = (
            ping_reply.startswith("+PONG")
            and not any(marker in info_reply for marker in noauth_markers)
        )

        # report
        if is_exposed:
            print("\n  [!] VULNERABILITY FOUND")
            print("  Redis commands are accepted without AUTH.")
            print("  Attackers may read/modify cached data or abuse the service.")
            print("  Fix: Require a password/ACL and bind service to private network.")
            return True

        print("  [OK] Redis appears protected or not vulnerable on this host.")
        return False

    except (socket.timeout, socket.gaierror) as err:
        print(f"  [ERROR] Network issue: {err}")
        return False
    except OSError as err:
        print(f"  [ERROR] Socket error: {err}")
        return False
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass


def main() -> None:
    print("=" * 60)
    print("  samuelbarth - Redis No-Auth Check")
    print("=" * 60)
    print("  Scope: *.0x10.cloud only")

    found_any = False
    for target in CANDIDATE_TARGETS:
        if check_target(target):
            found_any = True
        time.sleep(RATE_DELAY)

    print("\n" + "=" * 60)
    if not found_any:
        print("No vulnerable Redis target detected in the candidate list.")
        print("If needed, add other in-scope subdomains to CANDIDATE_TARGETS.")
    print("=" * 60)


if __name__ == "__main__":
    main()
