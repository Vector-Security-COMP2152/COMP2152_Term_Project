# MuksidAlam's vulnerability script
"""
Author: MuksidAlam
Vulnerability: Anonymous FTP login enabled on non-standard port
Target: ftp.0x10.cloud:2121

Pattern: connect -> check -> report
"""

import ftplib
import socket
import time

TARGET = "ftp.0x10.cloud"
PORT = 2121
TIMEOUT = 6


def main() -> None:
    print("=" * 60)
    print("  MuksidAlam - Anonymous FTP Check")
    print("=" * 60)
    print(f"\n  Target: {TARGET}:{PORT}")

    ftp = ftplib.FTP()

    try:
        # connect
        ftp.connect(TARGET, PORT, timeout=TIMEOUT)
        banner = ftp.getwelcome() or "No banner returned"
        print(f"  Banner: {banner}")
        time.sleep(0.15)

        # check
        reply = ftp.login(user="anonymous", passwd="anonymous@0x10.cloud")
        print(f"  Login Reply: {reply}")
        time.sleep(0.15)

        try:
            files = ftp.nlst()
            print(f"  Sample listing count: {len(files)}")
        except ftplib.all_errors:
            print("  Directory listing not available after login.")

        # report
        print("\n  [!] VULNERABILITY FOUND")
        print("  Anonymous FTP login is enabled.")
        print("  Attackers can access files without authentication.")
        print("  Disable anonymous access and enforce authenticated FTP/SFTP.")

    except ftplib.error_perm as err:
        print("\n  [OK] Anonymous login denied (not vulnerable).")
        print(f"  Server reply: {err}")
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as err:
        print(f"\n  [ERROR] Network/connection issue: {err}")
    except ftplib.all_errors as err:
        print(f"\n  [ERROR] FTP error: {err}")
    finally:
        try:
            ftp.quit()
        except Exception:
            pass

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
