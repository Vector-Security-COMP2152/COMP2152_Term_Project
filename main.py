# ============================================================
#  COMP2152 — Term Project: CTF Bug Bounty
#  Main Runner — Runs all vulnerability check scripts
# ============================================================

import subprocess
import sys
import os

scripts = [
    "example_http_check.py",
    "example_port_check.py",
    "example_header_check.py",
    "hasankhalil_http_vulnerability.py",
    "muksidalam_anonymous_ftp.py",
    "samuelbarth_redis_noauth.py",
]

if __name__ == "__main__":
    # Run scripts from the same directory as main.py
    script_dir = os.path.dirname(os.path.abspath(__file__))

    print("\n" + "=" * 50)
    print("  COMP2152 — Bug Bounty Scanner")
    print("  Running all vulnerability checks...")
    print("=" * 50, flush=True)

    for script in scripts:
        script_path = os.path.join(script_dir, script)
        if not os.path.exists(script_path):
            print(f"\n>>> Skipping {script} (file not found)\n", flush=True)
            continue
        print(f"\n>>> Running {script}...\n", flush=True)
        subprocess.run([sys.executable, script_path])

    print("\n" + "=" * 50)
    print("  All checks complete.")
    print("=" * 50 + "\n")
