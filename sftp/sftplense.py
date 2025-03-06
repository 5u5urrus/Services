# Author: Vahe
# Description: This script performs simple security assessments on SFTP services.
# It includes port checks, banner grabbing, protocol version checks, anonymous
# login detection, user enumeration, brute-force protection testing, rate-limiting
# detection, authentication method enumeration, and checks for weak cryptographic algorithms.
# Usage: python sftplense.py <target_ip> [port]

import paramiko
import socket
import sys
import time

TARGET = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 22

COMMON_USERS = ['root', 'admin', 'user', 'anonymous', 'test']
COMMON_PASSWORDS = ['password', '123456', 'anonymous', '']

# Check if port is open
def check_port_open(target, port):
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((target, port))
        print(f"[+] Port {port} is open on {target}")
        return True
    except Exception as e:
        print(f"[-] Port {port} is closed or unreachable on {target}: {e}")
        return False
    finally:
        s.close()

# Banner grabbing
def grab_banner(target, port):
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((target, port))
        banner = s.recv(1024).decode().strip()
        print(f"[+] Banner: {banner}")
        return banner
    except Exception as e:
        print(f"[-] Unable to grab banner: {e}")
        return None
    finally:
        s.close()

# (2) SSH Protocol Version Enforcement
def check_ssh_protocol_version(banner):
    if banner is None:
        print("[-] Cannot determine SSH protocol version: No banner received.")
        return
    if banner.startswith("SSH-1."):
        print("[!] Warning: The server supports SSH protocol version 1 which is deprecated and vulnerable.")
    elif banner.startswith("SSH-2.0"):
        print("[+] The server supports SSH protocol version 2.0 only.")
    else:
        print("[?] Unrecognized SSH banner format.")

# Attempt anonymous or default logins
def check_anonymous_login(target, port):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for user in ['anonymous', 'ftp', 'guest']:
        for passwd in ['anonymous', '', 'guest']:
            try:
                ssh.connect(target, port=port, username=user, password=passwd, timeout=5)
                print(f"[+] Anonymous login success with {user}:{passwd}")
                ssh.close()
                return
            except paramiko.AuthenticationException:
                print(f"[-] Anonymous login failed with {user}:{passwd}")
            except Exception as e:
                print(f"[-] Connection issue: {e}")
                return

# User enumeration via response analysis
def enumerate_users(target, port):
    for user in COMMON_USERS:
        transport = paramiko.Transport((target, port))
        try:
            transport.connect(username=user, password='invalidpassword')
        except paramiko.AuthenticationException as auth_exc:
            print(f"[*] Authentication failed for {user}: {auth_exc}")
        except paramiko.SSHException as ssh_exc:
            print(f"[!] Possible user enumeration detected for {user}: {ssh_exc}")
        except Exception as e:
            print(f"[-] Error testing user {user}: {e}")
        finally:
            transport.close()

# (7) Brute-force protection & Rate-Limiting Detection
def brute_force_protection_test(target, port):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    attempts = 10
    blocked = False
    attempt_times = []

    for attempt in range(attempts):
        start_time = time.time()
        try:
            ssh.connect(target, port=port, username='invaliduser', password='invalidpass', timeout=5)
        except paramiko.AuthenticationException:
            duration = time.time() - start_time
            attempt_times.append(duration)
            print(f"[*] Attempt {attempt+1}/{attempts} failed - expected (took {duration:.2f} seconds)")
        except paramiko.SSHException as e:
            duration = time.time() - start_time
            attempt_times.append(duration)
            print(f"[!] SSH Exception detected: {e} (took {duration:.2f} seconds)")
            if 'disconnect' in str(e).lower() or 'too many' in str(e).lower():
                print("[+] Brute force protection likely active")
                blocked = True
                break
        except Exception as e:
            duration = time.time() - start_time
            attempt_times.append(duration)
            print(f"[-] Connection issue during brute force test: {e} (took {duration:.2f} seconds)")
            break

    if not blocked:
        print("[-] No brute force protection detected.")

    # Rate-limiting detection: compare response times of early and later attempts
    if len(attempt_times) >= 6:
        avg_first = sum(attempt_times[:3]) / 3
        avg_last = sum(attempt_times[-3:]) / 3
        print(f"[*] Average time of first 3 attempts: {avg_first:.2f} seconds")
        print(f"[*] Average time of last 3 attempts: {avg_last:.2f} seconds")
        if avg_last > 2 * avg_first:
            print("[+] Rate limiting detected: Response times increased significantly.")
        else:
            print("[-] No rate limiting detected.")
    else:
        print("[-] Not enough data to analyze rate limiting.")

# (5) Authentication Methods Enumeration
def enumerate_auth_methods(target, port, username='test'):
    transport = paramiko.Transport((target, port))
    try:
        transport.start_client(timeout=5)
    except Exception as e:
        print(f"[-] Could not start SSH client for auth methods enumeration: {e}")
        return

    try:
        # Attempt an authentication with no credentials to trigger allowed methods response
        transport.auth_none(username)
    except paramiko.BadAuthenticationType as e:
        print(f"[+] Authentication methods for user '{username}': {e.allowed_types}")
    except paramiko.AuthenticationException as e:
        # Some versions of Paramiko might include allowed_types in this exception
        if hasattr(e, 'allowed_types'):
            print(f"[+] Authentication methods for user '{username}': {e.allowed_types}")
        else:
            print(f"[-] Could not enumerate authentication methods for user '{username}': {e}")
    except Exception as e:
        print(f"[-] Error enumerating authentication methods for user '{username}': {e}")
    finally:
        transport.close()

# Cipher and algorithm check
def check_weak_algorithms(target, port):
    transport = paramiko.Transport((target, port))
    try:
        transport.start_client(timeout=5)
    except Exception as e:
        print(f"[-] Could not start SSH client for algorithm check: {e}")
        return

    algorithms = transport.get_security_options()
    print(f"[+] Ciphers offered by server: {algorithms.ciphers}")
    print(f"[+] KEX algorithms offered: {algorithms.kex}")
    if hasattr(algorithms, 'macs'):
        print(f"[+] MAC algorithms offered: {algorithms.macs}")
    else:
        print("[-] MAC algorithms offered: Not available in this version of Paramiko")
    print(f"[+] Compression algorithms offered: {algorithms.compression}")

    transport.close()

if __name__ == "__main__":
    if not check_port_open(TARGET, PORT):
        sys.exit()

    banner = grab_banner(TARGET, PORT)
    check_ssh_protocol_version(banner)
    check_anonymous_login(TARGET, PORT)
    enumerate_users(TARGET, PORT)
    brute_force_protection_test(TARGET, PORT)
    enumerate_auth_methods(TARGET, PORT, username='test')
    check_weak_algorithms(TARGET, PORT)
