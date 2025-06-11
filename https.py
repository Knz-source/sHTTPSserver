import http.server
import ssl
import sys
import os
import subprocess
import argparse
import socket
import fcntl
import struct
from pathlib import Path

def list_interfaces():
    interfaces = []
    with open('/proc/net/dev') as f:
        data = f.readlines()[2:]
        for line in data:
            iface = line.split(':')[0].strip()
            interfaces.append(iface)
    return interfaces

def get_ip_address(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # secret
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return None

def print_interfaces():
    print("Available network interfaces and their IPv4 addresses:")
    interfaces = list_interfaces()
    for iface in interfaces:
        ip = get_ip_address(iface)
        print(f"  {iface}: {ip if ip else 'no IPv4'}")
    return interfaces

def get_cert_params(level):
    if level == "very_strong":
        return {"bits": "4096", "digest": "sha512"}
    elif level == "strong":
        return {"bits": "2048", "digest": "sha256"}
    elif level == "weak":
        return {"bits": "1024", "digest": "sha1"}
    else:
        return {"bits": "2048", "digest": "sha256"}

def generate_self_signed_cert(cert_file, key_file, cn="localhost", ou="redteam", level="strong"):
    os.makedirs(os.path.dirname(cert_file), exist_ok=True)
    os.makedirs(os.path.dirname(key_file), exist_ok=True)
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("Certificate already exists. Using existing files.")
        return
    params = get_cert_params(level)
    print(f"Generating self-signed certificate ({level})...")
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', f'rsa:{params["bits"]}', '-keyout', key_file,
        '-out', cert_file, '-days', '365', '-nodes',
        '-subj', f'/CN={cn}/OU={ou}',
        f'-{params["digest"]}'
    ], check=True)
    print(f"Certificate generated: {cert_file} / {key_file}")

def interactive_mode(default_cert_file, default_key_file):
    print("\n==== INTERACTIVE MODE ====\n")

    # select int
    interfaces = print_interfaces()
    while True:
        chosen = input("Enter the name of the network interface you want to use: ").strip()
        ip = get_ip_address(chosen)
        if ip:
            break
        print("Invalid interface or no IPv4 address found. Please try again.")
    host = ip

    # select port
    while True:
        port_input = input("Enter the port you want to use [4443]: ").strip()
        if not port_input:
            port = 4443
            break
        try:
            port = int(port_input)
            if 1 <= port <= 65535:
                break
            else:
                print("Please enter a valid port (1-65535).")
        except ValueError:
            print("Invalid input. Please enter a valid port.")

    # Certificate options
    print("\nHow do you want to handle the SSL certificate?")
    print("  1. Use/generate self-signed certificate (recommended for labs)")
    print("  2. Provide my own certificate and key files")
    while True:
        cert_option = input("Select [1/2]: ").strip()
        if cert_option in ("1", "2"):
            break
        print("Please type 1 or 2.")
    if cert_option == "2":
        cert_file = input(f"Path to certificate file (PEM): ").strip()
        key_file = input(f"Path to private key file (PEM): ").strip()
        if not (os.path.isfile(cert_file) and os.path.isfile(key_file)):
            print("Files not found! Exiting.")
            sys.exit(1)
        return host, port, cert_file, key_file
    else:
        cert_file = input(f"Certificate file path [{default_cert_file}]: ").strip() or default_cert_file
        key_file = input(f"Key file path [{default_key_file}]: ").strip() or default_key_file

        print("\nCipher strength:")
        print("  1. very_strong (4096 bits, SHA-512)")
        print("  2. strong      (2048 bits, SHA-256) [default]")
        print("  3. weak        (1024 bits, SHA-1)")

        level_map = {"1": "very_strong", "2": "strong", "3": "weak"}
        while True:
            cipher_choice = input("Select [1/2/3]: ").strip()
            if cipher_choice in level_map:
                level = level_map[cipher_choice]
                break
            if cipher_choice == "" or cipher_choice == "2":
                level = "strong"
                break
            print("Invalid input. Please select 1, 2, or 3.")

        cn = input("Certificate CN [localhost]: ").strip() or "localhost"
        ou = input("Certificate OU [redteam]: ").strip() or "redteam"

        generate_self_signed_cert(cert_file, key_file, cn=cn, ou=ou, level=level)
        return host, port, cert_file, key_file

def main():
    default_cert_dir = os.path.join(str(Path.home()), ".https_server")
    default_cert_file = os.path.join(default_cert_dir, "cert.pem")
    default_key_file = os.path.join(default_cert_dir, "key.pem")

    parser = argparse.ArgumentParser(
        description="Minimal HTTPS server for Red Team, labs, or dev. "
                    "Lets you pick interface, port, and SSL options, with safe certificate storage.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--int', type=str, help='Network interface to bind (e.g., ens18, lo)')
    parser.add_argument('--port', type=int, help='Port to bind')
    parser.add_argument('--list-interfaces', action='store_true', help='List available interfaces and exit')
    parser.add_argument('--cert', type=str, help='Path to certificate file (PEM)')
    parser.add_argument('--key', type=str, help='Path to private key file (PEM)')
    parser.add_argument('--generate-cert', action='store_true', help='Force generating a new self-signed certificate')
    parser.add_argument('--cert-cn', type=str, default="localhost", help='Common Name (CN) for generated certificate')
    parser.add_argument('--cert-ou', type=str, default="redteam", help='Organizational Unit (OU) for generated certificate')
    parser.add_argument('--cert-level', type=str, choices=['very_strong', 'strong', 'weak'], default='strong', help='Cipher strength for generated certificate')
    args = parser.parse_args()

    if args.list_interfaces:
        print_interfaces()
        sys.exit(0)

    if len(sys.argv) == 1:
        host, port, cert_file, key_file = interactive_mode(default_cert_file, default_key_file)
    else:
        # Interface selection
        if args.int:
            ip = get_ip_address(args.int)
            if not ip:
                print(f"Could not find IPv4 address for interface '{args.int}'.")
                print_interfaces()
                sys.exit(1)
            host = ip
        else:
            print_interfaces()
            chosen = input("Enter the name of the network interface you want to use: ").strip()
            ip = get_ip_address(chosen)
            if not ip:
                print(f"Could not find IPv4 address for interface '{chosen}'. Exiting.")
                sys.exit(1)
            host = ip

        # SELECT PORT
        if args.port:
            port = args.port
        else:
            port_input = input("Enter the port you want to use [4443]: ").strip()
            port = int(port_input) if port_input else 4443
#SELECT CERT
        cert_file = args.cert if args.cert else default_cert_file
        key_file = args.key if args.key else default_key_file

        if not os.path.exists(cert_file) or not os.path.exists(key_file) or args.generate_cert:
            generate_self_signed_cert(
                cert_file, key_file,
                cn=args.cert_cn,
                ou=args.cert_ou,
                level=args.cert_level
            )

    ##notdeprecated monkey
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer((host, port), handler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"\nHTTPS server running at https://{host}:{port}")
    print(f"Certificate: {cert_file}, Key: {key_file}")
    print("CTRL+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")

if __name__ == '__main__':
    main()

