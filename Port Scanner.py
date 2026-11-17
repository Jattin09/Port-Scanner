
import socket
import time
import argparse

from concurrent.futures import ThreadPoolExecutor, as_completed


# ==========================================
# CONFIGURATION
# ==========================================

def parse_arguments():

    parser = argparse.ArgumentParser(
        description="Advanced Multithreaded TCP Port Scanner"
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "--start-port",
        type=int,
        default=1
    )

    parser.add_argument(
        "--end-port",
        type=int,
        default=1024
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=100
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5
    )

    return parser.parse_args()


# ==========================================
# TCP SCANNING WORKER
# ==========================================

def scan_port(target, port, timeout):

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex(
                (target, port)
            )

            if result == 0:

                return {
                    "port": port,
                    "state": "open",
                    "service": socket.getservbyport(
                        port, "tcp"
                    ) if port <= 65535 else "unknown"
                }

    except OSError:
        return None

    return None


# ==========================================
# MULTITHREADED SCANNER
# ==========================================

def run_scanner(target, start_port, end_port,
                threads, timeout):

    print("\nStarting Advanced TCP Scanner")
    print("--------------------------------")

    print(f"Target: {target}")
    print(f"Port range: {start_port}-{end_port}")
    print(f"Threads: {threads}")
    print(f"Timeout: {timeout}")

    start_time = time.perf_counter()

    open_ports = []

    with ThreadPoolExecutor(
        max_workers=threads
    ) as executor:

        futures = {

            executor.submit(
                scan_port,
                target,
                port,
                timeout
            ): port

            for port in range(
                start_port,
                end_port + 1
            )
        }

        for future in as_completed(futures):

            result = future.result()

            if result:

                open_ports.append(result)

                print(
                    f"[+] {result['port']}/TCP OPEN "
                    f"| {result['service']}"
                )

    duration = time.perf_counter() - start_time

    print("\nScan completed!")
    print(f"Open ports found: {len(open_ports)}")
    print(f"Duration: {duration:.2f} seconds")

    return open_ports


# ==========================================
# MAIN
# ==========================================

def main():

    args = parse_arguments()

    if not (
        1 <= args.start_port
        <= args.end_port
        <= 65535
    ):
        raise SystemExit("Invalid port range")

    if not 1 <= args.threads <= 200:
        raise SystemExit("Threads must be between 1 and 200")

    if args.timeout <= 0:
        raise SystemExit("Timeout must be positive")

    try:

        target_ip = socket.gethostbyname(
            args.target
        )

    except socket.gaierror:

        raise SystemExit("Unable to resolve target")

    run_scanner(
        target_ip,
        args.start_port,
        args.end_port,
        args.threads,
        args.timeout
    )


if __name__ == "__main__":
    main()
