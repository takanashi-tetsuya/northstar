#!/usr/bin/env python3
"""
Allocate non-overlapping, available TCP ports within a specified range.
Usage: python3 scripts/allocate-test-ports.py <min_port> <max_port> <count>
Output: space-separated list of ports
"""
import random
import socket
import sys

def find_available_ports(min_port, max_port, count):
    ports = []
    candidates = list(range(min_port, max_port + 1))
    random.shuffle(candidates)

    for port in candidates:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(('127.0.0.1', port))
            ports.append(port)
            if len(ports) == count:
                break
        except OSError:
            continue
        finally:
            s.close()

    if len(ports) < count:
        sys.stderr.write(f"Error: Could only find {len(ports)} of {count} available ports in range {min_port}-{max_port}\n")
        sys.exit(1)

    print(" ".join(str(p) for p in ports))

if __name__ == '__main__':
    if len(sys.argv) < 4:
        sys.stderr.write("Usage: allocate-test-ports.py <min_port> <max_port> <count>\n")
        sys.exit(2)
    find_available_ports(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
