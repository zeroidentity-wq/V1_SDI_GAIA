#!/usr/bin/env python3
"""
tester.py - Script de testare pentru Rust IDS
==============================================

Trimite pachete UDP cu log-uri de firewall simulate.
Suportă atât formatul Gaia Raw cât și CEF.

Utilizare:
  python3 tester.py --mode fast_scan                     # Gaia (implicit)
  python3 tester.py --mode fast_scan --format cef        # CEF fast scan
  python3 tester.py --mode slow_scan --format gaia
  python3 tester.py --mode cef_normal                    # CEF Allow - nu alertă
  python3 tester.py --mode all
  python3 tester.py --mode fast_scan --coalesce --verbose

IMPORTANT: --format TREBUIE să corespundă cu parser din config.toml!
  config.toml -> parser = "gaia"  =>  --format gaia
  config.toml -> parser = "cef"   =>  --format cef
"""

import argparse
import socket
import time
import sys
import random
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# Constante
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_HOST   = "127.0.0.1"
DEFAULT_PORT   = 5555
DEFAULT_SRC_IP = "192.168.11.7"
FW_IP          = "192.168.99.1"

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
    995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    8888, 9090, 9200, 27017, 27018, 4444, 4445, 6666, 7777,
    2222, 2121, 3000, 4000, 5000, 5001, 7000, 8000, 9000, 9001
]


# ─────────────────────────────────────────────────────────────────────────────
# Generatoare de log-uri
# ─────────────────────────────────────────────────────────────────────────────

def make_gaia_drop_log(src_ip: str, dst_port: int, fw_ip: str = FW_IP) -> str:
    """
    Log Checkpoint Gaia Raw tip 'drop'.

    Exemplu:
      Sep  3 15:12:20 192.168.99.1 Checkpoint: drop 192.168.11.7 proto: tcp; service: 22; s_port: 1352
    """
    ts       = datetime.now().strftime("%b %d %H:%M:%S")
    src_port = random.randint(1024, 65535)
    return (
        f"{ts} {fw_ip} Checkpoint: drop {src_ip} "
        f"proto: tcp; service: {dst_port}; s_port: {src_port}"
    )


def make_gaia_accept_log(src_ip: str, dst_port: int, fw_ip: str = FW_IP) -> str:
    """Log Gaia 'accept' - IDS-ul trebuie să îl ignore."""
    ts       = datetime.now().strftime("%b %d %H:%M:%S")
    src_port = random.randint(1024, 65535)
    return (
        f"{ts} {fw_ip} Checkpoint: accept {src_ip} "
        f"proto: tcp; service: {dst_port}; s_port: {src_port}"
    )


def make_cef_drop_log(src_ip: str, dst_port: int) -> str:
    """
    Log CEF tip 'drop' cu prefix syslog (formatul real primit de IDS).

    Exemplu de log real:
      Nov 20 15:30:00 firewall CEF:0|Checkpoint|VPN-1 & FireWall-1|NGX R65|
          firewall|Connection Blocked|7|src=10.0.0.5 dst=10.0.0.1 dpt=22 act=drop

    NOTA: Log-ul are OBLIGATORIU un prefix syslog (timestamp + hostname)
    inaintea 'CEF:'. Acesta este formatul real al syslog-ului.
    Bug-ul initial din cef.rs era ca facea starts_with("CEF:") care
    respingea TOATE log-urile reale cu prefix. Acum e fix cu contains("CEF:").
    """
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    return (
        f"{ts} firewall "
        f"CEF:0|Checkpoint|VPN-1 & FireWall-1|NGX R65|firewall|"
        f"Connection Blocked|7|"
        f"src={src_ip} dst=10.0.0.1 dpt={dst_port} act=drop "
        f"proto=TCP rt={int(time.time() * 1000)}"
    )


def make_cef_allow_log(src_ip: str, dst_port: int) -> str:
    """Log CEF tip 'Allow' - IDS-ul trebuie să îl ignore."""
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    return (
        f"{ts} firewall "
        f"CEF:0|Checkpoint|VPN-1 & FireWall-1|NGX R65|firewall|"
        f"Connection Allowed|3|"
        f"src={src_ip} dst=10.0.0.1 dpt={dst_port} act=Allow "
        f"proto=TCP rt={int(time.time() * 1000)}"
    )


def make_log(src_ip: str, dst_port: int, fmt: str, drop: bool = True) -> str:
    """
    Factory: alege generatorul corect pe baza formatului.

    Args:
        fmt:  "gaia" sau "cef" — trebuie să corespundă cu parser din config.toml
        drop: True = drop/blocked, False = accept/allow
    """
    if fmt == "cef":
        return make_cef_drop_log(src_ip, dst_port) if drop else make_cef_allow_log(src_ip, dst_port)
    else:
        return make_gaia_drop_log(src_ip, dst_port) if drop else make_gaia_accept_log(src_ip, dst_port)


# ─────────────────────────────────────────────────────────────────────────────
# Trimitere UDP
# ─────────────────────────────────────────────────────────────────────────────

def send_udp(host: str, port: int, message: str, verbose: bool = False) -> bool:
    """Trimite un singur mesaj UDP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            encoded = (message + "\n").encode("utf-8")
            sock.sendto(encoded, (host, port))
            if verbose:
                preview = message[:110] + ("..." if len(message) > 110 else "")
                print(f"    [SENT] {preview}")
            return True
    except Exception as e:
        print(f"    [ERROR] {host}:{port} -> {e}", file=sys.stderr)
        return False


def send_udp_coalesced(host: str, port: int, messages: list, verbose: bool = False) -> bool:
    """
    Trimite mai multe log-uri concatenate într-un singur pachet UDP.
    Simulează buffer coalescing real al firewall-urilor.
    """
    combined = "\n".join(messages) + "\n"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(combined.encode("utf-8"), (host, port))
            if verbose:
                print(f"    [COALESCED] {len(messages)} log-uri => 1 pachet UDP ({len(combined)} bytes)")
            return True
    except Exception as e:
        print(f"    [ERROR] {e}", file=sys.stderr)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Scenarii de test
# ─────────────────────────────────────────────────────────────────────────────

def test_fast_scan(host, port, src_ip, log_format, delay, coalesce, verbose):
    """
    Simulare Fast Scan: 20 porturi unice in < 2 secunde.
    Prag din config.toml: fast_scan_ports=15, fast_scan_window_secs=10
    => 20 > 15 in fereastra de 10s => ALERTA ASTEPTATA.
    """
    print()
    print("=" * 65)
    print(f"  TEST: FAST SCAN  |  Format log: {log_format.upper()}")
    print(f"  IP Sursa: {src_ip}  |  IDS: {host}:{port}")
    print(f"  Porturi: 20 unice  |  Delay: {delay}s  |  Coalesce: {coalesce}")
    print()
    print(f"  Asigurati-va ca in config.toml: parser = \"{log_format}\"")
    print("=" * 65)

    ports = random.sample(COMMON_PORTS, min(20, len(COMMON_PORTS)))
    logs  = [make_log(src_ip, p, log_format, drop=True) for p in ports]
    sent  = 0

    if coalesce:
        print(f"\n  Trimit {len(logs)} log-uri intr-un singur pachet UDP (coalesced)...")
        if send_udp_coalesced(host, port, logs, verbose):
            sent = len(logs)
        print(f"  Trimis: {sent}/{len(logs)} log-uri")
    else:
        for i, (log, p) in enumerate(zip(logs, ports), 1):
            print(f"  [{i:02d}/{len(logs)}] Port {p:>5}", end="  ")
            if send_udp(host, port, log, verbose):
                sent += 1
                print("OK")
            else:
                print("FAIL")
            time.sleep(delay)
        print(f"\n  Trimis: {sent}/{len(logs)} pachete")

    print(f"\n  ASTEPTAT: Alerta FAST SCAN pentru IP {src_ip}")
    print()


def test_slow_scan(host, port, src_ip, log_format, verbose):
    """
    Simulare Slow Scan: 35 porturi unice cu 2s intre ele (~70s total).

    NOTA: Setati slow_scan_window_mins=1 in config.toml pentru test rapid.
    """
    print()
    print("=" * 65)
    print(f"  TEST: SLOW SCAN  |  Format log: {log_format.upper()}")
    print(f"  IP Sursa: {src_ip}  |  IDS: {host}:{port}")
    print(f"  Porturi: 35 unice  |  Delay: 2s/pachet  (~70s total)")
    print()
    print("  !! Setati slow_scan_window_mins=1 in config.toml pentru test rapid !!")
    print("=" * 65)

    ports = random.sample(range(1, 65000), 35)
    sent  = 0

    for i, p in enumerate(ports, 1):
        log = make_log(src_ip, p, log_format, drop=True)
        print(f"  [{i:02d}/35] Port {p:>5}", end="  ")
        if send_udp(host, port, log, verbose):
            sent += 1
            print("OK")
        else:
            print("FAIL")
        time.sleep(2.0)

    print(f"\n  Trimis: {sent}/35 pachete")
    print(f"  ASTEPTAT: Alerta SLOW SCAN pentru IP {src_ip}")
    print()


def test_cef_normal(host, port, src_ip, verbose):
    """
    Trimite log-uri CEF cu actiunea 'Allow' - IDS-ul NU trebuie sa alerteze.

    Verifica doua lucruri:
      1. Parser-ul CEF gestioneaza corect prefix-ul syslog (timestamp + hostname)
      2. Actiunile non-drop (Allow, Accept) sunt filtrate si ignorate
    """
    print()
    print("=" * 65)
    print("  TEST: CEF ALLOW LOGS  (nu trebuie alerta)")
    print(f"  IP Sursa: {src_ip}  |  IDS: {host}:{port}")
    print()
    print("  Verifica: parser CEF gestioneaza prefix syslog + filtreaza Allow")
    print("=" * 65)
    print()

    test_cases = [(80, "HTTP"), (443, "HTTPS"), (53, "DNS"), (25, "SMTP")]
    for dst_port, desc in test_cases:
        log = make_cef_allow_log(src_ip, dst_port)
        print(f"  CEF Allow {desc} (port {dst_port})", end="  ")
        send_udp(host, port, log, verbose=False)
        print("-> trimis")
        if verbose:
            print(f"    {log[:110]}...")
        time.sleep(0.1)

    print()
    print("  ASTEPTAT: Zero alerte (toate actiunile sunt Allow, nu drop)")
    print()


def test_normal_traffic(host, port, src_ip, log_format, verbose):
    """5 drop-uri (sub prag) - nu trebuie sa declanseze alerta."""
    print()
    print("=" * 65)
    print(f"  TEST: TRAFIC NORMAL SUB PRAG  |  Format: {log_format.upper()}")
    print(f"  5 porturi drop  (prag Fast Scan = 15 porturi)")
    print("=" * 65)

    for p in [22, 80, 443, 3306, 5432]:
        log = make_log(src_ip, p, log_format, drop=True)
        send_udp(host, port, log, verbose)
        time.sleep(0.1)

    print("  Trimis: 5 pachete drop")
    print("  ASTEPTAT: Nicio alerta (5 < 15 prag)")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Rust IDS Tester - Simulare atacuri de retea",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemple rapide:
  # Gaia fast scan (config.toml: parser = "gaia")
  python3 tester.py --mode fast_scan --format gaia

  # CEF fast scan (config.toml: parser = "cef")
  python3 tester.py --mode fast_scan --format cef --verbose

  # Buffer coalescing: 20 log-uri intr-un singur pachet UDP
  python3 tester.py --mode fast_scan --format gaia --coalesce

  # Verifica ca CEF Allow nu declanseaza alerta
  python3 tester.py --mode cef_normal

  # Toate testele (schimbati parserul in config.toml dupa nevoie)
  python3 tester.py --mode all --format cef
        """
    )

    parser.add_argument("--mode",
        choices=["fast_scan", "slow_scan", "cef_normal", "normal", "all"],
        default="fast_scan",
        help="Tipul de test (default: fast_scan)")
    parser.add_argument("--format",
        choices=["gaia", "cef"],
        default="gaia",
        help="Formatul log-urilor: gaia sau cef. "
             "TREBUIE sa corespunda cu 'parser' din config.toml! (default: gaia)")
    parser.add_argument("--host",      default=DEFAULT_HOST,
                        help=f"IP IDS (default: {DEFAULT_HOST})")
    parser.add_argument("--port",      type=int, default=DEFAULT_PORT,
                        help=f"Port UDP IDS (default: {DEFAULT_PORT})")
    parser.add_argument("--ip",        default=DEFAULT_SRC_IP,
                        help=f"IP sursa simulat (default: {DEFAULT_SRC_IP})")
    parser.add_argument("--delay",     type=float, default=0.05,
                        help="Delay intre pachete (fast_scan, default: 0.05s)")
    parser.add_argument("--coalesce",  action="store_true",
                        help="Trimite toate log-urile intr-un singur pachet UDP")
    parser.add_argument("--verbose",   action="store_true",
                        help="Afiseaza fiecare pachet trimis")

    args = parser.parse_args()

    print()
    print("=" * 65)
    print("  RUST IDS - PYTHON TESTER")
    print(f"  Target  : {args.host}:{args.port}")
    print(f"  Mode    : {args.mode.upper()}")
    print(f"  Format  : {args.format.upper()}")
    print("=" * 65)

    if args.mode == "fast_scan":
        test_fast_scan(args.host, args.port, args.ip, args.format,
                       args.delay, args.coalesce, args.verbose)

    elif args.mode == "slow_scan":
        test_slow_scan(args.host, args.port, args.ip, args.format, args.verbose)

    elif args.mode == "cef_normal":
        test_cef_normal(args.host, args.port, args.ip, args.verbose)

    elif args.mode == "normal":
        test_normal_traffic(args.host, args.port, args.ip, args.format, args.verbose)

    elif args.mode == "all":
        test_normal_traffic(args.host, args.port, "192.168.1.1",
                            args.format, args.verbose)
        test_cef_normal(args.host, args.port, "192.168.1.2", args.verbose)
        test_fast_scan(args.host, args.port, args.ip, args.format,
                       args.delay, args.coalesce, args.verbose)


if __name__ == "__main__":
    main()
