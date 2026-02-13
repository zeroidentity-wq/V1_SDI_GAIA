#!/usr/bin/env python3
"""
tester.py - Script de testare pentru Rust IDS
==============================================

Trimite pachete UDP către IDS pentru a simula:
  1. Fast Scan (log-uri Gaia Raw cu drop)
  2. Slow Scan  (log-uri Gaia Raw distribuite în timp)
  3. Log normal CEF (nu trebuie să declanșeze alertă)

Utilizare:
  python3 tester.py --mode fast_scan
  python3 tester.py --mode slow_scan --host 127.0.0.1 --port 5555
  python3 tester.py --mode cef_log
  python3 tester.py --mode all
  python3 tester.py --mode fast_scan --ip 10.5.5.100 --verbose

Opțiuni:
  --mode      : tipul de test (fast_scan, slow_scan, cef_log, all)
  --host      : IP-ul IDS-ului (default: 127.0.0.1)
  --port      : portul UDP al IDS-ului (default: 5555)
  --ip        : IP-ul sursă simulat (default: 192.168.11.7)
  --delay     : delay între pachete în secunde (default: 0.05)
  --coalesce  : trimite mai multe log-uri în același pachet UDP (simulează buffer coalescing)
  --verbose   : afișează fiecare pachet trimis
"""

import argparse
import socket
import time
import sys
import random
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# Constante și configurare implicită
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_HOST    = "127.0.0.1"
DEFAULT_PORT    = 5555
DEFAULT_SRC_IP  = "192.168.11.7"
FW_IP           = "192.168.99.1"   # IP-ul firewall-ului (apare în log)

# Paleta de porturi pentru simulare
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 
                995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                8888, 9090, 9200, 27017, 27018, 4444, 4445, 6666, 7777]


# ─────────────────────────────────────────────────────────────────────────────
# Funcții de generare a log-urilor
# ─────────────────────────────────────────────────────────────────────────────

def make_gaia_drop_log(src_ip: str, dst_port: int, fw_ip: str = FW_IP) -> str:
    """
    Generează un log Gaia Raw de tip 'drop'.
    
    Format:
    Sep  3 15:12:20 192.168.99.1 Checkpoint: drop 192.168.11.7 proto: tcp; service: 22; s_port: 1352
    """
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    src_port = random.randint(1024, 65535)
    return (f"{ts} {fw_ip} Checkpoint: drop {src_ip} "
            f"proto: tcp; service: {dst_port}; s_port: {src_port}")


def make_gaia_accept_log(src_ip: str, dst_port: int, fw_ip: str = FW_IP) -> str:
    """Generează un log Gaia de tip 'accept' - IDS-ul trebuie să ÎL IGNORE."""
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    src_port = random.randint(1024, 65535)
    return (f"{ts} {fw_ip} Checkpoint: accept {src_ip} "
            f"proto: tcp; service: {dst_port}; s_port: {src_port}")


def make_cef_log(src_ip: str, dst_port: int, action: str = "Allow") -> str:
    """
    Generează un log în format CEF (Common Event Format).
    
    Format:
    CEF:0|Checkpoint|VPN-1 & FireWall-1|NGX R65|firewall|Log message|5|
        src=IP dst=IP dpt=PORT act=Action
    """
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    return (f"{ts} sysloghost "
            f"CEF:0|Checkpoint|VPN-1 & FireWall-1|NGX R65|firewall|"
            f"Connection {action}|5|"
            f"src={src_ip} dst=10.0.0.1 dpt={dst_port} act={action} "
            f"proto=TCP rt={int(time.time()*1000)}")


# ─────────────────────────────────────────────────────────────────────────────
# Funcția de trimitere UDP
# ─────────────────────────────────────────────────────────────────────────────

def send_udp(host: str, port: int, message: str, verbose: bool = False) -> bool:
    """Trimite un mesaj UDP. Returnează True dacă a reușit."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            encoded = (message + "\n").encode("utf-8")
            sock.sendto(encoded, (host, port))
            if verbose:
                print(f"  [SENT] {message[:100]}{'...' if len(message) > 100 else ''}")
            return True
    except Exception as e:
        print(f"  [ERROR] Nu s-a putut trimite la {host}:{port} -> {e}", file=sys.stderr)
        return False


def send_udp_coalesced(host: str, port: int, messages: list, verbose: bool = False) -> bool:
    """
    Trimite mai multe log-uri într-un singur pachet UDP (simulează buffer coalescing).
    Log-urile sunt concatenate cu newline (\\n).
    """
    combined = "\n".join(messages) + "\n"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(combined.encode("utf-8"), (host, port))
            if verbose:
                print(f"  [COALESCED x{len(messages)}] Trimis {len(combined)} bytes")
            return True
    except Exception as e:
        print(f"  [ERROR] {e}", file=sys.stderr)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Scenarii de test
# ─────────────────────────────────────────────────────────────────────────────

def test_fast_scan(host: str, port: int, src_ip: str, delay: float,
                   coalesce: bool, verbose: bool):
    """
    Simulare Fast Scan: 20 porturi unice în <10 secunde.
    Pragul implicit din config: >15 porturi în 10s -> ALERTĂ.
    """
    print()
    print("=" * 60)
    print("  TEST: FAST SCAN SIMULATION")
    print(f"  Sursa: {src_ip} | Dest: {host}:{port}")
    print(f"  Porturi: 20 unice | Delay: {delay}s | Coalesce: {coalesce}")
    print("=" * 60)

    ports = random.sample(COMMON_PORTS + list(range(8000, 8030)), 20)
    logs  = [make_gaia_drop_log(src_ip, p) for p in ports]
    
    sent = 0

    if coalesce:
        # Trimitem toate log-urile într-un singur pachet UDP (test buffer coalescing)
        print(f"  Trimit {len(logs)} log-uri coalesce intr-un singur pachet UDP...")
        if send_udp_coalesced(host, port, logs, verbose):
            sent = len(logs)
    else:
        for i, log in enumerate(logs, 1):
            print(f"  [{i:02d}/{len(logs)}] Port: {ports[i-1]}", end="")
            if send_udp(host, port, log, verbose):
                sent += 1
                print(" -> OK")
            else:
                print(" -> FAIL")
            time.sleep(delay)

    print()
    print(f"  Trimis: {sent}/{len(logs)} pachete")
    print(f"  ASTEPTAT: Alerta FAST SCAN pentru {src_ip}")
    print()


def test_slow_scan(host: str, port: int, src_ip: str, verbose: bool):
    """
    Simulare Slow Scan: 35 porturi unice, trimise la interval de ~2s.
    Porturi > 30 unice -> ALERTĂ (pragul slow scan din config).
    
    NOTĂ: Pentru un slow scan real ar trebui W=60 minute, dar pentru
    testare reducem la câteva secunde (ajustați config.toml).
    """
    print()
    print("=" * 60)
    print("  TEST: SLOW SCAN SIMULATION")
    print(f"  Sursa: {src_ip} | Dest: {host}:{port}")
    print(f"  Porturi: 35 unice | Delay: 2s intre fiecare")
    print("=" * 60)
    print()
    print("  NOTĂ: Ajustați slow_scan_window_mins=1 in config.toml pentru test rapid!")
    print()

    ports = random.sample(range(1, 65535), 35)
    sent  = 0

    for i, p in enumerate(ports, 1):
        log = make_gaia_drop_log(src_ip, p)
        print(f"  [{i:02d}/35] Port={p}", end="")
        if send_udp(host, port, log, verbose):
            sent += 1
            print(" -> OK")
        else:
            print(" -> FAIL")
        time.sleep(2.0)  # 2 secunde între pachete = 70 secunde total

    print()
    print(f"  Trimis: {sent}/35 pachete")
    print(f"  ASTEPTAT: Alerta SLOW SCAN pentru {src_ip}")
    print()


def test_cef_log(host: str, port: int, src_ip: str, verbose: bool):
    """
    Trimite un log CEF normal (Allow) - IDS-ul NU trebuie să declanșeze alertă.
    Util pentru a verifica că parser-ul CEF funcționează și filtrează corect.
    """
    print()
    print("=" * 60)
    print("  TEST: CEF LOG NORMAL (nu trebuie alerta)")
    print(f"  Sursa: {src_ip} | Dest: {host}:{port}")
    print("=" * 60)

    # Log Allow - trebuie ignorat de IDS
    log_allow = make_cef_log(src_ip, 80, action="Allow")
    print(f"  Trimit CEF Allow log...")
    send_udp(host, port, log_allow, verbose)

    # Log Drop in CEF - ar trebui procesat dacă parser-ul e setat pe "cef"
    log_drop = make_cef_log(src_ip, 443, action="drop")
    print(f"  Trimit CEF Drop log (procesat doar daca parser=cef in config)...")
    send_udp(host, port, log_drop, verbose)

    print()
    print("  ASTEPTAT: Nicio alerta (log normal sau parser=gaia activ)")
    print()


def test_normal_traffic(host: str, port: int, src_ip: str, verbose: bool):
    """
    Trafic normal sub prag - IDS-ul NU trebuie să declanșeze alertă.
    """
    print()
    print("=" * 60)
    print("  TEST: TRAFIC NORMAL (sub prag)")
    print(f"  Sursa: {src_ip} | Dest: {host}:{port}")
    print("=" * 60)

    # 5 porturi - sub pragul fast_scan_ports=15
    ports = [80, 443, 8080, 22, 3306]
    for p in ports:
        log = make_gaia_drop_log(src_ip, p)
        send_udp(host, port, log, verbose)
        time.sleep(0.1)

    print(f"  Trimis: 5 pachete (sub prag)")
    print(f"  ASTEPTAT: Nicio alerta")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Tester UDP pentru Rust IDS - Simulare atacuri de rețea",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemple:
  python3 tester.py --mode fast_scan
  python3 tester.py --mode fast_scan --coalesce --verbose
  python3 tester.py --mode slow_scan --ip 10.0.0.50
  python3 tester.py --mode cef_log
  python3 tester.py --mode all --verbose
        """
    )

    parser.add_argument("--mode", choices=["fast_scan", "slow_scan", "cef_log", "normal", "all"],
                        default="fast_scan",
                        help="Tipul de test de rulat (default: fast_scan)")
    parser.add_argument("--host",  default=DEFAULT_HOST,
                        help=f"IP-ul IDS-ului (default: {DEFAULT_HOST})")
    parser.add_argument("--port",  type=int, default=DEFAULT_PORT,
                        help=f"Portul UDP al IDS-ului (default: {DEFAULT_PORT})")
    parser.add_argument("--ip",    default=DEFAULT_SRC_IP,
                        help=f"IP sursă simulat (default: {DEFAULT_SRC_IP})")
    parser.add_argument("--delay", type=float, default=0.05,
                        help="Delay între pachete pentru fast_scan (default: 0.05s)")
    parser.add_argument("--coalesce", action="store_true",
                        help="Trimite toate log-urile intr-un singur pachet UDP")
    parser.add_argument("--verbose", action="store_true",
                        help="Afișează fiecare pachet trimis")

    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  RUST IDS - PYTHON TESTER")
    print(f"  Target: {args.host}:{args.port}")
    print(f"  Mode:   {args.mode.upper()}")
    print("=" * 60)

    # Verificăm că IDS-ul e accesibil (trimitem un pachet de test)
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_socket.close()

    if args.mode == "fast_scan":
        test_fast_scan(args.host, args.port, args.ip, args.delay, args.coalesce, args.verbose)

    elif args.mode == "slow_scan":
        test_slow_scan(args.host, args.port, args.ip, args.verbose)

    elif args.mode == "cef_log":
        test_cef_log(args.host, args.port, args.ip, args.verbose)

    elif args.mode == "normal":
        test_normal_traffic(args.host, args.port, args.ip, args.verbose)

    elif args.mode == "all":
        # IP-uri diferite pentru fiecare test (nu se interferează)
        test_normal_traffic(args.host, args.port, "192.168.1.1",  args.verbose)
        test_cef_log(       args.host, args.port, "192.168.1.2",  args.verbose)
        test_fast_scan(     args.host, args.port, args.ip, args.delay, args.coalesce, args.verbose)


if __name__ == "__main__":
    main()
