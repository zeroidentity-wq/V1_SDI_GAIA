# Rust IDS — Intrusion Detection System
### Network Port Scan Detector | RHEL 9.6

---

## Structura proiectului

```
ids-rust/
├── Cargo.toml              # Manifest proiect + dependențe
├── config.toml             # Configurație runtime (editați înainte de rulare)
├── tester.py               # Script Python pentru testare
└── src/
    ├── main.rs             # Entry point + bucla UDP principală
    ├── config.rs           # Structuri de configurare (serde + TOML)
    ├── display.rs          # Output consolă colorat (ANSI)
    ├── detector.rs         # Logica Fast Scan / Slow Scan
    ├── state.rs            # Stare shared thread-safe (DashMap)
    ├── alert.rs            # Trimitere alerte: SIEM UDP + Email
    └── parser/
        ├── mod.rs          # Trait LogParser + factory function
        ├── gaia.rs         # Parser Checkpoint Gaia Raw
        └── cef.rs          # Parser ArcSight CEF (schelet extensibil)
```

---

## Compilare și rulare pe RHEL 9.6

### 1. Instalare Rust (dacă nu este prezent)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup update stable
```

### 2. Dependențe de sistem (pentru OpenSSL / TLS - necesar pentru lettre)

```bash
sudo dnf install -y openssl-devel pkg-config gcc
```

### 3. Compilare

```bash
# Development build (mai rapid la compilat, mai lent la execuție)
cargo build

# Production build (optimizat, recomandat pentru server)
cargo build --release
```

Executabilul se creează la:
- Debug:   `./target/debug/rust-ids`
- Release: `./target/release/rust-ids`

### 4. Configurare

Editați `config.toml` înainte de rulare:

```toml
[listener]
parser = "gaia"        # "gaia" sau "cef"
port   = 5555

[detection]
fast_scan_ports       = 15   # Alertă la >15 porturi în 10 secunde
fast_scan_window_secs = 10
slow_scan_ports       = 30   # Alertă la >30 porturi în 60 minute
slow_scan_window_mins = 60

[email]
enabled = false        # Setați true și completați credențialele SMTP
```

### 5. Rulare

```bash
# Cu drepturi normale (portul 5555 > 1024 nu necesită root)
./target/release/rust-ids

# Cu nivel de logging verbose
RUST_LOG=debug ./target/release/rust-ids

# Ca serviciu systemd (opțional)
sudo cp target/release/rust-ids /usr/local/bin/
```

### 6. Configurare firewall RHEL (dacă e necesar)

```bash
# Permite trafic UDP pe portul 5555
sudo firewall-cmd --add-port=5555/udp --permanent
sudo firewall-cmd --reload
```

---

## Testare cu scriptul Python

```bash
# Instalare dependențe Python (niciunele externe - stdlib only)
python3 --version  # Necesită Python 3.6+

# Cu parser = "gaia" in config.toml:
python3 tester.py --mode fast_scan --format gaia

# Cu parser = "cef" in config.toml:
python3 tester.py --mode fast_scan --format cef

# Verificare ca CEF Allow nu declanseaza alerta:
python3 tester.py --mode cef_normal

# Test Fast Scan (default) - trimite 20 porturi în <2 secunde
python3 tester.py --mode fast_scan

# Test cu buffer coalescing (mai multe log-uri într-un pachet UDP)
python3 tester.py --mode fast_scan --coalesce --verbose

# Test Slow Scan (NOTĂ: ajustați slow_scan_window_mins=1 în config.toml pentru test rapid)
python3 tester.py --mode slow_scan

# Test log CEF normal (nu trebuie să declanșeze alertă)
python3 tester.py --mode cef_log

# Test complet cu IP-uri diferite
python3 tester.py --mode all --verbose

# Simulare atac de la IP specific
python3 tester.py --mode fast_scan --ip 10.0.0.200 --delay 0.01
```

---

## Exemplu output consolă

```
╔══════════════════════════════════════════════════════════════════════╗
║             RUST INTRUSION DETECTION SYSTEM  v0.1.0                ║
║             Network Port Scan Detector  |  RHEL 9.6                ║
╚══════════════════════════════════════════════════════════════════════╝

[2024-11-20 15:28:00]  INFO  Configurație încărcată. Parser activ: [GAIA]
[2024-11-20 15:28:00]  INFO  Fast Scan: >15 porturi in 10s | Slow Scan: >30 porturi in 60min
[2024-11-20 15:28:00]  INFO  Ascult pe UDP 0.0.0.0:5555 ...
──────────────────────────────────────────────────────────────────────
[2024-11-20 15:30:12] [DROP] Src=192.168.11.7 DstPort=22
[2024-11-20 15:30:12] [DROP] Src=192.168.11.7 DstPort=80
...

──────────────────────────────────────────────────────────────────────
[2024-11-20 15:30:13] ▶▶▶  ALERT  [FAST SCAN] [IP: 192.168.11.7] | 16 porturi unice in 10s
──────────────────────────────────────────────────────────────────────
```

---

Now let me create the Python tester and verify the project structure:Now let's verify the project compiles:Now let's create the README with compilation and run instructions:Now let's package everything and copy to the output directory:Proiectul complet este gata — 13 fișiere, ~850 linii de Rust comentat + tester Python. Iată un ghid rapid al arhitecturii și lecțiile Rust incluse:

---

## Ce găsești în fiecare fișier

| Fișier | Responsabilitate | Concept Rust principal |
|---|---|---|
| `main.rs` | Orchestrator: UDP listener + spawn task-uri | `#[tokio::main]`, `Arc::clone`, `async/await` |
| `config.rs` | Încărcare `config.toml` | `serde::Deserialize`, `#[derive]`, `anyhow::Result` |
| `display.rs` | Output consolă colorat ANSI | `colored` crate, funcții libere |
| `parser/mod.rs` | **Trait `LogParser`** + factory | `trait`, `Box<dyn T>`, `Send + Sync` |
| `parser/gaia.rs` | Parser Checkpoint Gaia Raw | `once_cell::Lazy<Regex>`, `Option<T>`, `?` operator |
| `parser/cef.rs` | Parser ArcSight CEF (schelet) | `impl Trait for Struct` |
| `state.rs` | Stare shared thread-safe | `Arc<DashMap>`, `Instant`, ownership vs borrowing |
| `detector.rs` | Logica Fast/Slow Scan | `enum` cu date asociate, pattern matching exhaustiv |
| `alert.rs` | SIEM UDP + email `lettre` | funcții `async`, `tokio::net::UdpSocket` |

---

## Pașii de pornire rapidă pe RHEL 9.6

```bash
# 1. Instalare Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# 2. Dependențe OpenSSL (pentru lettre TLS)
sudo dnf install -y openssl-devel pkg-config gcc

# 3. Build + rulare
cd ids-rust
cargo build --release
./target/release/rust-ids

# 4. Testare din altă sesiune
python3 tester.py --mode fast_scan --verbose
```

---

## Trei aspecte de reținut din cod

**1. Traits ca interfețe extensibile** (`parser/mod.rs`): `trait LogParser` definește contractul. Adăugarea unui parser nou pentru Palo Alto/Fortinet necesită un singur fișier nou + o linie în `match` din `create_parser()` — zero modificări în restul sistemului.

**2. Ownership fără locks** (`state.rs`): `Arc<DashMap>` oferă concurență fără `Mutex` global. DashMap shardează intern cheile, permițând scrieri simultane din sute de task-uri tokio fără contention.

**3. `Option<T>` în loc de null** (`parser/gaia.rs`): `fn parse() -> Option<LogEntry>` forțează tratarea cazului "linia nu este un log valid". Operatorul `?` pe `Option` face early-return cu `None` în mod implicit — mult mai sigur decât null pointer exceptions.

## Arhitectură — Extindere viitoare

### Adăugare parser nou (ex: Palo Alto)

1. Creați `src/parser/palo_alto.rs` implementând `LogParser` trait
2. Adăugați `pub mod palo_alto;` în `src/parser/mod.rs`
3. Adăugați ramura în `create_parser()`: `"palo_alto" => Box::new(palo_alto::PaloAltoParser::new())`
4. Setați `parser = "palo_alto"` în `config.toml`

**Zero modificări** în restul codului — aceasta este puterea trait-urilor Rust.
