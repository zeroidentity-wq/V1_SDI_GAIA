// ============================================================
//  parser/gaia.rs - Parser pentru log-urile Checkpoint Gaia Raw
// ============================================================
//
//  Format log exemplu:
//  Sep 3 15:12:20 192.168.99.1 Checkpoint: drop 192.168.11.7 proto: tcp; service: 22; s_port: 1352
//
//  Câmpuri extrase:
//    - Acțiunea : "drop" (ignorăm tot ce nu este "drop")
//    - IP sursă : 192.168.11.7
//    - Port dest.: 22 (câmpul "service:")
//
//  Concepte Rust demonstrate:
//  - `once_cell::sync::Lazy` : inițializare leneșă a regex-ului (compilat o singură dată)
//  - `impl Trait for Struct` : implementarea unui trait pentru un tip concret
//  - Destructurare: `if let Some(caps) = regex.captures(...)`
//  - Conversii de tip: `.parse::<IpAddr>()`, `.parse::<u16>()`
// ============================================================

use super::{LogEntry, LogParser};
use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// `Lazy<Regex>` = expresia regulată este compilată O SINGURĂ DATĂ,
// la prima utilizare, și reutilizată ulterior.
//
// De ce? Compilarea unui regex este costisitoare (O(n) față de dimensiunea
// pattern-ului). Dacă am compila regex-ul în fiecare apel `parse()`,
// performanța ar fi dramatică.
//
// `static` înseamnă că variabila trăiește pe toată durata programului.
// `Lazy` garantează inițializarea thread-safe (o singură dată).
// ---------------------------------------------------------------------------
static GAIA_REGEX: Lazy<Regex> = Lazy::new(|| {
    // Explicația pattern-ului:
    //   Checkpoint:\s+   -> textul literal "Checkpoint:" urmat de spații
    //   (\w+)            -> capturează acțiunea (drop, accept, reject...)
    //   \s+              -> spații
    //   ([\d.]+)         -> capturează IP-ul sursă (cifre și puncte)
    //   .*?service:\s*   -> orice caractere, ne-lacom, până la "service:"
    //   (\d+)            -> capturează portul destinație
    Regex::new(
        r"Checkpoint:\s+(\w+)\s+([\d.]+).*?service:\s*(\d+)"
    ).expect("GAIA_REGEX: pattern invalid - eroare de programare!")
    // `.expect()` e acceptabil pentru erori de programare (bug, nu eroare de runtime)
    // Dacă regex-ul e invalid, e un bug în cod, nu o eroare de utilizator.
});

// ---------------------------------------------------------------------------
// Structura concretă a parser-ului Gaia.
//
// Deocamdată nu are câmpuri (este un "unit struct" efectiv),
// dar o structurăm explicit pentru extensibilitate viitoare
// (ex: ar putea stoca configurații specifice parser-ului).
// ---------------------------------------------------------------------------
pub struct GaiaParser;

impl GaiaParser {
    /// Constructor convențional în Rust.
    /// `new()` este convenție, nu keyword; returnează instanță owned.
    pub fn new() -> Self {
        GaiaParser
    }
}

// ---------------------------------------------------------------------------
// Implementăm trait-ul `LogParser` pentru `GaiaParser`.
//
// Aceasta este "inima" arhitecturii extensibile:
// - Compilatorul verifică că am implementat TOATE metodele din trait
// - Orice cod care primește `&dyn LogParser` poate folosi un GaiaParser
//   fără să știe tipul concret
// ---------------------------------------------------------------------------
impl LogParser for GaiaParser {
    fn name(&self) -> &str {
        "Checkpoint Gaia Raw"
    }

    fn parse(&self, line: &str) -> Option<LogEntry> {
        // Ignorăm linii goale sau comentarii - early return cu None
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        // `captures()` returnează Option<Captures>
        // Dacă pattern-ul nu se potrivește, returnăm None (linia nu este un log Gaia valid)
        let caps = GAIA_REGEX.captures(line)?;
        // Nota: `?` pe Option funcționează ca un early return cu None

        // Grupele de captură sunt indexate de la 1 (0 = întregul match)
        // `.get(n)` returnează Option<Match>, `.as_str()` returnează &str

        // Extragere acțiune (câmpul 1)
        let action = caps.get(1)?.as_str().to_lowercase();

        // Filtrăm: ne interesează DOAR acțiunile "drop"
        // Logica de business: alte acțiuni (accept, log) nu sunt relevante pentru IDS
        if action != "drop" {
            return None;
        }

        // Extragere IP sursă (câmpul 2)
        // `.parse::<IpAddr>()` returnează Result<IpAddr, _>
        // `.ok()` convertește Result în Option (Err devine None)
        let source_ip: IpAddr = caps.get(2)?.as_str().parse().ok()?;

        // Extragere port destinație (câmpul 3)
        let dest_port: u16 = caps.get(3)?.as_str().parse().ok()?;

        // Construim LogEntry. Rust garantează că dacă ajungem aici,
        // toate câmpurile sunt valide (compilatorul nu permite valori lipsă/null).
        Some(LogEntry {
            source_ip,
            dest_port,
            action,
            timestamp: Utc::now(), // Folosim timestamps UTC pentru consistență
        })
    }
}
