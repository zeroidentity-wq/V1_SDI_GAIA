// ============================================================
//  parser/mod.rs - Trait-ul LogParser și factory-ul de parsere
// ============================================================
//
//  Concepte Rust demonstrate aici:
//  - `trait` : contractul/interfața pe care parsere trebuie să-l implementeze
//  - `Box<dyn Trait>` : pointer inteligent la un obiect trait (dynamic dispatch)
//  - `Send + Sync` : marker traits pentru thread safety
//  - `Option<T>` : tipul Rust pentru valori care pot fi absente (fără null!)
//  - Vizibilitate module: `pub mod`, `pub use`
// ============================================================

pub mod cef;
pub mod gaia;

use chrono::{DateTime, Utc};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Structura unui eveniment de log deja parsat și validat
//
// Aceasta reprezintă "contractul de date" intern al IDS-ului.
// Indiferent de formatul sursă (Gaia, CEF, etc.), odată parsat,
// orice log este reprezentat ca un `LogEntry`.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// IP-ul sursă al pachetului suspicios
    pub source_ip: IpAddr,

    /// Portul destinație scanat (ex: 22 pentru SSH)
    pub dest_port: u16,

    /// Acțiunea raportată de firewall (ex: "drop", "accept", "reject")
    pub action: String,

    /// Timestamp-ul evenimentului (UTC pentru consistență)
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Trăsătura (trait) LogParser - "interfața" pe care orice parser trebuie
// să o implementeze.
//
// `trait LogParser: Send + Sync` înseamnă că orice tip care implementează
// LogParser trebuie să fie și thread-safe:
//   - `Send`  : tipul poate fi trimis (transferat ownership) între thread-uri
//   - `Sync`  : referințele la tip pot fi partajate între thread-uri
//
// Acestea sunt "marker traits" - nu au metode, ci marchează proprietăți
// garantate de compilator.
// ---------------------------------------------------------------------------
pub trait LogParser: Send + Sync {
    // -----------------------------------------------------------------------
    // Metoda principală de parsare.
    //
    // `&self` = referință imutabilă la sine (nu mutăm parser-ul)
    // `&str`  = string slice (nu luăm ownership)
    // `Option<LogEntry>` = returnam `Some(entry)` daca parsarea reușește,
    //                      sau `None` dacă linia nu este un log valid/relevant
    //
    // Absența excepțiilor: Rust nu aruncă excepții. În schimb, funcțiile
    // returnează `Option<T>` sau `Result<T, E>` pentru a gestiona eșecuri.
    // -----------------------------------------------------------------------
    fn parse(&self, line: &str) -> Option<LogEntry>;

    /// Numele parser-ului (pentru logging și diagnostice)
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Factory function: creează parser-ul potrivit pe baza configurației
//
// `Box<dyn LogParser>` = un pointer alocat pe heap la ceva care implementează
// LogParser. "dyn" = dynamic dispatch (vtable la runtime, ca virtual în C++).
//
// De ce `Box` și nu referință? Deoarece funcția creează valoarea și
// trebuie să returneze ownership-ul. O referință ar expira imediat.
// ---------------------------------------------------------------------------
pub fn create_parser(parser_type: &str) -> Box<dyn LogParser> {
    match parser_type.to_lowercase().as_str() {
        "gaia" => Box::new(gaia::GaiaParser::new()),
        "cef" => Box::new(cef::CefParser::new()),
        unknown => {
            // Logging la stderr pentru erori de configurare
            eprintln!(
                "[CONFIG] Tip parser necunoscut '{}'. Se folosește 'gaia' implicit.",
                unknown
            );
            Box::new(gaia::GaiaParser::new())
        }
    }
}
