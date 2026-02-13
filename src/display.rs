// ============================================================
//  display.rs - Output vizual în consolă (Modern CLI UX)
// ============================================================
//
//  Concepte Rust demonstrate aici:
//  - Funcții libere (nu sunt metode ale unui struct)
//  - Trăsătura Display implementată prin crate-ul `colored`
//  - `&str` vs `String`: &str este o referință împrumutată la date UTF-8
//  - Macro-ul `format!` pentru construire de String-uri
// ============================================================

use chrono::Local;
use colored::Colorize;

// Lățimea separatorului orizontal (în caractere)
const SEPARATOR_WIDTH: usize = 70;

// ---------------------------------------------------------------------------
// Banner-ul de pornire al aplicației
//
// `r#"..."#` = raw string literal: nu necesită escape pentru backslash/ghilimele
// Caracterele box-drawing (╔, ═, etc.) sunt Unicode standard
// ---------------------------------------------------------------------------
pub fn print_banner() {
    let border = "═".repeat(SEPARATOR_WIDTH - 2);
    println!();
    println!("{}", format!("╔{}╗", border).bold().cyan());
    println!(
        "{}",
        format!(
            "║{:^width$}║",
            "RUST INTRUSION DETECTION SYSTEM  v0.1.0",
            width = SEPARATOR_WIDTH - 2
        )
        .bold()
        .cyan()
    );
    println!(
        "{}",
        format!(
            "║{:^width$}║",
            "Network Port Scan Detector  |  RHEL 9.6",
            width = SEPARATOR_WIDTH - 2
        )
        .cyan()
    );
    println!("{}", format!("╚{}╝", border).bold().cyan());
    println!();
}

/// Linie separatoare orizontală pentru lizibilitate vizuală
pub fn print_separator() {
    let line = "─".repeat(SEPARATOR_WIDTH);
    println!("{}", line.dimmed());
}

// ---------------------------------------------------------------------------
// Funcții de logging cu nivel și culori semantice
//
// Observați: toate funcțiile primesc `&str` (string slice, referință),
// nu `String` (owned). Aceasta este practica idiomatică Rust:
//   - `&str` = "împrumutăm" stringul, nu îl preluăm în proprietate
//   - mai eficient (nu copiezi date) și mai flexibil (acceptă &String, &str literal)
// ---------------------------------------------------------------------------

/// Mesaj informațional - verde, pentru operații normale
pub fn log_info(msg: &str) {
    let ts = timestamp();
    println!(
        "{} {} {}",
        ts.bold().white(),
        " INFO ".on_green().black().bold(),
        msg.white()
    );
}

/// Avertisment - galben, pentru situații care merită atenție
pub fn log_warn(msg: &str) {
    let ts = timestamp();
    println!(
        "{} {} {}",
        ts.bold().white(),
        " WARN ".on_yellow().black().bold(),
        msg.yellow()
    );
}

/// Eroare - roșu aprins, pentru eșecuri non-fatale
pub fn log_error(msg: &str) {
    let ts = timestamp();
    eprintln!(
        "{} {} {}",
        ts.bold().white(),
        " ERR  ".on_red().white().bold(),
        msg.red()
    );
}

/// Mesaj de debug - albastru deschis, afișat doar dacă RUST_LOG=debug
/// În producție, aceste mesaje sunt suprimate de tracing subscriber
pub fn log_debug(msg: &str) {
    let ts = timestamp();
    println!(
        "{} {} {}",
        ts.dimmed(),
        "[DEBUG]".blue(),
        msg.bright_blue()
    );
}

// ---------------------------------------------------------------------------
// Funcțiile de alertă - cel mai înalt nivel de vizibilitate
//
// Utilizăm `&std::net::IpAddr` pentru parametrul IP, nu &str,
// pentru a forța tipizare corectă (nu orice string poate fi IP valid).
// ---------------------------------------------------------------------------

/// Alertă Fast Scan - fundal roșu intens, imposibil de ratat
pub fn log_fast_scan_alert(ip: &std::net::IpAddr, ports: usize, window_secs: u64) {
    let ts = timestamp();
    let separator = "▶".repeat(3);

    println!();
    println!("{}", "─".repeat(SEPARATOR_WIDTH).red());
    println!(
        "{} {} {} [FAST SCAN] {} | {} porturi unice in {}s",
        ts.bold().white(),
        separator.red().bold(),
        " ALERT ".on_red().white().bold(),
        format!("[IP: {}]", ip).red().bold(),
        format!("{}", ports).red().bold(),
        window_secs
    );
    println!("{}", "─".repeat(SEPARATOR_WIDTH).red());
    println!();
}

/// Alertă Slow Scan - roșu, mai puțin urgent dar la fel de periculos
pub fn log_slow_scan_alert(ip: &std::net::IpAddr, ports: usize, window_mins: u64) {
    let ts = timestamp();
    let separator = "▶".repeat(3);

    println!();
    println!("{}", "─".repeat(SEPARATOR_WIDTH).yellow());
    println!(
        "{} {} {} [SLOW SCAN] {} | {} porturi unice in {}min",
        ts.bold().white(),
        separator.yellow().bold(),
        " ALERT ".on_yellow().black().bold(),
        format!("[IP: {}]", ip).yellow().bold(),
        format!("{}", ports).yellow().bold(),
        window_mins
    );
    println!("{}", "─".repeat(SEPARATOR_WIDTH).yellow());
    println!();
}

/// Confirmă că o alertă a fost trimisă cu succes (verde subtil)
pub fn log_alert_sent(destination: &str, alert_type: &str) {
    let ts = timestamp();
    println!(
        "{} {} Alert '{}' transmis -> {}",
        ts.dimmed(),
        "[SENT]".bold().green(),
        alert_type.green(),
        destination.green().underline()
    );
}

/// Logarea unui eveniment de pachet primit (drop firewall) - albastru subtil
pub fn log_drop_event(ip: &std::net::IpAddr, port: u16) {
    let ts = timestamp();
    println!(
        "{} {} Src={} DstPort={}",
        ts.dimmed(),
        "[DROP]".blue(),
        format!("{}", ip).bright_blue(),
        format!("{}", port).bright_blue()
    );
}

/// Logarea cleanup-ului periodic
pub fn log_cleanup(removed_ips: usize) {
    let ts = timestamp();
    println!(
        "{} {} {} intrari de IP vechi eliminate din memorie",
        ts.dimmed(),
        "[CLEANUP]".cyan(),
        format!("{}", removed_ips).bold().cyan()
    );
}

// ---------------------------------------------------------------------------
// Funcție helper privată: returnează timestamp-ul curent formatat
//
// `-> String` înseamnă că funcția returnează un String owned (alocat pe heap)
// `Local::now()` returnează data/ora locală, `.format(...)` o formatează
// ---------------------------------------------------------------------------
fn timestamp() -> String {
    Local::now().format("[%Y-%m-%d %H:%M:%S]").to_string()
}
