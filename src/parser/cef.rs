// ============================================================
//  parser/cef.rs - Parser CEF (Common Event Format) - ArcSight
// ============================================================
//
//  Formatul CEF urmează schema:
//  CEF:Version|Device Vendor|Device Product|Device Version|
//      SignatureID|Name|Severity|Extension
//
//  Exemplu log CEF:
//  CEF:0|Checkpoint|VPN-1 & FireWall-1|NGX R65|firewall|
//      Log message|5|src=192.168.1.10 dst=10.0.0.1 dpt=80 act=Drop
//
//  Câmpuri relevante din Extension:
//    src  = IP sursă
//    dpt  = destination port
//    act  = acțiunea (Drop, Allow, etc.)
//
//  Concepte Rust demonstrate:
//  - Implementare parțială a unui trait (schelet pentru extensie viitoare)
//  - `todo!()` macro: panică cu mesaj clar "funcționalitate neimplementată"
//  - Documentație inline cu `///` (rustdoc)
// ============================================================

use super::{LogEntry, LogParser};
use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use std::net::IpAddr;

// Regex pentru extragerea câmpurilor din extensia CEF
// Formatul extensiei: key=value perechi separate prin spații
static CEF_SRC_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"src=([\d.]+)").expect("CEF_SRC_REGEX invalid"));

static CEF_DPT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"dpt=(\d+)").expect("CEF_DPT_REGEX invalid"));

static CEF_ACT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"act=(\w+)").expect("CEF_ACT_REGEX invalid"));

/// Parser pentru formatul Common Event Format (CEF) utilizat de ArcSight.
///
/// Gestionează ambele forme de log:
///   - CEF pur:       `CEF:0|Vendor|...|ext`
///   - Syslog + CEF:  `Nov 20 15:30:00 host CEF:0|Vendor|...|ext`
///
/// Log-urile reale ce vin din syslog / firewall au întotdeauna prefix de
/// timestamp + hostname înaintea payload-ului CEF. Parser-ul detectează
/// și extrage portul CEF din linie indiferent de prefix.
pub struct CefParser;

impl CefParser {
    pub fn new() -> Self {
        CefParser
    }

    // -----------------------------------------------------------------------
    // BUG FIX #1: `starts_with("CEF:")` eșua pentru orice log primit prin
    // syslog, deoarece linia arată astfel:
    //   "Nov 20 15:30:00 firewall CEF:0|Checkpoint|..."
    //              ↑ prefix syslog — parser-ul respingea totul!
    //
    // Soluție: `contains("CEF:")` găsește token-ul oriunde în linie.
    // -----------------------------------------------------------------------
    fn is_cef(line: &str) -> bool {
        line.contains("CEF:")
    }

    // -----------------------------------------------------------------------
    // BUG FIX #2: `parse_header` primea întreaga linie syslog și o spărgea
    // după `|`. Primul element era "Nov 20 15:30:00 firewall CEF:0",
    // iar `.trim_start_matches("CEF:")` nu funcționa, deci versiunea era
    // unparseable -> `None` -> parser-ul returna `None` pentru orice linie.
    //
    // Soluție: extragem mai întâi DOAR porțiunea `CEF:0|...|extension`
    // folosind `find("CEF:")`, apoi lucrăm doar cu aceasta.
    // -----------------------------------------------------------------------
    fn extract_cef_portion(line: &str) -> Option<&str> {
        // `find` returnează Option<usize> - indexul primei apariții a "CEF:"
        // Dacă nu există, returnăm None direct cu `?`
        let cef_start = line.find("CEF:")?;

        // Slice-ul de la indexul găsit până la sfârșit
        // `&line[cef_start..]` este O(1) — nu copiază date, referință la aceeași memorie
        Some(&line[cef_start..])
    }

    /// Validează că porțiunea CEF are structura corectă (min. 8 câmpuri `|`)
    fn validate_header(cef_portion: &str) -> bool {
        // Un CEF valid are exact 7 separatoare `|` pentru cele 8 câmpuri de header
        // (ultimul câmp = extensia, poate conține orice)
        cef_portion.splitn(8, '|').count() >= 7
    }
}

impl LogParser for CefParser {
    fn name(&self) -> &str {
        "ArcSight CEF"
    }

    fn parse(&self, line: &str) -> Option<LogEntry> {
        let line = line.trim();

        // Pasul 1: verificăm că linia conține un payload CEF (oriunde în linie)
        if !Self::is_cef(line) {
            return None;
        }

        // Pasul 2: extragem DOAR porțiunea CEF (fără prefix syslog)
        let cef_portion = Self::extract_cef_portion(line)?;

        // Pasul 3: validăm structura minimă a header-ului CEF
        if !Self::validate_header(cef_portion) {
            return None;
        }

        // Pasul 4: extragem câmpurile din extensia CEF cu regex-uri key=value.
        // Regex-urile caută în întreaga linie (nu doar în cef_portion) pentru că
        // `src=`, `dpt=`, `act=` se află în extension, după ultimul `|`.
        // Căutăm în `line` original pentru a beneficia de indexarea suplimentară.
        let source_ip: IpAddr = CEF_SRC_REGEX
            .captures(line)?
            .get(1)?
            .as_str()
            .parse()
            .ok()?;

        let dest_port: u16 = CEF_DPT_REGEX
            .captures(line)?
            .get(1)?
            .as_str()
            .parse()
            .ok()?;

        // Extragem acțiunea (case-insensitive: "Drop", "DROP", "drop" sunt toate valide)
        let action = CEF_ACT_REGEX
            .captures(line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_lowercase())
            .unwrap_or_else(|| "unknown".to_string());

        // Filtrăm: ne interesează doar acțiuni de blocare
        // Checkpoint CEF folosește "drop", alte vendor-uri pot folosi "deny"
        if action != "drop" && action != "deny" {
            return None;
        }

        Some(LogEntry {
            source_ip,
            dest_port,
            action,
            timestamp: Utc::now(),
        })
    }
}
