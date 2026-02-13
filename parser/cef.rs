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
/// # Notă de implementare
/// Acest parser este un **schelet** (skeleton) gata de extins.
/// Logica de bază pentru extragerea câmpurilor standard CEF este implementată.
/// Câmpuri suplimentare specifice vendor-ului pot fi adăugate ulterior.
pub struct CefParser;

impl CefParser {
    pub fn new() -> Self {
        CefParser
    }

    /// Verifică dacă un string este un log CEF valid
    fn is_cef(line: &str) -> bool {
        line.trim_start().starts_with("CEF:")
    }

    /// Parsează header-ul CEF (primele 8 câmpuri separate de `|`)
    ///
    /// Returnează numărul de câmpuri header parsate sau None dacă formatul e invalid.
    fn parse_header(line: &str) -> Option<(u8, String, String, String, String, String, u8)> {
        // Separăm header-ul de extensie: primele 8 câmpuri, ultima parte = extension
        let parts: Vec<&str> = line.splitn(8, '|').collect();

        if parts.len() < 8 {
            return None;
        }

        // parts[0] = "CEF:0" -> extragem versiunea
        let version: u8 = parts[0]
            .trim_start_matches("CEF:")
            .parse()
            .ok()?;

        Some((
            version,
            parts[1].to_string(), // Device Vendor
            parts[2].to_string(), // Device Product
            parts[3].to_string(), // Device Version
            parts[4].to_string(), // Signature ID
            parts[5].to_string(), // Name
            parts[6].trim().parse().unwrap_or(5), // Severity (default 5)
        ))
    }
}

impl LogParser for CefParser {
    fn name(&self) -> &str {
        "ArcSight CEF"
    }

    fn parse(&self, line: &str) -> Option<LogEntry> {
        let line = line.trim();

        // Verificăm că este un log CEF valid
        if !Self::is_cef(line) {
            return None;
        }

        // Parsăm header-ul pentru validare (rezultatul poate fi extins)
        // Deocamdată nu folosim toate câmpurile header-ului, dar le validăm
        let _header = Self::parse_header(line)?;

        // Extragem câmpurile din extensia CEF (ultima parte după al 8-lea `|`)
        // Regex-urile caută perechi key=value specifice
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

        // Extragem acțiunea; dacă nu există, nu putem evalua relevanța
        let action = CEF_ACT_REGEX
            .captures(line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_lowercase())
            .unwrap_or_else(|| "unknown".to_string());

        // Filtrăm acțiunile irelevante (ne interesează drop/deny)
        // CEF folosește "drop" sau "deny" în funcție de vendor
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
