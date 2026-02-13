// ============================================================
//  detector.rs - Logica de detecție Fast Scan și Slow Scan
// ============================================================
//
//  Concepte Rust demonstrate:
//  - Enum-uri cu date asociate: `DetectionResult` transportă informații
//    despre tipul de scan detectat
//  - Pattern matching exhaustiv cu `match`
//  - Funcții pure (fără side-effects) - ușor de testat
// ============================================================

use crate::config::DetectionConfig;
use crate::state::SharedState;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Rezultatul unei evaluări de detecție
//
// `enum` în Rust este mult mai puternic decât în alte limbaje:
// fiecare variantă poate transporta date diferite.
// Aceasta se numește "Algebraic Data Type" sau "Sum Type".
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq)]
pub enum DetectionResult {
    /// Nicio activitate suspicioasă detectată
    Clean,

    /// Fast Scan detectat
    /// Câmpuri: ports (număr porturi unice), window_secs (fereastra de timp)
    FastScan { ports: usize, window_secs: u64 },

    /// Slow Scan detectat
    /// Câmpuri: ports (număr porturi unice), window_mins (fereastra în minute)
    SlowScan { ports: usize, window_mins: u64 },

    /// Ambele tipuri de scan detectate simultan (posibil în faza de tranziție)
    BothScans {
        fast_ports: usize,
        slow_ports:  usize,
    },
}

/// Evaluează dacă un IP a depășit pragurile de detecție.
///
/// Aceasta este o funcție pură: primește starea și configurația,
/// returnează un rezultat, fără side-effects (nu modifică nimic).
///
/// # Argumente
/// * `ip`     - IP-ul de evaluat
/// * `state`  - Starea shared (read-only în acest context)
/// * `config` - Pragurile de detecție din configurație
pub fn evaluate(ip: &IpAddr, state: &SharedState, config: &DetectionConfig) -> DetectionResult {
    // Calculăm numărul de porturi unice în fereastra Fast Scan
    let fast_ports = state.unique_ports_in_window(ip, config.fast_scan_window_secs);

    // Calculăm numărul de porturi unice în fereastra Slow Scan
    // (slow_scan_window_mins * 60 = secunde)
    let slow_window_secs = config.slow_scan_window_mins * 60;
    let slow_ports = state.unique_ports_in_window(ip, slow_window_secs);

    // Determinăm dacă pragurile sunt depășite
    let is_fast_scan = fast_ports > config.fast_scan_ports;
    let is_slow_scan = slow_ports > config.slow_scan_ports;

    // Pattern matching exhaustiv - compilatorul ne forțează să acoperim
    // TOATE combinațiile posibile (în cazul tuplelor bool, sunt 4)
    match (is_fast_scan, is_slow_scan) {
        (false, false) => DetectionResult::Clean,

        (true, false) => DetectionResult::FastScan {
            ports:       fast_ports,
            window_secs: config.fast_scan_window_secs,
        },

        (false, true) => DetectionResult::SlowScan {
            ports:       slow_ports,
            window_mins: config.slow_scan_window_mins,
        },

        // Ambele praguri depășite simultan
        (true, true) => DetectionResult::BothScans {
            fast_ports,
            slow_ports,
        },
    }
}

impl DetectionResult {
    /// Returnează `true` dacă s-a detectat un scan (oricare tip)
    pub fn is_threat(&self) -> bool {
        !matches!(self, DetectionResult::Clean)
    }

    /// Returnează tipul de scan ca string (pentru logging)
    pub fn scan_type_label(&self) -> &str {
        match self {
            DetectionResult::Clean        => "CLEAN",
            DetectionResult::FastScan { .. } => "FAST_SCAN",
            DetectionResult::SlowScan { .. } => "SLOW_SCAN",
            DetectionResult::BothScans { .. } => "FAST+SLOW_SCAN",
        }
    }
}
