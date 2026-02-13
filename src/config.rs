// ============================================================
//  config.rs - Structurile de configurare și încărcarea TOML
// ============================================================
//
//  Concepte Rust demonstrate aici:
//  - #[derive(...)] : generare automată de implementări de trait-uri
//  - serde::Deserialize : permite conversie automată TOML/JSON -> struct
//  - Result<T, E> : tipul idiomatic Rust pentru operații care pot eșua
//  - anyhow::Result : un Result cu tipul de eroare dinamic (Box<dyn Error>)
// ============================================================

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

// ---------------------------------------------------------------------------
// Structura principală de configurare
//
// `#[derive(Deserialize)]` instruiește compilatorul (via macro procedural)
// să genereze automat codul necesar pentru a deserializa această structură
// dintr-un format suportat de serde (în cazul nostru, TOML).
//
// `Debug` permite afișarea cu {:?} și `Clone` permite copierea structurii.
// ---------------------------------------------------------------------------
#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub listener:  ListenerConfig,
    pub detection: DetectionConfig,
    pub siem:      SiemConfig,
    pub email:     EmailConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ListenerConfig {
    /// Adresa IP pe care IDS-ul ascultă (ex: "0.0.0.0" pentru toate interfețele)
    pub bind_address: String,

    /// Portul UDP pe care sosesc log-urile de firewall
    pub port: u16,

    /// Tipul de parser: "gaia" sau "cef"
    pub parser: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DetectionConfig {
    /// Fast Scan: câte porturi unice trebuie accesate ca să se declanșeze alerta
    pub fast_scan_ports: usize,

    /// Fast Scan: fereastra de timp în secunde
    pub fast_scan_window_secs: u64,

    /// Slow Scan: câte porturi unice trebuie accesate ca să se declanșeze alerta
    pub slow_scan_ports: usize,

    /// Slow Scan: fereastra de timp în minute
    pub slow_scan_window_mins: u64,

    /// Cât de des (în secunde) rulează task-ul de curățare a stării interne
    pub cleanup_interval_secs: u64,

    /// Cooldown în secunde între alerte pentru același IP (previne spam)
    pub alert_cooldown_secs: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SiemConfig {
    /// IP-ul sau hostname-ul SIEM-ului ArcSight
    pub address: String,

    /// Portul UDP al SIEM-ului
    pub port: u16,
}

#[derive(Deserialize, Debug, Clone)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port:   u16,
    pub username:    String,
    pub password:    String,
    pub from:        String,
    pub to:          String,
    /// Dacă false, email-urile NU se trimit (util pentru development/testare)
    pub enabled:     bool,
}

impl Config {
    // ---------------------------------------------------------------------------
    // Metoda asociată (associated function) - nu primește `self`, deci este
    // echivalentul unui "static method" din alte limbaje.
    //
    // `anyhow::Result<Self>` înseamnă "returnează un Config sau o eroare
    // cu context descriptiv". Operatorul `?` propagă automat erorile în sus.
    // ---------------------------------------------------------------------------
    pub fn load(path: &str) -> Result<Self> {
        // `fs::read_to_string` returnează Result<String, io::Error>
        // `.context(...)` adaugă un mesaj descriptiv în caz de eroare
        // `?` dezambalează Ok(val) sau propagă eroarea la apelant
        let content = fs::read_to_string(path)
            .with_context(|| format!("Nu s-a putut citi fișierul de configurare: '{}'", path))?;

        // `toml::from_str` returnează Result<Config, toml::de::Error>
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Eroare la parsarea TOML din '{}'", path))?;

        Ok(config)
    }

    /// Returnează adresa completă a listener-ului UDP (ex: "0.0.0.0:5555")
    pub fn listener_addr(&self) -> String {
        format!("{}:{}", self.listener.bind_address, self.listener.port)
    }

    /// Returnează adresa completă a SIEM-ului (ex: "127.0.0.1:514")
    pub fn siem_addr(&self) -> String {
        format!("{}:{}", self.siem.address, self.siem.port)
    }

    /// Returnează fereastra slow scan convertită în secunde
    pub fn slow_scan_window_secs(&self) -> u64 {
        self.detection.slow_scan_window_mins * 60
    }
}
