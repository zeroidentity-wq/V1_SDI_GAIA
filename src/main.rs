// ============================================================
//  main.rs - Punctul de intrare al IDS-ului
// ============================================================
//
//  Concepte Rust demonstrate:
//  - `#[tokio::main]` : macro care transformă `main()` async într-o
//    funcție sincronă, pornind runtime-ul tokio
//  - `Arc<T>` : partajarea datelor imutabile între task-uri async
//  - `tokio::spawn` : lansarea de task-uri asincrone concurente
//  - Ownership în contexte async: de ce clonăm Arc-uri înainte de spawn
//  - `loop` + `.recv_from().await` : bucla principală asincronă
// ============================================================

// Declarăm modulele proiectului.
// Rustc va căuta fișierele: src/config.rs, src/display.rs, etc.
mod alert;
mod config;
mod detector;
mod display;
mod parser;
mod state;

use alert::{send_alerts, AlertPayload};
use config::Config;
use detector::evaluate;
use parser::LogParser;
use state::SharedState;

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// `#[tokio::main]` este un macro procedural care:
//   1. Creează un runtime tokio multi-threaded
//   2. Transformă `async fn main()` -> `fn main()` (sincron)
//   3. Rulează viitorul (future) returnat de `main()` până la completare
//
// Fără acest macro, nu am putea folosi `.await` la nivel de top-level.
// ---------------------------------------------------------------------------
#[tokio::main]
async fn main() -> Result<()> {
    // -----------------------------------------------------------------------
    // 1. Inițializare tracing subscriber
    //
    // `tracing-subscriber` configurează cum se afișează mesajele tracing.
    // `RUST_LOG=debug cargo run` activează nivel debug.
    // `EnvFilter` citește variabila de mediu RUST_LOG.
    // -----------------------------------------------------------------------
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rust_ids=info".parse().unwrap()),
        )
        .without_time() // Gestionăm manual timestamp-urile în display.rs
        .compact()
        .init();

    // -----------------------------------------------------------------------
    // 2. Afișăm banner-ul și încărcăm configurația
    // -----------------------------------------------------------------------
    display::print_banner();

    let config = Config::load("config.toml")
        .context("Eroare fatală: nu s-a putut încărca config.toml")?;

    display::log_info(&format!(
        "Configurație încărcată. Parser activ: [{}]",
        config.listener.parser.to_uppercase()
    ));
    display::log_info(&format!(
        "Fast Scan: >{} porturi in {}s | Slow Scan: >{} porturi in {}min",
        config.detection.fast_scan_ports,
        config.detection.fast_scan_window_secs,
        config.detection.slow_scan_ports,
        config.detection.slow_scan_window_mins
    ));

    // -----------------------------------------------------------------------
    // 3. Creăm parser-ul și starea shared
    //
    // `Arc::new(parser)` împachetează parser-ul în Arc pentru a putea fi
    // clonat (shared) între task-uri fără a copia datele.
    //
    // De ce Arc și nu simplu clone? Parser-ul implementează `Box<dyn LogParser>`.
    // Clonarea box-ului ar duplica datele (scump). Arc numără referințele atomic.
    // -----------------------------------------------------------------------
    let parser: Arc<Box<dyn LogParser>> = Arc::new(parser::create_parser(&config.listener.parser));
    display::log_info(&format!("Parser '{}' inițializat", parser.name()));

    let state = SharedState::new();

    // `Arc::new(config)` - configurația e immutabilă după inițializare,
    // deci o partajăm cu Arc (fără locks, accesul concurrent la date imutabile e safe)
    let config = Arc::new(config);

    // -----------------------------------------------------------------------
    // 4. Pornire task cleanup periodic
    //
    // `tokio::spawn` lansează un task async în background.
    // Task-ul rulează concurent cu bucla principală (nu blocant).
    //
    // IMPORTANT despre ownership:
    //   - `cleanup_state = state.clone()` -> clonăm Arc-ul (nu datele!)
    //   - Variabilele capturate de closures async trebuie să fie 'static + Send
    //   - `move` în `async move` transferă ownership-ul variabilelor capturate în task
    // -----------------------------------------------------------------------
    let cleanup_state = state.clone();
    let cleanup_interval = config.detection.cleanup_interval_secs;
    let max_age_secs = config.slow_scan_window_secs() + 120; // +2min grace period

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval));
        loop {
            // `.tick().await` așteaptă asincron până la următorul tick
            // Nu blochează thread-ul - tokio poate rula alte task-uri între timp
            interval.tick().await;

            let removed = cleanup_state.cleanup_old_entries(max_age_secs);
            if removed > 0 {
                display::log_cleanup(removed);
            }
        }
    });

    // -----------------------------------------------------------------------
    // 5. Legăm socket-ul UDP
    // -----------------------------------------------------------------------
    let bind_addr = config.listener_addr();
    let socket = UdpSocket::bind(&bind_addr)
        .await
        .with_context(|| format!("Nu s-a putut lega socket UDP pe {}", bind_addr))?;

    display::log_info(&format!("Ascult pe UDP {} ...", bind_addr));
    display::print_separator();

    // Buffer pentru datele UDP (64KB - dimensiunea maximă a unui pachet UDP)
    let mut buf = vec![0u8; 65535];

    // -----------------------------------------------------------------------
    // 6. Bucla principală de procesare
    //
    // `.recv_from().await` blochează ASYNC (nu blocant pentru thread):
    //   - Suspendă task-ul curent dacă nu sunt date disponibile
    //   - Tokio procesează alte task-uri între timp
    //   - Când sosesc date, task-ul este reprogramat pentru execuție
    // -----------------------------------------------------------------------
    loop {
        let (len, src_addr) = socket
            .recv_from(&mut buf)
            .await
            .context("Eroare la recv_from UDP")?;

        // Convertim bytes-ii la String (lossy = înlocuiește caractere invalide cu '?')
        // `to_string()` crează un String owned, necesar pentru task-ul spawn
        let raw_data = String::from_utf8_lossy(&buf[..len]).to_string();

        // -----------------------------------------------------------------------
        // Clonăm Arc-urile pentru task-ul spawned
        //
        // De ce clonăm? `tokio::spawn(async move { ... })` preia ownership-ul
        // variabilelor capturate. Dacă am muta `config` sau `state` în task,
        // nu le-am mai putea folosi în iterația următoare a buclei `loop`.
        // Arc::clone() este ieftin: O(1), incrementează atomic un contor.
        // -----------------------------------------------------------------------
        let config   = Arc::clone(&config);
        let parser   = Arc::clone(&parser);
        let state    = state.clone(); // SharedState::clone clonează Arc-urile interne

        tokio::spawn(async move {
            process_packet(&raw_data, &src_addr.to_string(), &config, &parser, &state).await;
        });
    }
}

// ---------------------------------------------------------------------------
// Procesarea unui pachet UDP primit
//
// Funcție async separată pentru claritate și testabilitate.
// Primește `&str` (referință) unde e posibil pentru a evita copieri inutile.
//
// NOTĂ despre "buffer coalescing":
// Firewall-urile pot trimite multiple log-uri într-un singur pachet UDP
// (pentru eficiență). Le separăm prin newline.
// ---------------------------------------------------------------------------
async fn process_packet(
    raw_data: &str,
    src_addr: &str,
    config:   &Arc<Config>,
    parser:   &Arc<Box<dyn LogParser>>,
    state:    &SharedState,
) {
    // Split pe newline-uri - gestionăm "buffer coalescing"
    // Un pachet poate conține 1 sau mai multe log-uri concatenate
    for line in raw_data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parsăm linia cu parser-ul activ
        // `parse()` returnează Option<LogEntry> - None dacă linia nu e relevantă
        let entry = match parser.parse(line) {
            Some(e) => e,
            None => {
                // Linia nu e un log valid sau nu e de tip "drop" - ignorăm
                continue;
            }
        };

        // Logăm evenimentul de drop (nivel debug pentru a nu polua consola)
        display::log_drop_event(&entry.source_ip, entry.dest_port);

        // Înregistrăm evenimentul în starea shared
        state.record_event(entry.source_ip, entry.dest_port);

        // Evaluăm dacă pragurile de detecție sunt depășite
        let detection = evaluate(&entry.source_ip, state, &config.detection);

        // Dacă s-a detectat o amenințare ȘI IP-ul nu e în cooldown
        if detection.is_threat() && !state.is_in_cooldown(&entry.source_ip, config.detection.alert_cooldown_secs) {
            // Marcăm IP-ul ca alertat (intrăm în cooldown)
            state.mark_alerted(entry.source_ip);

            // Afișăm alerta vizuală în consolă
            match &detection {
                detector::DetectionResult::FastScan { ports, window_secs } => {
                    display::log_fast_scan_alert(&entry.source_ip, *ports, *window_secs);
                }
                detector::DetectionResult::SlowScan { ports, window_mins } => {
                    display::log_slow_scan_alert(&entry.source_ip, *ports, *window_mins);
                }
                detector::DetectionResult::BothScans { fast_ports, .. } => {
                    // Prioritizăm afișarea Fast Scan pentru BothScans
                    display::log_fast_scan_alert(&entry.source_ip, *fast_ports, config.detection.fast_scan_window_secs);
                }
                detector::DetectionResult::Clean => unreachable!(),
            }

            // Trimitem alertele externe (SIEM + email)
            let alert_payload = AlertPayload {
                ip:     &entry.source_ip,
                result: &detection,
            };
            send_alerts(&alert_payload, config).await;
        }

        let _ = src_addr; // Suprima warning "unused" - poate fi folosit pentru logging extins
    }
}
