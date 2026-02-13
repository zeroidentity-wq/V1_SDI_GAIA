// ============================================================
//  state.rs - Starea shared a IDS-ului (thread-safe)
// ============================================================
//
//  Concepte Rust demonstrate:
//  - `Arc<T>` (Atomic Reference Counting): pointer inteligent pentru
//    partajarea ownership-ului între thread-uri. `Arc` numără referințele
//    atomic (thread-safe), eliberând memoria când ultima referință dispare.
//  - `DashMap<K, V>`: HashMap concurrent care permite citire/scriere
//    simultană din multiple thread-uri fără un Mutex global.
//    Internamente folosește "sharding" (lock per grup de chei).
//  - `Clone` derivat: clonarea unui `Arc` nu copiează datele,
//    ci incrementează atomic contorul de referințe.
//  - `Instant`: timp monoton (nu poate da înapoi) - ideal pentru măsurarea intervalelor
// ============================================================

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Un eveniment de scan: portul văzut + momentul exact al observării
//
// `Instant` NU este un timestamp absolut (nu știe data/ora).
// Este un punct pe o linie de timp monotonă - perfect pentru calcule
// de interval (ex: "a trecut X secunde de la eveniment?")
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct ScanEvent {
    pub port:      u16,
    pub seen_at:   Instant,
}

// ---------------------------------------------------------------------------
// Starea internă a IDS-ului
//
// `Arc<DashMap<K, V>>` este patternul clasic Rust pentru state shared:
//  - `DashMap` permite accesul concurrent (multiple thread-uri citesc/scriu)
//  - `Arc` permite clone-ul ieftin (fără copiere de date) și distribuirea
//    între thread-uri (satisface `Send + Sync`)
//
// `#[derive(Clone)]` pe structură cu câmpuri `Arc` este ieftin:
// clonează doar Arc-ul (incrementează contorul), nu datele subiacente.
// ---------------------------------------------------------------------------
#[derive(Clone)]
pub struct SharedState {
    /// Istoricul evenimentelor per IP sursă
    /// Key: IP sursă | Value: lista evenimentelor de scan (port + timestamp)
    pub scan_map: Arc<DashMap<IpAddr, Vec<ScanEvent>>>,

    /// Cooldown pentru alerte: previne spam-ul de alerte pentru același IP
    /// Key: IP sursă | Value: momentul ultimei alerte trimise
    pub alert_cooldown: Arc<DashMap<IpAddr, Instant>>,
}

impl SharedState {
    /// Creează o nouă instanță de stare goală
    pub fn new() -> Self {
        SharedState {
            scan_map:       Arc::new(DashMap::new()),
            alert_cooldown: Arc::new(DashMap::new()),
        }
    }

    // -----------------------------------------------------------------------
    // Înregistrează un eveniment de scan pentru un IP
    //
    // `.entry(ip)` returnează un `Entry` (similar cu HashMap::entry)
    // `.or_insert_with(Vec::new)` inserează un Vec gol dacă cheia nu există
    // `.push(...)` adaugă evenimentul în vector
    //
    // DashMap garantează că operația este atomică per-shard.
    // -----------------------------------------------------------------------
    pub fn record_event(&self, ip: IpAddr, port: u16) {
        self.scan_map
            .entry(ip)
            .or_insert_with(Vec::new)
            .push(ScanEvent {
                port,
                seen_at: Instant::now(),
            });
    }

    // -----------------------------------------------------------------------
    // Returnează numărul de porturi UNICE accesate de un IP
    // într-o fereastră de timp specificată (în secunde)
    //
    // `window_secs`: numărul de secunde înapoi în care ne uităm
    //
    // Algoritmul:
    //   1. Filtrăm evenimentele mai vechi decât fereastra
    //   2. Colectăm porturile unice folosind un set de deduplicare
    //   3. Returnăm numărul de porturi unice
    // -----------------------------------------------------------------------
    pub fn unique_ports_in_window(&self, ip: &IpAddr, window_secs: u64) -> usize {
        let window = Duration::from_secs(window_secs);
        let now = Instant::now();

        // `get(ip)` returnează Option<Ref<'_, IpAddr, Vec<ScanEvent>>>
        // Dacă IP-ul nu există, returnăm 0 direct cu `?`... dar nu putem
        // folosi `?` pe Option în funcție care returnează usize.
        // Folosim `if let` sau `.map_or`:
        match self.scan_map.get(ip) {
            None => 0,
            Some(events) => {
                // Iterăm evenimentele, filtrăm pe fereastra de timp,
                // colectăm porturile unice într-un HashSet
                let unique: std::collections::HashSet<u16> = events
                    .iter()
                    .filter(|e| {
                        // `now.duration_since(e.seen_at)` calculează intervalul
                        // Dacă seen_at este în fereastra, păstrăm evenimentul
                        now.duration_since(e.seen_at) <= window
                    })
                    .map(|e| e.port)
                    .collect();
                unique.len()
            }
        }
    }

    // -----------------------------------------------------------------------
    // Verifică dacă un IP este în cooldown (am trimis deja o alertă recent)
    //
    // Returnează `true` dacă NU trebuie să trimitem alertă (suntem în cooldown)
    // -----------------------------------------------------------------------
    pub fn is_in_cooldown(&self, ip: &IpAddr, cooldown_secs: u64) -> bool {
        match self.alert_cooldown.get(ip) {
            None => false, // Nicio alertă anterioară => putem alerta
            Some(last_alert) => {
                Instant::now().duration_since(*last_alert) < Duration::from_secs(cooldown_secs)
            }
        }
    }

    /// Marchează un IP ca "alertat" - resetează cooldown-ul
    pub fn mark_alerted(&self, ip: IpAddr) {
        self.alert_cooldown.insert(ip, Instant::now());
    }

    // -----------------------------------------------------------------------
    // Cleanup periodic: șterge intrările IP-urilor pentru care nu au sosit
    // evenimente de mai mult de `max_age_secs` secunde.
    //
    // Returnează numărul de IP-uri eliminate (pentru logging).
    //
    // Fără cleanup, DashMap ar crește nelimitat în memorie (memory leak lent).
    // -----------------------------------------------------------------------
    pub fn cleanup_old_entries(&self, max_age_secs: u64) -> usize {
        let max_age = Duration::from_secs(max_age_secs);
        let now = Instant::now();
        let mut removed = 0;

        // `retain` parcurge DashMap și păstrează doar intrările pentru care
        // closure-ul returnează `true`. Aceasta este o operație de cleanup in-place.
        self.scan_map.retain(|_ip, events| {
            // Dacă cel mai recent eveniment e mai vechi decât max_age, eliminăm IP-ul
            let is_fresh = events
                .iter()
                .any(|e| now.duration_since(e.seen_at) <= max_age);

            if !is_fresh {
                removed += 1;
            }
            is_fresh
        });

        // Cleanup și cooldown-uri expirate
        self.alert_cooldown.retain(|_ip, last_alert| {
            now.duration_since(*last_alert) < max_age
        });

        removed
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}
