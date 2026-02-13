// ============================================================
//  alert.rs - Trimiterea alertelor (SIEM UDP + Email)
// ============================================================
//
//  Concepte Rust demonstrate:
//  - Funcții `async` și `await`: programare asincronă non-blocantă
//  - `anyhow::Result` pentru gestionarea erorilor din funcții async
//  - `tokio::net::UdpSocket` pentru comunicare UDP asincronă
//  - Crate-ul `lettre` pentru trimiterea email-urilor
// ============================================================

use crate::config::{Config, EmailConfig, SiemConfig};
use crate::detector::DetectionResult;
use crate::display;
use anyhow::{Context, Result};
use chrono::Utc;
use std::net::IpAddr;
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Payload-ul unei alerte: toate informațiile necesare pentru notificare
// ---------------------------------------------------------------------------
pub struct AlertPayload<'a> {
    pub ip:     &'a IpAddr,
    pub result: &'a DetectionResult,
}

// ---------------------------------------------------------------------------
// Funcția principală de alertare - orchestrează SIEM + Email
//
// `async fn` = funcție asincronă. Când apelăm `.await`, cedăm controlul
// executor-ului (tokio), care poate rula alt task între timp.
// Aceasta permite scalabilitate masivă fără thread-uri separate per conexiune.
// ---------------------------------------------------------------------------
pub async fn send_alerts(payload: &AlertPayload<'_>, config: &Config) {
    // Construim mesajul de alertă o singură dată și îl refolosim
    let alert_msg = build_alert_message(payload);

    // Trimitem alert la SIEM via UDP (nu blocăm dacă SIEM-ul nu răspunde)
    if let Err(e) = send_siem_alert(&alert_msg, &config.siem).await {
        display::log_warn(&format!("Nu s-a putut trimite alerta SIEM: {}", e));
    } else {
        display::log_alert_sent(&config.siem_addr(), "SIEM UDP");
    }

    // Trimitem email dacă este activat în configurație
    if config.email.enabled {
        if let Err(e) = send_email_alert(&alert_msg, payload, &config.email).await {
            display::log_warn(&format!("Nu s-a putut trimite email-ul de alertă: {}", e));
        } else {
            display::log_alert_sent(&config.email.to, "Email");
        }
    }
}

// ---------------------------------------------------------------------------
// Construiește mesajul de alertă în format CEF (pentru SIEM)
//
// Formatul CEF este standardul de facto pentru SIEM-uri.
// Structura: CEF:Version|Vendor|Product|Version|SigID|Name|Severity|Extension
// ---------------------------------------------------------------------------
fn build_alert_message(payload: &AlertPayload<'_>) -> String {
    let ts = Utc::now().format("%b %d %H:%M:%S").to_string();
    let hostname = "rust-ids";

    let (sig_id, name, severity, extension) = match payload.result {
        DetectionResult::FastScan { ports, window_secs } => (
            "IDS001",
            "Fast Port Scan Detected",
            8,
            format!(
                "src={} cs1Label=ScanType cs1=FastScan cs2Label=UniquePorts cs2={} cs3Label=WindowSecs cs3={}",
                payload.ip, ports, window_secs
            ),
        ),
        DetectionResult::SlowScan { ports, window_mins } => (
            "IDS002",
            "Slow Port Scan Detected",
            6,
            format!(
                "src={} cs1Label=ScanType cs1=SlowScan cs2Label=UniquePorts cs2={} cs3Label=WindowMins cs3={}",
                payload.ip, ports, window_mins
            ),
        ),
        DetectionResult::BothScans { fast_ports, slow_ports } => (
            "IDS003",
            "Combined Fast+Slow Port Scan Detected",
            9,
            format!(
                "src={} cs1Label=ScanType cs1=FastAndSlowScan cs2Label=FastPorts cs2={} cs3Label=SlowPorts cs3={}",
                payload.ip, fast_ports, slow_ports
            ),
        ),
        DetectionResult::Clean => unreachable!("Nu se trimite alertă pentru Clean"),
    };

    // Header Syslog + payload CEF
    format!(
        "{} {} CEF:0|RustIDS|NetworkScanner|0.1.0|{}|{}|{}|{}",
        ts, hostname, sig_id, name, severity, extension
    )
}

// ---------------------------------------------------------------------------
// Trimite alerta la SIEM via UDP
//
// UDP este ales deliberat pentru SIEM-uri: este lightweight, non-blocking,
// și SIEM-urile sunt proiectate să primească fluxuri mari de mesaje UDP.
// Pierderea ocazională a unui pachet este acceptabilă în acest context.
// ---------------------------------------------------------------------------
async fn send_siem_alert(message: &str, siem_config: &SiemConfig) -> Result<()> {
    // Cream un socket UDP etalon. "0.0.0.0:0" = orice interfață, port aleatoriu
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Nu s-a putut crea socket UDP pentru SIEM")?;

    let siem_addr = format!("{}:{}", siem_config.address, siem_config.port);

    socket
        .send_to(message.as_bytes(), &siem_addr)
        .await
        .with_context(|| format!("Nu s-a putut trimite la SIEM {}", siem_addr))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Trimite email de alertă folosind lettre (SMTP async)
//
// Lettre este crate-ul standard Rust pentru email.
// Versiunea 0.11 suportă async/tokio nativ.
// ---------------------------------------------------------------------------
async fn send_email_alert(
    alert_msg: &str,
    payload:   &AlertPayload<'_>,
    email_cfg: &EmailConfig,
) -> Result<()> {
    use lettre::{
        message::header::ContentType,
        transport::smtp::authentication::Credentials,
        AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    };

    let scan_type = payload.result.scan_type_label();

    let email_body = format!(
        "RUST IDS ALERT\n\
        ========================\n\
        Timestamp:  {}\n\
        IP Sursă:   {}\n\
        Tip Scan:   {}\n\
        \n\
        Mesaj CEF:\n\
        {}\n\
        \n\
        Acțiune recomandată: Investigați imediat IP-ul sursă.",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        payload.ip,
        scan_type,
        alert_msg
    );

    // Construim mesajul email
    // `.parse()` pe adrese email returnează Result - folosim `?` pentru propagare
    let email = Message::builder()
        .from(email_cfg.from.parse().context("Adresă 'from' invalidă")?)
        .to(email_cfg.to.parse().context("Adresă 'to' invalidă")?)
        .subject(format!("[IDS ALERT] {} detectat de la {}", scan_type, payload.ip))
        .header(ContentType::TEXT_PLAIN)
        .body(email_body)
        .context("Nu s-a putut construi email-ul")?;

    // Creăm transportul SMTP cu autentificare
    let creds = Credentials::new(
        email_cfg.username.clone(),
        email_cfg.password.clone(),
    );

    let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&email_cfg.smtp_server)
        .context("SMTP relay configuration failed")?
        .credentials(creds)
        .port(email_cfg.smtp_port)
        .build();

    transport
        .send(email)
        .await
        .context("Trimiterea email-ului SMTP a eșuat")?;

    Ok(())
}
