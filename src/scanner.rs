use crate::pipeline::{http_metadata_timeout_ms, HTTP_METADATA_PORTS, TARGETED_METADATA_PORTS};
use crate::platform::{
    icmp_echo, local_networks, mac_address, reverse_dns, windows_enrichment, LocalNetwork,
    ShareInfo,
};
use crate::probes::ProbeDatabase;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Ports tried during host discovery when ICMP/ARP get no answer.
const DISCOVERY_PORTS: [u16; 5] = [445, 80, 443, 3389, 22];

/// Maximum extra wait for DNS, MAC and Windows data once ports are scanned.
const DETAIL_TIMEOUT: Duration = Duration::from_secs(8);

const MAX_HTTP_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub max_workers: usize,
    pub ports: Vec<u16>,
    pub collect_http_metadata: bool,
    pub resolve_hostnames: bool,
    pub collect_windows_enrichment: bool,
    pub probe_database: Option<Arc<ProbeDatabase>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        let mut ports = vec![80, 21, 443, 445];
        ports.extend(TARGETED_METADATA_PORTS);
        ports.extend(HTTP_METADATA_PORTS);
        ports.push(4899);
        ports.sort_unstable();
        ports.dedup();

        Self {
            connect_timeout: Duration::from_millis(700),
            read_timeout: Duration::from_millis(500),
            max_workers: 32,
            ports,
            collect_http_metadata: true,
            resolve_hostnames: true,
            collect_windows_enrichment: false,
            probe_database: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecord {
    pub port: u16,
    pub name: String,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMetadata {
    pub port: u16,
    pub status: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub authenticate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostResult {
    pub address: Ipv4Addr,
    pub reachable: bool,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub services: Vec<ServiceRecord>,
    pub http: Option<HttpMetadata>,
    pub users: Vec<String>,
    pub shares: Vec<ShareInfo>,
    pub remote_time: Option<String>,
}

pub fn scan_targets<I>(targets: I, options: ScanOptions) -> Vec<HostResult>
where
    I: IntoIterator<Item = Ipv4Addr>,
    I::IntoIter: Send + 'static,
{
    scan_targets_with_control(targets, options, Arc::new(AtomicBool::new(false)), |_| {})
}

pub fn scan_targets_with_control<I, F>(
    targets: I,
    options: ScanOptions,
    cancelled: Arc<AtomicBool>,
    mut on_result: F,
) -> Vec<HostResult>
where
    I: IntoIterator<Item = Ipv4Addr>,
    I::IntoIter: Send + 'static,
    F: FnMut(&HostResult),
{
    let targets = Arc::new(Mutex::new(targets.into_iter()));
    let worker_count = options.max_workers.max(1);
    let (sender, receiver) = mpsc::channel();
    let mut workers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let targets = Arc::clone(&targets);
        let sender = sender.clone();
        let options = options.clone();
        let cancelled = Arc::clone(&cancelled);
        workers.push(thread::spawn(move || loop {
            if cancelled.load(Ordering::Relaxed) {
                break;
            }
            let target = {
                let mut targets = targets.lock().expect("target iterator lock poisoned");
                targets.next()
            };
            let Some(target) = target else {
                break;
            };
            if sender.send(scan_target(target, &options)).is_err() {
                break;
            }
        }));
    }
    drop(sender);

    let mut results = Vec::new();
    for result in receiver {
        on_result(&result);
        results.push(result);
    }
    for worker in workers {
        worker.join().expect("scan worker panicked");
    }
    results.sort_by_key(|result| u32::from(result.address));
    results
}

pub fn scan_target(address: Ipv4Addr, options: &ScanOptions) -> HostResult {
    let responds_to_icmp = icmp_echo(address, options.connect_timeout);
    let mut services = Vec::new();

    for &port in &options.ports {
        if let Some(stream) = connect(address, port, options.connect_timeout) {
            let (name, banner) = identify_open_service(address, port, stream, options);
            services.push(ServiceRecord { port, name, banner });
        }
    }

    let http = options
        .collect_http_metadata
        .then(|| fetch_http_metadata(address, options))
        .flatten();
    let reachable = responds_to_icmp || !services.is_empty();
    let mac_address = reachable.then(|| mac_address(address)).flatten();
    let hostname = options
        .resolve_hostnames
        .then(|| reverse_dns(address))
        .flatten();
    let enrichment = if options.collect_windows_enrichment && reachable {
        windows_enrichment(address)
    } else {
        Default::default()
    };

    HostResult {
        address,
        reachable,
        mac_address,
        hostname,
        services,
        http,
        users: enrichment.users,
        shares: enrichment.shares,
        remote_time: enrichment.remote_time,
    }
}

/// Events emitted by [`scan_progressive`].
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// One target finished host discovery (alive or not).
    Probed,
    /// A live host was found; only basic data (address, MAC) is filled in.
    Found(HostResult),
    /// Service discovery for a previously found host has finished.
    Detailed(HostResult),
}

/// Two-phase scan: finds live hosts quickly, then discovers their services.
///
/// Both phases run concurrently: a host is analysed as soon as it is found.
/// Returns as soon as `cancelled` is set; background work then stops at the
/// next check point without blocking the caller.
pub fn scan_progressive<F>(
    targets: Vec<Ipv4Addr>,
    options: ScanOptions,
    cancelled: Arc<AtomicBool>,
    mut on_event: F,
) where
    F: FnMut(ScanEvent),
{
    let options = Arc::new(options);
    let networks = Arc::new(local_networks());
    let targets = Arc::new(Mutex::new(targets.into_iter()));
    let (event_sender, events) = mpsc::channel();
    let (found_sender, found) = mpsc::channel::<HostResult>();
    let found = Arc::new(Mutex::new(found));
    let workers = options.max_workers.max(1);

    for _ in 0..workers {
        let targets = Arc::clone(&targets);
        let options = Arc::clone(&options);
        let networks = Arc::clone(&networks);
        let cancelled = Arc::clone(&cancelled);
        let events = event_sender.clone();
        let found = found_sender.clone();
        thread::spawn(move || loop {
            if cancelled.load(Ordering::Relaxed) {
                break;
            }
            let Some(target) = targets.lock().ok().and_then(|mut targets| targets.next()) else {
                break;
            };
            if let Some(host) = discover_host(target, &options, &networks) {
                if events.send(ScanEvent::Found(host.clone())).is_err() {
                    break;
                }
                let _ = found.send(host);
            }
            if events.send(ScanEvent::Probed).is_err() {
                break;
            }
        });
    }
    drop(found_sender);

    for _ in 0..(workers / 2).max(1) {
        let found = Arc::clone(&found);
        let options = Arc::clone(&options);
        let cancelled = Arc::clone(&cancelled);
        let events = event_sender.clone();
        thread::spawn(move || loop {
            if cancelled.load(Ordering::Relaxed) {
                break;
            }
            let Some(host) = found.lock().ok().and_then(|found| found.recv().ok()) else {
                break;
            };
            let host = detail_host(host, &options, &cancelled);
            if cancelled.load(Ordering::Relaxed) || events.send(ScanEvent::Detailed(host)).is_err()
            {
                break;
            }
        });
    }
    drop(event_sender);

    loop {
        if cancelled.load(Ordering::Relaxed) {
            return;
        }
        match events.recv_timeout(Duration::from_millis(50)) {
            Ok(event) => on_event(event),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Fast liveness check: ICMP, ARP (local subnets only) and a few TCP ports, in parallel.
fn discover_host(
    address: Ipv4Addr,
    options: &ScanOptions,
    networks: &[LocalNetwork],
) -> Option<HostResult> {
    let local = networks.iter().any(|network| network.contains(address));
    let timeout = options.connect_timeout;
    let (alive, mac) = thread::scope(|scope| {
        let arp = local.then(|| scope.spawn(move || mac_address(address)));
        let tcp: Vec<_> = DISCOVERY_PORTS
            .iter()
            .map(|&port| scope.spawn(move || connect(address, port, timeout).is_some()))
            .collect();
        let icmp = icmp_echo(address, timeout);
        let mac = arp.and_then(|handle| handle.join().ok().flatten());
        let tcp = tcp.into_iter().any(|handle| handle.join().unwrap_or(false));
        (icmp || tcp || mac.is_some(), mac)
    });
    alive.then(|| HostResult {
        address,
        reachable: true,
        mac_address: mac,
        hostname: None,
        services: Vec::new(),
        http: None,
        users: Vec::new(),
        shares: Vec::new(),
        remote_time: None,
    })
}

/// Fills in hostname, services, HTTP and Windows data for a live host.
fn detail_host(mut host: HostResult, options: &ScanOptions, cancelled: &AtomicBool) -> HostResult {
    let address = host.address;
    // DNS and NetAPI calls cannot be interrupted and may hang for minutes on
    // some hosts, so they run detached and are abandoned after a deadline.
    let hostname = options
        .resolve_hostnames
        .then(|| run_detached(move || reverse_dns(address)));
    let enrichment = options
        .collect_windows_enrichment
        .then(|| run_detached(move || windows_enrichment(address)));
    let mac = host
        .mac_address
        .is_none()
        .then(|| run_detached(move || mac_address(address)));

    thread::scope(|scope| {
        let http = options
            .collect_http_metadata
            .then(|| scope.spawn(move || fetch_http_metadata(address, options)));
        let ports: Vec<_> = options
            .ports
            .iter()
            .map(|&port| {
                scope.spawn(move || {
                    if cancelled.load(Ordering::Relaxed) {
                        return None;
                    }
                    let stream = connect(address, port, options.connect_timeout)?;
                    let (name, banner) = identify_open_service(address, port, stream, options);
                    Some(ServiceRecord { port, name, banner })
                })
            })
            .collect();
        host.services = ports
            .into_iter()
            .filter_map(|handle| handle.join().ok().flatten())
            .collect();
        host.http = http.and_then(|handle| handle.join().ok().flatten());
    });

    let deadline = std::time::Instant::now() + DETAIL_TIMEOUT;
    fn wait<T>(receiver: mpsc::Receiver<T>, deadline: std::time::Instant) -> Option<T> {
        receiver
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .ok()
    }
    if let Some(mac) = mac.and_then(|r| wait(r, deadline)).flatten() {
        host.mac_address = Some(mac);
    }
    host.hostname = hostname.and_then(|r| wait(r, deadline)).flatten();
    if let Some(enrichment) = enrichment.and_then(|r| wait(r, deadline)) {
        host.users = enrichment.users;
        host.shares = enrichment.shares;
        host.remote_time = enrichment.remote_time;
    }
    host
}

/// Runs `work` on its own thread; the result arrives on the returned channel.
fn run_detached<T, W>(work: W) -> mpsc::Receiver<T>
where
    T: Send + 'static,
    W: FnOnce() -> T + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(work());
    });
    receiver
}

fn connect(address: Ipv4Addr, port: u16, timeout: Duration) -> Option<TcpStream> {
    let endpoint = SocketAddr::new(IpAddr::V4(address), port);
    TcpStream::connect_timeout(&endpoint, timeout).ok()
}

fn identify_open_service(
    address: Ipv4Addr,
    port: u16,
    stream: TcpStream,
    options: &ScanOptions,
) -> (String, Option<String>) {
    let should_read_passive =
        options.probe_database.is_some() || matches!(port, 21 | 22 | 25 | 110 | 143);
    let passive_banner = should_read_passive
        .then(|| read_banner_bytes(stream, options.read_timeout))
        .flatten();

    if let (Some(database), Some(response)) = (&options.probe_database, &passive_banner) {
        for probe in database
            .probes_for_tcp_port(port, 5)
            .into_iter()
            .filter(|probe| probe.name == "NULL")
        {
            if let Some(service) = probe.identify(response) {
                return (
                    resolved_service_name(port, service),
                    response_text(response),
                );
            }
        }
    }

    if let Some(database) = &options.probe_database {
        for probe in database
            .probes_for_tcp_port(port, 5)
            .into_iter()
            .filter(|probe| !probe.payload.is_empty())
            .take(3)
        {
            if let Some(response) = send_probe(address, port, &probe.payload, options) {
                if let Some(service) = probe.identify(&response) {
                    return (
                        resolved_service_name(port, service),
                        response_text(&response),
                    );
                }
                if !response.is_empty() {
                    return (service_name(port).to_owned(), response_text(&response));
                }
            }
        }
    }

    (
        service_name(port).to_owned(),
        passive_banner.as_deref().and_then(response_text),
    )
}

fn send_probe(
    address: Ipv4Addr,
    port: u16,
    payload: &[u8],
    options: &ScanOptions,
) -> Option<Vec<u8>> {
    let mut stream = connect(address, port, options.connect_timeout)?;
    stream.set_read_timeout(Some(options.read_timeout)).ok()?;
    stream.set_write_timeout(Some(options.read_timeout)).ok()?;
    stream.write_all(payload).ok()?;
    read_limited(&mut stream)
}

fn read_banner_bytes(mut stream: TcpStream, timeout: Duration) -> Option<Vec<u8>> {
    stream.set_read_timeout(Some(timeout)).ok()?;
    read_limited(&mut stream)
}

fn read_limited(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut bytes = vec![0_u8; 4096];
    let length = stream.read(&mut bytes).ok()?;
    bytes.truncate(length);
    Some(bytes)
}

fn response_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let sample = &bytes[..bytes.len().min(512)];
    let printable = sample
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\r' | b'\n' | b'\t'))
        .count();
    if printable * 100 >= sample.len() * 85 {
        clean_text(&String::from_utf8_lossy(sample))
    } else {
        Some(format!(
            "hex:{}{}",
            sample[..sample.len().min(96)]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            if bytes.len() > 96 { "…" } else { "" }
        ))
    }
}

fn fetch_http_metadata(address: Ipv4Addr, options: &ScanOptions) -> Option<HttpMetadata> {
    for port in HTTP_METADATA_PORTS {
        if let Some(metadata) = fetch_http_follow_redirects(address, port, "/", options) {
            return Some(metadata);
        }
    }
    None
}

#[cfg(test)]
fn fetch_http_once(
    address: Ipv4Addr,
    port: u16,
    path: &str,
    options: &ScanOptions,
) -> Option<HttpMetadata> {
    fetch_http_response(address, port, path, options).map(|response| response.metadata)
}

struct HttpResponse {
    metadata: HttpMetadata,
    location: Option<String>,
}

fn fetch_http_follow_redirects(
    address: Ipv4Addr,
    initial_port: u16,
    initial_path: &str,
    options: &ScanOptions,
) -> Option<HttpMetadata> {
    let mut port = initial_port;
    let mut path = initial_path.to_owned();
    for _ in 0..=5 {
        let response = fetch_http_response(address, port, &path, options)?;
        if !matches!(response.metadata.status, Some(301 | 302 | 303 | 307 | 308)) {
            return Some(response.metadata);
        }
        let (next_port, next_path) =
            parse_same_target_location(response.location.as_deref()?, address, port)?;
        port = next_port;
        path = next_path;
    }
    None
}

fn fetch_http_response(
    address: Ipv4Addr,
    port: u16,
    path: &str,
    _options: &ScanOptions,
) -> Option<HttpResponse> {
    let timeout = Duration::from_millis(http_metadata_timeout_ms(false));
    let mut stream = connect(address, port, timeout)?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {address}\r\nUser-Agent: scanner-rs/0.1\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;

    let mut bytes = Vec::new();
    stream.take(MAX_HTTP_BYTES).read_to_end(&mut bytes).ok()?;
    let response = String::from_utf8_lossy(&bytes);
    parse_http_response(port, &response)
}

#[cfg(test)]
fn parse_http_metadata(port: u16, response: &str) -> Option<HttpMetadata> {
    parse_http_response(port, response).map(|response| response.metadata)
}

fn parse_http_response(port: u16, response: &str) -> Option<HttpResponse> {
    if response.is_empty() {
        return None;
    }
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .or_else(|| response.split_once("\n\n"))
        .unwrap_or((response, ""));
    let mut lines = headers.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok());
    let mut server = None;
    let mut authenticate = None;
    let mut location = None;

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("server") {
                server = clean_text(value);
            } else if name.eq_ignore_ascii_case("www-authenticate") {
                authenticate = clean_text(value);
            } else if name.eq_ignore_ascii_case("location") {
                location = clean_text(value);
            }
        }
    }

    Some(HttpResponse {
        metadata: HttpMetadata {
            port,
            status,
            title: html_title(body),
            server,
            authenticate,
        },
        location,
    })
}

fn parse_same_target_location(
    location: &str,
    address: Ipv4Addr,
    current_port: u16,
) -> Option<(u16, String)> {
    if location.starts_with('/') {
        return Some((current_port, location.to_owned()));
    }
    let value = location.strip_prefix("http://")?;
    let (authority, path) = value.split_once('/').unwrap_or((value, ""));
    let (host, port) = authority
        .rsplit_once(':')
        .map(|(host, port)| (host, port.parse::<u16>().ok()))
        .unwrap_or((authority, Some(80)));
    if host != address.to_string() {
        return None;
    }
    Some((port?, format!("/{path}")))
}

fn html_title(body: &str) -> Option<String> {
    let lowercase = body.to_ascii_lowercase();
    let start = lowercase.find("<title")?;
    let content_start = start + lowercase[start..].find('>')? + 1;
    let content_end = content_start + lowercase[content_start..].find("</title>")?;
    clean_text(&decode_basic_entities(&body[content_start..content_end]))
}

fn decode_basic_entities(value: &str) -> String {
    value
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
}

fn clean_text(value: &str) -> Option<String> {
    let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    (!value.is_empty()).then_some(value)
}

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        139 => "netbios-ssn",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        3389 => "rdp",
        4899 => "radmin",
        8080 => "http-alt",
        _ => "unknown",
    }
}

fn resolved_service_name(port: u16, signature_service: &str) -> String {
    let known = service_name(port);
    if known == "unknown" {
        signature_service.to_owned()
    } else {
        known.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        fetch_http_follow_redirects, fetch_http_once, parse_http_metadata,
        parse_same_target_location, resolved_service_name, response_text, scan_target,
        scan_targets_with_control, ScanOptions,
    };
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn parses_http_metadata() {
        let metadata = parse_http_metadata(
            80,
            "HTTP/1.1 401 Unauthorized\r\nServer: Test Server\r\nWWW-Authenticate: Basic realm=\"lab\"\r\n\r\n<html><title> Demo &amp; Test </title></html>",
        )
        .expect("metadata should parse");

        assert_eq!(metadata.status, Some(401));
        assert_eq!(metadata.server.as_deref(), Some("Test Server"));
        assert_eq!(
            metadata.authenticate.as_deref(),
            Some("Basic realm=\"lab\"")
        );
        assert_eq!(metadata.title.as_deref(), Some("Demo & Test"));
    }

    #[test]
    fn renders_binary_banners_as_bounded_hex() {
        let banner = response_text(&[0, 1, 2, 0xff, b'A']).expect("banner should render");

        assert_eq!(banner, "hex:000102ff41");
    }

    #[test]
    fn honours_a_preexisting_cancellation_request() {
        let cancelled = Arc::new(AtomicBool::new(true));
        let mut progress_count = 0;
        let results = scan_targets_with_control(
            [Ipv4Addr::LOCALHOST],
            ScanOptions {
                ports: Vec::new(),
                collect_http_metadata: false,
                resolve_hostnames: false,
                ..ScanOptions::default()
            },
            cancelled,
            |_| progress_count += 1,
        );

        assert!(results.is_empty());
        assert_eq!(progress_count, 0);
    }

    #[test]
    fn partial_signatures_do_not_override_known_port_protocols() {
        assert_eq!(resolved_service_name(80, "gnutella"), "http");
        assert_eq!(
            resolved_service_name(65000, "custom-service"),
            "custom-service"
        );
    }

    #[test]
    fn accepts_only_same_target_http_redirects() {
        assert_eq!(
            parse_same_target_location("/next", Ipv4Addr::LOCALHOST, 8080),
            Some((8080, "/next".to_owned()))
        );
        assert_eq!(
            parse_same_target_location("http://127.0.0.1:9000/final", Ipv4Addr::LOCALHOST, 80),
            Some((9000, "/final".to_owned()))
        );
        assert_eq!(
            parse_same_target_location("http://example.com/", Ipv4Addr::LOCALHOST, 80),
            None
        );
    }

    #[test]
    fn follows_a_controlled_same_target_redirect() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener should bind");
        let port = listener.local_addr().expect("listener address").port();
        let server = thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().expect("connection should succeed");
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request);
                let response = if index == 0 {
                    "HTTP/1.0 302 Found\r\nLocation: /final\r\n\r\n".to_owned()
                } else {
                    "HTTP/1.0 200 OK\r\n\r\n<title>Redirected</title>".to_owned()
                };
                stream
                    .write_all(response.as_bytes())
                    .expect("response should write");
            }
        });
        let options = ScanOptions {
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(1),
            max_workers: 1,
            ports: vec![port],
            collect_http_metadata: true,
            resolve_hostnames: false,
            collect_windows_enrichment: false,
            probe_database: None,
        };

        let metadata = fetch_http_follow_redirects(Ipv4Addr::LOCALHOST, port, "/", &options)
            .expect("redirect should resolve");
        assert_eq!(metadata.status, Some(200));
        assert_eq!(metadata.title.as_deref(), Some("Redirected"));
        server.join().expect("server should exit");
    }

    #[test]
    fn scans_a_controlled_local_http_service() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener should bind");
        let port = listener.local_addr().expect("listener address").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("connection should succeed");
            drop(stream);
        });
        let options = ScanOptions {
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(1),
            max_workers: 1,
            ports: vec![port],
            collect_http_metadata: false,
            resolve_hostnames: false,
            collect_windows_enrichment: false,
            probe_database: None,
        };

        let result = scan_target(Ipv4Addr::LOCALHOST, &options);
        assert!(result.reachable);
        assert_eq!(result.services[0].port, port);

        server.join().expect("server should exit");
    }

    #[test]
    fn fetches_http_from_a_controlled_local_service() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener should bind");
        let port = listener.local_addr().expect("listener address").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should succeed");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.0 200 OK\r\nServer: local-test\r\n\r\n<title>Loopback</title>")
                .expect("response should write");
        });
        let options = ScanOptions {
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(1),
            max_workers: 1,
            ports: vec![port],
            collect_http_metadata: true,
            resolve_hostnames: false,
            collect_windows_enrichment: false,
            probe_database: None,
        };

        let metadata = fetch_http_once(Ipv4Addr::LOCALHOST, port, "/", &options)
            .expect("HTTP metadata should be returned");
        assert_eq!(metadata.status, Some(200));
        assert_eq!(metadata.server.as_deref(), Some("local-test"));
        assert_eq!(metadata.title.as_deref(), Some("Loopback"));
        server.join().expect("server should exit");
    }
}
