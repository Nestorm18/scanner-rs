//! MAC address vendor lookup (IEEE OUI registry, via Wireshark's `manuf`).

use flate2::read::GzDecoder;
use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

static DATA: &[u8] = include_bytes!("../assets/oui.txt.gz");

/// Label for MACs with the "locally administered" bit (random/private addresses).
pub const RANDOM_MAC: &str = "MAC aleatoria";

fn table() -> &'static HashMap<String, String> {
    static TABLE: OnceLock<HashMap<String, String>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut text = String::new();
        if GzDecoder::new(DATA).read_to_string(&mut text).is_err() {
            return HashMap::new();
        }
        text.lines()
            .filter_map(|line| line.split_once('\t'))
            .map(|(prefix, name)| (prefix.to_owned(), name.to_owned()))
            .collect()
    })
}

/// Vendor for a MAC such as `BC:24:11:6D:E6:05`; `None` if unknown.
pub fn lookup(mac: &str) -> Option<&'static str> {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|character| character.to_ascii_uppercase())
        .collect();
    if hex.len() < 6 {
        return None;
    }
    let table = table();
    for length in [9, 7, 6] {
        if hex.len() >= length {
            if let Some(name) = table.get(&hex[..length]) {
                return Some(name);
            }
        }
    }
    let second = hex.as_bytes()[1];
    matches!(second, b'2' | b'6' | b'A' | b'E').then_some(RANDOM_MAC)
}

#[cfg(test)]
mod tests {
    use super::{lookup, RANDOM_MAC};

    #[test]
    fn finds_known_vendors() {
        assert_eq!(
            lookup("BC:24:11:6D:E6:05"),
            Some("Proxmox Server Solutions")
        );
        assert_eq!(lookup("00-11-32-f5-65-27"), Some("Synology"));
    }

    #[test]
    fn flags_random_macs() {
        assert_eq!(lookup("0A:0B:32:53:8F:2C"), Some(RANDOM_MAC));
        assert_eq!(lookup("zz"), None);
    }
}
