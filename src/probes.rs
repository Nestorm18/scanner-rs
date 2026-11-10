use flate2::read::ZlibDecoder;
use regex::bytes::{Regex, RegexBuilder};
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct ProbeMatch {
    pub service: String,
    pub prefix: Vec<u8>,
    regex: Option<Regex>,
}

impl ProbeMatch {
    fn is_match(&self, response: &[u8]) -> bool {
        self.regex
            .as_ref()
            .map(|regex| regex.is_match(response))
            .unwrap_or_else(|| response.starts_with(&self.prefix))
    }
}

#[derive(Debug, Clone)]
pub struct ServiceProbe {
    pub transport: Transport,
    pub name: String,
    pub payload: Vec<u8>,
    pub ports: Vec<u16>,
    pub ssl_ports: Vec<u16>,
    pub rarity: u8,
    pub matches: Vec<ProbeMatch>,
}

impl ServiceProbe {
    pub fn identify(&self, response: &[u8]) -> Option<&str> {
        self.matches
            .iter()
            .find(|candidate| candidate.is_match(response))
            .map(|candidate| candidate.service.as_str())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProbeDatabase {
    probes: Vec<ServiceProbe>,
}

impl ProbeDatabase {
    pub fn parse(contents: &str) -> Result<Self, String> {
        let mut probes = Vec::<ServiceProbe>::new();

        for (index, raw_line) in contents.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("Probe ") {
                let mut pieces = rest.splitn(3, ' ');
                let transport = match pieces.next() {
                    Some("TCP") => Transport::Tcp,
                    Some("UDP") => Transport::Udp,
                    Some(value) => {
                        return Err(format!("line {}: unknown transport {value}", index + 1))
                    }
                    None => return Err(format!("line {}: missing transport", index + 1)),
                };
                let name = pieces
                    .next()
                    .ok_or_else(|| format!("line {}: missing probe name", index + 1))?;
                let payload = decode_delimited(
                    pieces
                        .next()
                        .ok_or_else(|| format!("line {}: missing probe payload", index + 1))?,
                    'q',
                )
                .map_err(|error| format!("line {}: {error}", index + 1))?;
                probes.push(ServiceProbe {
                    transport,
                    name: name.to_owned(),
                    payload,
                    ports: Vec::new(),
                    ssl_ports: Vec::new(),
                    rarity: 5,
                    matches: Vec::new(),
                });
            } else if let Some(value) = line.strip_prefix("ports ") {
                current_probe(&mut probes, index)?.ports =
                    parse_ports(value).map_err(|error| format!("line {}: {error}", index + 1))?;
            } else if let Some(value) = line.strip_prefix("sslports ") {
                current_probe(&mut probes, index)?.ssl_ports =
                    parse_ports(value).map_err(|error| format!("line {}: {error}", index + 1))?;
            } else if let Some(value) = line.strip_prefix("rarity ") {
                current_probe(&mut probes, index)?.rarity = value
                    .parse()
                    .map_err(|_| format!("line {}: invalid rarity", index + 1))?;
            } else if let Some(value) = line
                .strip_prefix("match ")
                .or_else(|| line.strip_prefix("softmatch "))
            {
                if let Some(probe_match) = parse_probe_match(value) {
                    current_probe(&mut probes, index)?.matches.push(probe_match);
                }
            }
        }

        Ok(Self { probes })
    }

    pub fn load_qcompressed(path: &Path) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        if bytes.len() < 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "qCompress file too short",
            ));
        }
        let declared_length = u32::from_be_bytes(bytes[..4].try_into().expect("four bytes"));
        let mut decoder = ZlibDecoder::new(&bytes[4..]);
        let mut contents = String::with_capacity(declared_length as usize);
        decoder.read_to_string(&mut contents)?;
        if contents.len() != declared_length as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "qCompress length mismatch: expected {declared_length}, got {}",
                    contents.len()
                ),
            ));
        }
        Self::parse(&contents).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub fn load_default() -> io::Result<Option<Self>> {
        for path in default_candidates() {
            if path.is_file() {
                return Self::load_qcompressed(&path).map(Some);
            }
        }
        Ok(None)
    }

    pub fn probes_for_tcp_port(&self, port: u16, maximum_rarity: u8) -> Vec<&ServiceProbe> {
        self.probes
            .iter()
            .filter(|probe| {
                probe.transport == Transport::Tcp
                    && probe.rarity <= maximum_rarity
                    && (probe.name == "NULL" || probe.ports.contains(&port))
            })
            .collect()
    }

    pub fn identify(&self, response: &[u8]) -> Option<&str> {
        self.probes
            .iter()
            .flat_map(|probe| &probe.matches)
            .find(|candidate| candidate.is_match(response))
            .map(|candidate| candidate.service.as_str())
    }

    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }
}

fn current_probe(
    probes: &mut [ServiceProbe],
    zero_based_line: usize,
) -> Result<&mut ServiceProbe, String> {
    probes
        .last_mut()
        .ok_or_else(|| format!("line {}: directive before first Probe", zero_based_line + 1))
}

fn parse_ports(value: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if let Some((start, end)) = item.split_once('-') {
            let start: u16 = start.parse().map_err(|_| format!("invalid port {start}"))?;
            let end: u16 = end.parse().map_err(|_| format!("invalid port {end}"))?;
            if start > end {
                return Err(format!("reversed port range {item}"));
            }
            ports.extend(start..=end);
        } else {
            ports.insert(item.parse().map_err(|_| format!("invalid port {item}"))?);
        }
    }
    Ok(ports.into_iter().collect())
}

fn decode_delimited(value: &str, marker: char) -> Result<Vec<u8>, String> {
    let mut characters = value.char_indices();
    let (_, actual_marker) = characters.next().ok_or("empty delimited value")?;
    if actual_marker != marker {
        return Err(format!("expected {marker} marker"));
    }
    let (_, delimiter) = characters.next().ok_or("missing delimiter")?;
    let content_start = marker.len_utf8() + delimiter.len_utf8();
    let content_end = find_unescaped_delimiter(value, content_start, delimiter)
        .ok_or("unterminated delimited value")?;
    decode_escapes(&value[content_start..content_end], Some(delimiter))
}

fn find_unescaped_delimiter(value: &str, start: usize, delimiter: char) -> Option<usize> {
    let mut escaped = false;
    for (offset, character) in value[start..].char_indices() {
        if character == delimiter && !escaped {
            return Some(start + offset);
        }
        if character == '\\' && !escaped {
            escaped = true;
        } else {
            escaped = false;
        }
    }
    None
}

fn parse_probe_match(value: &str) -> Option<ProbeMatch> {
    let mut pieces = value.splitn(2, ' ');
    let service = pieces.next()?.trim();
    let expression = pieces.next()?.trim_start();
    if !expression.starts_with('m') {
        return None;
    }
    let delimiter = expression.chars().nth(1)?;
    let start = 2;
    let end = find_unescaped_delimiter(expression, start, delimiter)?;
    let pattern = &expression[start..end];
    let flags = expression[end + delimiter.len_utf8()..]
        .split_whitespace()
        .next()
        .unwrap_or_default();
    let normalized = normalize_regex(pattern, delimiter);
    let regex = RegexBuilder::new(&normalized)
        .unicode(false)
        .case_insensitive(flags.contains('i'))
        .dot_matches_new_line(flags.contains('s'))
        .build()
        .ok();

    let literal = pattern.strip_prefix('^').unwrap_or(pattern);
    let literal_end = first_regex_meta(literal);
    let prefix = decode_escapes(&literal[..literal_end], Some(delimiter)).unwrap_or_default();
    (regex.is_some() || prefix.len() >= 3).then(|| ProbeMatch {
        service: service.to_owned(),
        prefix,
        regex,
    })
}

fn normalize_regex(pattern: &str, delimiter: char) -> String {
    let mut normalized = String::with_capacity(pattern.len());
    let mut characters = pattern.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\\' {
            normalized.push(character);
            continue;
        }
        let Some(escaped) = characters.next() else {
            normalized.push('\\');
            break;
        };
        if escaped == delimiter {
            normalized.push(escaped);
        } else if escaped == '0' {
            normalized.push_str("\\x00");
        } else {
            normalized.push('\\');
            normalized.push(escaped);
        }
    }
    normalized
}

fn first_regex_meta(pattern: &str) -> usize {
    let mut escaped = false;
    for (index, character) in pattern.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
        } else if matches!(
            character,
            '.' | '[' | '(' | '*' | '+' | '?' | '{' | '$' | '|'
        ) {
            return index;
        }
    }
    pattern.len()
}

fn decode_escapes(value: &str, delimiter: Option<char>) -> Result<Vec<u8>, String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        index += 1;
        let escaped = *bytes.get(index).ok_or("trailing escape")?;
        match escaped {
            b'0' => output.push(0),
            b'r' => output.push(b'\r'),
            b'n' => output.push(b'\n'),
            b't' => output.push(b'\t'),
            b'x' => {
                let hex = bytes.get(index + 1..index + 3).ok_or("short hex escape")?;
                let text = std::str::from_utf8(hex).map_err(|_| "invalid hex escape")?;
                output.push(u8::from_str_radix(text, 16).map_err(|_| "invalid hex escape")?);
                index += 2;
            }
            value if delimiter == Some(value as char) || value == b'\\' => output.push(value),
            value => output.push(value),
        }
        index += 1;
    }
    Ok(output)
}

fn default_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![PathBuf::from("service_probes")];
    if let Ok(executable) = std::env::current_exe() {
        for ancestor in executable.ancestors().take(5) {
            candidates.push(ancestor.join("service_probes"));
        }
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::{parse_ports, ProbeDatabase};

    #[test]
    fn parses_probe_payload_ports_and_prefix_match() {
        let database = ProbeDatabase::parse(
            "Probe TCP Demo q|HELLO\\r\\n|\nports 80,8000-8002\nrarity 2\nmatch demo m|^WORLD\\x20OK [0-9]+$| p/Demo/\n",
        )
        .expect("fixture should parse");

        let probes = database.probes_for_tcp_port(8001, 3);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].payload, b"HELLO\r\n");
        assert_eq!(probes[0].identify(b"WORLD OK 1.0"), None);
        assert_eq!(probes[0].identify(b"WORLD OK 42"), Some("demo"));
        assert_eq!(database.identify(b"WORLD OK 42"), Some("demo"));
    }

    #[test]
    fn applies_full_binary_regex_and_flags_when_supported() {
        let database = ProbeDatabase::parse(
            "Probe TCP Demo q||\nports 65000\nmatch demo m|^HELLO\\x00[0-9]+$|i p/Demo/\n",
        )
        .expect("fixture should parse");
        let probe = database.probes_for_tcp_port(65000, 5)[0];

        assert_eq!(probe.identify(b"hello\0"), None);
        assert_eq!(probe.identify(b"hello\0123"), Some("demo"));
        assert_eq!(probe.identify(b"hello\0123 trailing"), None);
    }

    #[test]
    fn expands_and_sorts_port_ranges() {
        assert_eq!(parse_ports("443,80-82,81").unwrap(), [80, 81, 82, 443]);
    }
}
