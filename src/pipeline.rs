pub const HTTP_METADATA_PORTS: [u16; 2] = [80, 8080];
pub const TARGETED_METADATA_PORTS: [u16; 3] = [443, 21, 3389];

pub const fn http_metadata_timeout_ms(high_accuracy: bool) -> u64 {
    if high_accuracy {
        5_000
    } else {
        2_000
    }
}

#[cfg(test)]
mod tests {
    use super::{http_metadata_timeout_ms, HTTP_METADATA_PORTS, TARGETED_METADATA_PORTS};

    #[test]
    fn exposes_service_ports_and_http_timeouts() {
        assert_eq!(HTTP_METADATA_PORTS, [80, 8080]);
        assert_eq!(TARGETED_METADATA_PORTS, [443, 21, 3389]);
        assert_eq!(http_metadata_timeout_ms(false), 2_000);
        assert_eq!(http_metadata_timeout_ms(true), 5_000);
    }
}
