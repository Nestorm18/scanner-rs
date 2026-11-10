use crate::targets::{Ipv4Range, TargetError};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub struct SourceError {
    pub line: usize,
    pub value: String,
    pub source: TargetError,
}

impl fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid target on line {} ({:?}): {}",
            self.line, self.value, self.source
        )
    }
}

impl std::error::Error for SourceError {}

pub fn parse_source(contents: &str) -> Result<Vec<Ipv4Range>, SourceError> {
    contents
        .lines()
        .enumerate()
        .filter_map(|(index, raw)| {
            let value = raw.trim();
            if value.is_empty() || value.starts_with('#') || value.starts_with(';') {
                None
            } else {
                Some((index + 1, value))
            }
        })
        .map(|(line, value)| {
            value.parse().map_err(|source| SourceError {
                line,
                value: value.to_owned(),
                source,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_source;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_ranges_and_ignores_comments() {
        let ranges = parse_source("# targets\n192.0.2.1\n\n; disabled\n192.0.2.3-192.0.2.4\n")
            .expect("source should parse");
        let targets = ranges
            .into_iter()
            .flat_map(|range| range.into_iter())
            .collect::<Vec<_>>();

        assert_eq!(
            targets,
            [
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(192, 0, 2, 3),
                Ipv4Addr::new(192, 0, 2, 4),
            ]
        );
    }

    #[test]
    fn reports_the_original_line_number() {
        let error = parse_source("# comment\n\nnot-an-address\n").expect_err("source should fail");

        assert_eq!(error.line, 3);
        assert_eq!(error.value, "not-an-address");
    }
}
