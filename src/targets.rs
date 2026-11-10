use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Range {
    start: u32,
    end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    InvalidAddress(String),
    ReversedRange { start: Ipv4Addr, end: Ipv4Addr },
    TooManySeparators(String),
}

impl fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress(address) => write!(formatter, "invalid IPv4 address: {address}"),
            Self::ReversedRange { start, end } => {
                write!(formatter, "range starts after it ends: {start}-{end}")
            }
            Self::TooManySeparators(value) => write!(formatter, "invalid IPv4 range: {value}"),
        }
    }
}

impl std::error::Error for TargetError {}

impl Ipv4Range {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Result<Self, TargetError> {
        let start_number = u32::from(start);
        let end_number = u32::from(end);

        if start_number > end_number {
            return Err(TargetError::ReversedRange { start, end });
        }

        Ok(Self {
            start: start_number,
            end: end_number,
        })
    }

    pub fn len(self) -> u64 {
        u64::from(self.end) - u64::from(self.start) + 1
    }

    pub fn is_empty(self) -> bool {
        false
    }

    pub fn iter(self) -> Ipv4RangeIter {
        Ipv4RangeIter {
            next: Some(self.start),
            end: self.end,
        }
    }
}

impl FromStr for Ipv4Range {
    type Err = TargetError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut pieces = value.split('-');
        let start_text = pieces.next().unwrap_or_default();
        let end_text = pieces.next();

        if pieces.next().is_some() {
            return Err(TargetError::TooManySeparators(value.to_owned()));
        }

        let start = parse_address(start_text)?;
        let end = match end_text {
            Some(text) => parse_address(text)?,
            None => start,
        };

        Self::new(start, end)
    }
}

impl IntoIterator for Ipv4Range {
    type Item = Ipv4Addr;
    type IntoIter = Ipv4RangeIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct Ipv4RangeIter {
    next: Option<u32>,
    end: u32,
}

impl Iterator for Ipv4RangeIter {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next?;
        self.next = if current == self.end {
            None
        } else {
            Some(current + 1)
        };
        Some(Ipv4Addr::from(current))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self
            .next
            .map(|next| u64::from(self.end) - u64::from(next) + 1)
            .unwrap_or(0);
        let bounded = usize::try_from(remaining).unwrap_or(usize::MAX);
        (bounded, Some(bounded))
    }
}

impl ExactSizeIterator for Ipv4RangeIter {}

fn parse_address(value: &str) -> Result<Ipv4Addr, TargetError> {
    value
        .parse()
        .map_err(|_| TargetError::InvalidAddress(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{Ipv4Range, TargetError};
    use std::net::Ipv4Addr;

    #[test]
    fn parses_a_single_address() {
        let range: Ipv4Range = "192.168.1.7".parse().expect("address should parse");

        assert_eq!(range.len(), 1);
        assert_eq!(
            range.into_iter().collect::<Vec<_>>(),
            [Ipv4Addr::new(192, 168, 1, 7)]
        );
    }

    #[test]
    fn expands_an_inclusive_range_across_an_octet_boundary() {
        let range: Ipv4Range = "192.168.0.254-192.168.1.1"
            .parse()
            .expect("range should parse");

        assert_eq!(
            range.into_iter().collect::<Vec<_>>(),
            [
                Ipv4Addr::new(192, 168, 0, 254),
                Ipv4Addr::new(192, 168, 0, 255),
                Ipv4Addr::new(192, 168, 1, 0),
                Ipv4Addr::new(192, 168, 1, 1),
            ]
        );
    }

    #[test]
    fn rejects_a_reversed_range() {
        let error = "10.0.0.2-10.0.0.1"
            .parse::<Ipv4Range>()
            .expect_err("reversed range should fail");

        assert_eq!(
            error,
            TargetError::ReversedRange {
                start: Ipv4Addr::new(10, 0, 0, 2),
                end: Ipv4Addr::new(10, 0, 0, 1),
            }
        );
    }

    #[test]
    fn full_ipv4_space_has_a_non_overflowing_length() {
        let range: Ipv4Range = "0.0.0.0-255.255.255.255"
            .parse()
            .expect("full range should parse");

        assert_eq!(range.len(), 4_294_967_296);
    }
}
