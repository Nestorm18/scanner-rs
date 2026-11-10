use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    HostsOnly,
    Services,
    GroupedServices,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanConfig {
    pub range: Option<String>,
    pub source_file: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub output_xml: bool,
    pub verbosity: Verbosity,
    pub portable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    NonUnicodeArgument(OsString),
    UnknownArgument(String),
    EmptyValue(&'static str),
    DuplicateOption(&'static str),
    MissingTarget,
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUnicodeArgument(argument) => {
                write!(formatter, "argument is not valid Unicode: {argument:?}")
            }
            Self::UnknownArgument(argument) => write!(formatter, "unknown argument: {argument}"),
            Self::EmptyValue(option) => write!(formatter, "{option} requires a value"),
            Self::DuplicateOption(option) => write!(formatter, "duplicate option: {option}"),
            Self::MissingTarget => write!(formatter, "provide /r:<target> or /s:<file>"),
        }
    }
}

impl std::error::Error for CliError {}

pub fn parse_args<I, S>(arguments: I) -> Result<ScanConfig, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut config = ScanConfig {
        range: None,
        source_file: None,
        output_file: None,
        output_xml: false,
        verbosity: Verbosity::HostsOnly,
        portable: false,
    };
    let mut services_seen = false;
    let mut grouped_services_seen = false;
    let mut portable_seen = false;

    for argument in arguments {
        let argument = argument.into();
        let argument = argument
            .into_string()
            .map_err(CliError::NonUnicodeArgument)?;
        if argument == "/v" {
            reject_duplicate(&mut services_seen, "/v")?;
            config.verbosity = Verbosity::Services;
        } else if argument == "/v2" {
            reject_duplicate(&mut grouped_services_seen, "/v2")?;
            config.verbosity = Verbosity::GroupedServices;
        } else if argument == "/portable" {
            reject_duplicate(&mut portable_seen, "/portable")?;
            config.portable = true;
        } else if let Some(value) = option_value(&argument, "/r:") {
            if config.range.is_some() {
                return Err(CliError::DuplicateOption("/r"));
            }
            config.range = Some(required_value("/r", value)?.to_owned());
        } else if let Some(value) = option_value(&argument, "/s:") {
            if config.source_file.is_some() {
                return Err(CliError::DuplicateOption("/s"));
            }
            config.source_file = Some(PathBuf::from(required_value("/s", value)?));
        } else if let Some(value) = option_value(&argument, "/f:") {
            if config.output_file.is_some() {
                return Err(CliError::DuplicateOption("/f"));
            }
            let value = required_value("/f", value)?;
            config.output_xml = value.to_ascii_lowercase().ends_with(".xml");
            config.output_file = Some(PathBuf::from(value));
        } else {
            return Err(CliError::UnknownArgument(argument));
        }
    }

    if config.range.is_none() && config.source_file.is_none() {
        return Err(CliError::MissingTarget);
    }

    Ok(config)
}

fn option_value<'a>(argument: &'a str, prefix: &str) -> Option<&'a str> {
    argument
        .get(..prefix.len())
        .filter(|candidate| *candidate == prefix)
        .map(|_| &argument[prefix.len()..])
}

fn reject_duplicate(seen: &mut bool, option: &'static str) -> Result<(), CliError> {
    if *seen {
        Err(CliError::DuplicateOption(option))
    } else {
        *seen = true;
        Ok(())
    }
}

fn required_value<'a>(option: &'static str, value: &'a str) -> Result<&'a str, CliError> {
    if value.is_empty() {
        Err(CliError::EmptyValue(option))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_args, CliError, ScanConfig, Verbosity};
    use std::path::PathBuf;

    #[test]
    fn parses_embedded_range_example() {
        let config = parse_args(["/r:192.168.0.1-192.168.0.255", "/v2", "/portable"])
            .expect("the command line should parse");

        assert_eq!(
            config,
            ScanConfig {
                range: Some("192.168.0.1-192.168.0.255".to_owned()),
                source_file: None,
                output_file: None,
                output_xml: false,
                verbosity: Verbosity::GroupedServices,
                portable: true,
            }
        );
    }

    #[test]
    fn parses_embedded_file_example() {
        let config = parse_args(["/s:ip_ranges.txt", "/f:scan_results.txt", "/v"])
            .expect("the command line should parse");

        assert_eq!(config.source_file, Some(PathBuf::from("ip_ranges.txt")));
        assert_eq!(config.output_file, Some(PathBuf::from("scan_results.txt")));
        assert!(!config.output_xml);
        assert_eq!(config.verbosity, Verbosity::Services);
    }

    #[test]
    fn xml_output_is_selected_by_case_insensitive_suffix() {
        let config =
            parse_args(["/r:127.0.0.1", "/f:scan_results.XML"]).expect("options should parse");

        assert!(config.output_xml);
    }

    #[test]
    fn option_names_are_case_sensitive() {
        assert_eq!(
            parse_args(["/R:127.0.0.1"]),
            Err(CliError::UnknownArgument("/R:127.0.0.1".to_owned()))
        );
    }

    #[test]
    fn rejects_repeated_identical_options() {
        assert_eq!(
            parse_args(["/r:127.0.0.1", "/r:127.0.0.2"]),
            Err(CliError::DuplicateOption("/r"))
        );
        assert_eq!(
            parse_args(["/r:127.0.0.1", "/v", "/v"]),
            Err(CliError::DuplicateOption("/v"))
        );
    }

    #[test]
    fn target_is_required() {
        assert_eq!(parse_args(["/v"]), Err(CliError::MissingTarget));
    }
}
