// A single executable: no arguments opens the window, arguments run the CLI.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod gui;

use scanner_rs::cli::{parse_args, Verbosity};
use scanner_rs::output::{render_text, render_xml};
use scanner_rs::probes::ProbeDatabase;
use scanner_rs::scanner::{scan_progressive, ScanEvent, ScanOptions};
use scanner_rs::source::parse_source;
use scanner_rs::targets::Ipv4Range;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn run_cli() -> ExitCode {
    let config = match parse_args(env::args_os().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };

    let mut ranges = Vec::new();
    if let Some(range) = &config.range {
        match range.parse::<Ipv4Range>() {
            Ok(range) => ranges.push(range),
            Err(error) => return fail(&error.to_string(), 2),
        }
    }

    if let Some(path) = &config.source_file {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) => return fail(&format!("cannot read {}: {error}", path.display()), 2),
        };
        match parse_source(&contents) {
            Ok(source_ranges) => ranges.extend(source_ranges),
            Err(error) => return fail(&error.to_string(), 2),
        }
    }

    let targets: Vec<_> = ranges
        .into_iter()
        .flat_map(|range| range.into_iter())
        .collect();
    let mut options = ScanOptions::default();
    options.max_workers = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().saturating_mul(8).clamp(32, 128))
        .unwrap_or(64);
    if config.verbosity == Verbosity::HostsOnly {
        options.ports.clear();
    }
    options.collect_http_metadata = config.verbosity != Verbosity::HostsOnly;
    options.resolve_hostnames = true;
    options.collect_windows_enrichment = config.verbosity == Verbosity::GroupedServices;
    match ProbeDatabase::load_default() {
        Ok(Some(database)) => options.probe_database = Some(Arc::new(database)),
        Ok(None) => {}
        Err(error) => eprintln!("warning: service probe database could not be loaded: {error}"),
    }

    // Only live hosts are reported; each one arrives once its details are done.
    let mut results = Vec::new();
    scan_progressive(
        targets,
        options,
        Arc::new(AtomicBool::new(false)),
        |event| {
            if let ScanEvent::Detailed(host) = event {
                results.push(host);
            }
        },
    );
    results.sort_by_key(|result| result.address);
    let rendered = if config.output_xml {
        render_xml(&results)
    } else {
        render_text(&results, config.verbosity)
    };

    if let Some(path) = &config.output_file {
        if let Err(error) = fs::write(path, rendered.as_bytes()) {
            return fail(&format!("cannot write {}: {error}", path.display()), 1);
        }
    } else if let Err(error) = io::stdout().write_all(rendered.as_bytes()) {
        return fail(&format!("cannot write output: {error}"), 1);
    }

    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    if env::args_os().len() <= 1 {
        return match gui::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
    attach_parent_console();
    run_cli()
}

/// Release builds use the GUI subsystem; reuse the terminal we were started from
/// so command-line output is visible.
#[cfg(windows)]
fn attach_parent_console() {
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
    }
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(windows))]
fn attach_parent_console() {}

fn fail(message: &str, code: u8) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::from(code)
}
