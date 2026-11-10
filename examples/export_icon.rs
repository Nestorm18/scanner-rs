//! Writes `assets/icon.ico` and `assets/icon.png` from `src/icon.rs`.
//!
//! cargo run --example export_icon

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::fs;
use std::io::Write;

fn main() -> std::io::Result<()> {
    fs::create_dir_all("assets")?;
    fs::write("assets/icon.ico", scanner_rs::icon::ico())?;
    fs::write("assets/icon.png", png(256))?;
    println!("assets/icon.ico, assets/icon.png");
    Ok(())
}

fn png(size: u32) -> Vec<u8> {
    let pixels = scanner_rs::icon::rgba(size);
    let mut raw = Vec::with_capacity(pixels.len() + size as usize);
    for row in pixels.chunks(size as usize * 4) {
        raw.push(0);
        raw.extend_from_slice(row);
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&raw).unwrap();
    let data = encoder.finish().unwrap();

    let mut header = Vec::new();
    header.extend_from_slice(&size.to_be_bytes());
    header.extend_from_slice(&size.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);

    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut out, b"IHDR", &header);
    chunk(&mut out, b"IDAT", &data);
    chunk(&mut out, b"IEND", &[]);
    out
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in kind.iter().chain(data) {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    out.extend_from_slice(&(!crc).to_be_bytes());
}
