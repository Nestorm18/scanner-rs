//! Embeds the application icon into the Windows executables (MSVC toolchain).
//!
//! The icon is drawn by `src/icon.rs` and written as a compiled resource
//! (`.res`) that `link.exe` accepts directly, so no extra tools are needed.

#[allow(dead_code)]
#[path = "src/icon.rs"]
mod icon;

use std::env;
use std::fs;
use std::path::PathBuf;

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;

fn main() {
    println!("cargo:rerun-if-changed=src/icon.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let windows = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let msvc = env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if !(windows && msvc) {
        return;
    }

    let mut res = Vec::new();
    push_resource(&mut res, 0, 0, 0, &[]);

    let mut group = Vec::new();
    group.extend_from_slice(&0u16.to_le_bytes());
    group.extend_from_slice(&1u16.to_le_bytes());
    group.extend_from_slice(&(icon::ICO_SIZES.len() as u16).to_le_bytes());
    for (index, &size) in icon::ICO_SIZES.iter().enumerate() {
        let id = index as u16 + 1;
        let image = icon::dib(size);
        let dimension = if size >= 256 { 0 } else { size as u8 };
        group.extend_from_slice(&[dimension, dimension, 0, 0]);
        group.extend_from_slice(&1u16.to_le_bytes());
        group.extend_from_slice(&32u16.to_le_bytes());
        group.extend_from_slice(&(image.len() as u32).to_le_bytes());
        group.extend_from_slice(&id.to_le_bytes());
        push_resource(&mut res, RT_ICON, id, 0x1010, &image);
    }
    push_resource(&mut res, RT_GROUP_ICON, 1, 0x1030, &group);

    let path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("scanner-rs-icon.res");
    fs::write(&path, res).expect("write icon resource");
    println!("cargo:rustc-link-arg-bins={}", path.display());
}

fn push_resource(out: &mut Vec<u8>, kind: u16, name: u16, flags: u16, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&32u32.to_le_bytes());
    out.extend_from_slice(&[0xFF, 0xFF]);
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&[0xFF, 0xFF]);
    out.extend_from_slice(&name.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}
