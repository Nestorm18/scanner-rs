//! Procedurally drawn application icon (radar on a blue rounded square).
//!
//! This file has no dependencies so it can also be included from `build.rs`
//! to embed the icon into the Windows executable.

/// Draws the icon and returns straight (non-premultiplied) RGBA8 pixels.
pub fn rgba(size: u32) -> Vec<u8> {
    const SAMPLES: u32 = 4;
    let mut pixels = Vec::with_capacity((size * size * 4) as usize);
    let scale = 1.0 / size as f32;
    for y in 0..size {
        for x in 0..size {
            let mut acc = [0.0f32; 4];
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let u = (x as f32 + (sx as f32 + 0.5) / SAMPLES as f32) * scale;
                    let v = (y as f32 + (sy as f32 + 0.5) / SAMPLES as f32) * scale;
                    let [r, g, b, a] = sample(u, v);
                    acc[0] += r * a;
                    acc[1] += g * a;
                    acc[2] += b * a;
                    acc[3] += a;
                }
            }
            let n = (SAMPLES * SAMPLES) as f32;
            let alpha = acc[3] / n;
            let unpremultiply = |c: f32| {
                if acc[3] > 0.0 {
                    (c / acc[3] * 255.0).round().clamp(0.0, 255.0) as u8
                } else {
                    0
                }
            };
            pixels.extend_from_slice(&[
                unpremultiply(acc[0]),
                unpremultiply(acc[1]),
                unpremultiply(acc[2]),
                (alpha * 255.0).round() as u8,
            ]);
        }
    }
    pixels
}

/// Icon image encoded as an ICO-style DIB (BITMAPINFOHEADER + BGRA + AND mask).
pub fn dib(size: u32) -> Vec<u8> {
    let pixels = rgba(size);
    let mask_row = size.div_ceil(32) * 4;
    let image_size = size * size * 4 + mask_row * size;
    let mut out = Vec::with_capacity(40 + image_size as usize);
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(size as i32).to_le_bytes());
    out.extend_from_slice(&(size as i32 * 2).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&image_size.to_le_bytes());
    out.extend_from_slice(&[0u8; 16]);
    for y in (0..size).rev() {
        for x in 0..size {
            let i = ((y * size + x) * 4) as usize;
            out.extend_from_slice(&[pixels[i + 2], pixels[i + 1], pixels[i], pixels[i + 3]]);
        }
    }
    out.resize(out.len() + (mask_row * size) as usize, 0);
    out
}

/// Sizes embedded in the `.ico` / executable.
pub const ICO_SIZES: [u32; 5] = [16, 24, 32, 48, 256];

/// Complete `.ico` file containing every size in [`ICO_SIZES`].
pub fn ico() -> Vec<u8> {
    let images: Vec<Vec<u8>> = ICO_SIZES.iter().map(|&size| dib(size)).collect();
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 1, 0]);
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len() as u32;
    for (size, image) in ICO_SIZES.iter().zip(&images) {
        let dimension = if *size >= 256 { 0 } else { *size as u8 };
        out.extend_from_slice(&[dimension, dimension, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(image.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += image.len() as u32;
    }
    for image in images {
        out.extend_from_slice(&image);
    }
    out
}

fn sample(u: f32, v: f32) -> [f32; 4] {
    // Rounded square background.
    let margin = 0.04;
    let radius = 0.22;
    let half = 0.5 - margin;
    let qx = (u - 0.5).abs() - (half - radius);
    let qy = (v - 0.5).abs() - (half - radius);
    let outside = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt() + qx.max(qy).min(0.0);
    if outside > radius {
        return [0.0; 4];
    }

    let t = ((v - margin) / (1.0 - 2.0 * margin)).clamp(0.0, 1.0);
    let top = [0.30, 0.60, 1.0];
    let bottom = [0.13, 0.36, 0.86];
    let mut color = [
        top[0] + (bottom[0] - top[0]) * t,
        top[1] + (bottom[1] - top[1]) * t,
        top[2] + (bottom[2] - top[2]) * t,
    ];
    let mut blend = |overlay: [f32; 3], alpha: f32| {
        for i in 0..3 {
            color[i] = color[i] * (1.0 - alpha) + overlay[i] * alpha;
        }
    };
    const WHITE: [f32; 3] = [1.0, 1.0, 1.0];

    let dx = u - 0.5;
    let dy = v - 0.5;
    let distance = (dx * dx + dy * dy).sqrt();
    let angle = dy.atan2(dx);
    let outer = 0.31;

    // Radar sweep with fading trail behind the leading edge.
    let lead = -30f32.to_radians();
    let span = 100f32.to_radians();
    if distance < outer {
        let mut behind = lead - angle;
        if behind < 0.0 {
            behind += std::f32::consts::TAU;
        }
        if behind < span {
            blend(WHITE, 0.5 * (1.0 - behind / span));
        }
    }

    // Rings.
    if (distance - outer).abs() < 0.026 {
        blend(WHITE, 0.95);
    }
    if (distance - 0.19).abs() < 0.02 {
        blend(WHITE, 0.55);
    }

    // Leading edge line.
    let (dir_x, dir_y) = (lead.cos(), lead.sin());
    let along = (dx * dir_x + dy * dir_y).clamp(0.0, outer);
    let off_x = dx - dir_x * along;
    let off_y = dy - dir_y * along;
    if (off_x * off_x + off_y * off_y).sqrt() < 0.022 {
        blend(WHITE, 1.0);
    }

    // Center dot.
    if distance < 0.045 {
        blend(WHITE, 1.0);
    }

    // Detected device blip.
    let blip_angle = -65f32.to_radians();
    let bx = dx - blip_angle.cos() * 0.235;
    let by = dy - blip_angle.sin() * 0.235;
    if (bx * bx + by * by).sqrt() < 0.052 {
        blend([0.36, 0.89, 0.60], 1.0);
    }

    [color[0], color[1], color[2], 1.0]
}
