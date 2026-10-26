use font8x8::UnicodeFonts;

#[derive(Debug)]
pub struct Frame {
    pub width: usize,
    pub height: usize,
    pub planes: [Vec<u8>; 3],
}

pub const WORKLOADS: &[&str] = &["static-text", "scroll", "windows", "video"];

// Versioned, deterministic, platform-independent synthetic I420 fixtures. Generation
// is outside codec timers. Coordinates are pixel based, so font size stays constant.
pub fn generate(width: usize, height: usize, index: usize, workload: &str) -> Frame {
    let mut f = Frame {
        width,
        height,
        planes: [
            vec![28; width * height],
            vec![128; width * height / 4],
            vec![128; width * height / 4],
        ],
    };
    if workload == "video" {
        for y in 0..height {
            for x in 0..width {
                let sx = x + index * 5;
                let sy = y + index * 3;
                let wave = ((sx / 3 + sy / 2) % 160) as u8;
                let texture = hash((sx / 2) as u32 ^ (sy as u32).wrapping_mul(0x9e3779b9)) % 24;
                f.planes[0][y * width + x] = 24 + wave + texture as u8;
            }
        }
        for y in 0..height / 2 {
            for x in 0..width / 2 {
                f.planes[1][y * width / 2 + x] = 64 + ((x + index * 2) % 128) as u8;
                f.planes[2][y * width / 2 + x] = 64 + ((y + index) % 128) as u8;
            }
        }
        return f;
    }
    let offset = if workload == "scroll" { index * 4 } else { 0 };
    for row in 0..(height + offset) / 20 + 1 {
        let baseline = row as isize * 20 - offset as isize + 5;
        if baseline < -16 || baseline >= height as isize {
            continue;
        }
        let line = format!(
            "{row:04}  fn mirror_frame(frame: &VideoFrame) -> Result<()> {{ // ESP video 0123456789"
        );
        draw_text(&mut f, 12, baseline, &line, 210);
    }
    if workload == "windows" {
        let ww = width / 2;
        let wh = height / 2;
        let left = (index * 13) % (width - ww);
        let top = (index * 7) % (height - wh);
        for y in top..top + wh {
            for x in left..left + ww {
                f.planes[0][y * width + x] = if y < top + 24 { 85 } else { 180 };
            }
        }
        for y in top / 2..(top + wh) / 2 {
            for x in left / 2..(left + ww) / 2 {
                f.planes[1][y * width / 2 + x] = 150;
                f.planes[2][y * width / 2 + x] = 100;
            }
        }
        draw_text(
            &mut f,
            left as isize + 6,
            top as isize + 4,
            "Moving window",
            235,
        );
    }
    f
}
fn hash(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846ca68b);
    x ^ (x >> 16)
}
fn draw_text(f: &mut Frame, left: isize, top: isize, text: &str, color: u8) {
    for (col, ch) in text.chars().enumerate() {
        let glyph = font8x8::BASIC_FONTS.get(ch).unwrap();
        for (y, bits) in glyph.iter().enumerate() {
            for x in 0..8 {
                let px = left + col as isize * 9 + x;
                let py = top + y as isize;
                if bits & (1 << x) != 0
                    && px >= 0
                    && py >= 0
                    && px < f.width as isize
                    && py < f.height as isize
                {
                    f.planes[0][py as usize * f.width + px as usize] = color;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_and_static() {
        for work in WORKLOADS {
            let f = generate(160, 90, 7, work);
            assert_eq!(f.planes, generate(160, 90, 7, work).planes);
            assert_eq!(f.planes[0].len(), 14400);
            assert_eq!(f.planes[1].len(), 3600);
            if *work == "static-text" {
                assert_eq!(f.planes, generate(160, 90, 0, work).planes);
            } else {
                assert_ne!(f.planes, generate(160, 90, 0, work).planes);
            }
        }
    }
}
