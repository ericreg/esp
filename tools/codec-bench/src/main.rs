mod archive;
mod codecs;
mod frames;
use anyhow::{Context as _, Result, bail, ensure};
use clap::Parser;
use codecs::{Decoder, Encoder, Packet};
use frames::Frame;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Parser, Debug)]
#[command(
    about = "Portable Rust-only VP8 and AV1 software codec benchmark (no display or driver needed)"
)]
struct Args {
    #[arg(long, default_value = "vp8,av1", value_delimiter = ',')]
    codecs: Vec<String>,
    #[arg(long, default_value = "1280x720,1920x1080", value_delimiter = ',')]
    sizes: Vec<String>,
    #[arg(
        long,
        default_value = "static-text,scroll,windows,video",
        value_delimiter = ','
    )]
    workloads: Vec<String>,
    #[arg(long, default_value_t = 60)]
    frames: usize,
    #[arg(long, default_value_t = 3)]
    warmup: usize,
    #[arg(long, default_value_t = 3)]
    repeats: usize,
    #[arg(long, default_value_t = 30)]
    fps: usize,
    /// AV1 thread count; VP8's standalone streaming encoder is single-threaded.
    #[arg(long, default_value_t = 1)]
    threads: usize,
    #[arg(long, default_value_t = 32)]
    vp8_q: u8,
    #[arg(long, default_value_t = 100)]
    av1_q: usize,
    #[arg(long, default_value_t = 10)]
    av1_speed: u8,
    /// AV1 target tile count (0 keeps the codec default); fixed independently of threads.
    #[arg(long, default_value_t = 0)]
    av1_tiles: usize,
    /// Kill an individual case after this many seconds, including warmup.
    #[arg(long, default_value_t = 600)]
    timeout: u64,
    #[arg(long, default_value = "codec-bench-results.json")]
    output: PathBuf,
    /// Export measured encoded streams for replay on another machine.
    #[arg(long)]
    export_streams: Option<PathBuf>,
    /// Decode an exported corpus without running its encoder (repeatable flag).
    #[arg(long)]
    decode_stream: Vec<PathBuf>,
    /// Internal isolated worker request (used by the benchmark runner).
    #[arg(long, hide = true)]
    worker: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    width: usize,
    height: usize,
    fps: usize,
    threads: usize,
    vp8_q: u8,
    av1_q: usize,
    av1_speed: u8,
    #[serde(default)]
    av1_tiles: usize,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Request {
    codec: String,
    workload: String,
    settings: Settings,
    frames: usize,
    warmup: usize,
    repeat: usize,
    export: Option<PathBuf>,
    replay: Option<PathBuf>,
}
#[derive(Default, Serialize, Deserialize)]
struct Distribution {
    mean: f64,
    p50: f64,
    p95: f64,
    max: f64,
}
fn distribution(v: &[f64]) -> Distribution {
    if v.is_empty() {
        return Distribution::default();
    }
    let mut sorted = v.to_vec();
    sorted.sort_by(f64::total_cmp);
    let percentile = |q: f64| sorted[((q * sorted.len() as f64).ceil() as usize).saturating_sub(1)];
    Distribution {
        mean: v.iter().sum::<f64>() / v.len() as f64,
        p50: percentile(0.5),
        p95: percentile(0.95),
        max: *sorted.last().unwrap(),
    }
}
#[derive(Serialize, Deserialize)]
struct Sample {
    frame: usize,
    bytes: usize,
    keyframe: bool,
    decode_ms: f64,
    encoder_residence_codec_ms: f64,
    additional_inputs_before_packet: usize,
    psnr_y_db: Option<f64>,
    psnr_yuv_db: Option<f64>,
    decoded_checksum: String,
    tile_grid: Option<[usize; 2]>,
}
#[derive(Serialize, Deserialize)]
struct Measurement {
    mode: String,
    encode_setup_ms: f64,
    decode_setup_ms: f64,
    encode_total_ms: f64,
    encode_flush_ms: f64,
    decode_total_ms: f64,
    encode_cpu_ms: f64,
    decode_cpu_ms: f64,
    encode_fps: f64,
    decode_fps: f64,
    serial_codec_fps: f64,
    encoded_bytes: usize,
    bitrate_mbps_at_target_fps: f64,
    encode_call_ms: Distribution,
    decode_ms: Distribution,
    encoder_residence_codec_ms: Distribution,
    max_additional_inputs_before_packet: usize,
    psnr_y_db: Option<f64>,
    psnr_yuv_db: Option<f64>,
    encode_calls_over_frame_budget: usize,
    decode_frames_over_frame_budget: usize,
    peak_rss_bytes: u64,
    encode_call_samples_ms: Vec<f64>,
    samples: Vec<Sample>,
}
#[derive(Serialize, Deserialize)]
struct Case {
    request: Request,
    result: Option<Measurement>,
    error: Option<String>,
}
#[derive(Serialize)]
struct Report {
    schema_version: u32,
    fixture_version: u32,
    unix_time: u64,
    os: String,
    architecture: String,
    cpu: String,
    logical_cpus: usize,
    rustc: String,
    target: String,
    profile: String,
    rustflags: String,
    versions: serde_json::Value,
    assembly_enabled: bool,
    command: Vec<String>,
    cases: Vec<Case>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(path) = &args.worker {
        let req: Request = serde_json::from_slice(&fs::read(path)?)?;
        if req.warmup > 0 {
            measure(&req, req.warmup, false)?;
        }
        let result = measure(&req, req.frames, true)?;
        fs::write(&args.output, serde_json::to_vec(&result)?)?;
        return Ok(());
    }
    ensure!(
        env!("BENCH_PROFILE") == "release",
        "build with --release for meaningful results"
    );
    ensure!(
        args.frames > 0 && args.frames <= 600 && args.warmup <= 60,
        "frames must be 1..600; warmup 0..60"
    );
    ensure!(
        args.repeats > 0 && args.repeats <= 100 && args.fps > 0 && args.fps <= 240,
        "invalid repeats/fps"
    );
    ensure!(
        (1..=64).contains(&args.threads) && args.timeout > 0,
        "threads must be 1..64; timeout must be positive"
    );
    ensure!(
        args.vp8_q <= 127 && args.av1_q <= 255 && args.av1_speed <= 10 && args.av1_tiles <= 64,
        "invalid codec quantizer/speed"
    );
    for c in &args.codecs {
        ensure!(["vp8", "av1"].contains(&c.as_str()), "unknown codec {c}");
    }
    for w in &args.workloads {
        ensure!(
            frames::WORKLOADS.contains(&w.as_str()),
            "unknown workload {w}"
        );
    }
    let sizes: Vec<_> = args
        .sizes
        .iter()
        .map(|size| parse_size(size))
        .collect::<Result<_>>()?;
    let mut report = Report {
        schema_version: 1,
        fixture_version: 1,
        unix_time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        cpu: cpu_name(),
        logical_cpus: std::thread::available_parallelism().map_or(1, usize::from),
        rustc: env!("BENCH_RUSTC").into(),
        target: env!("BENCH_TARGET").into(),
        profile: env!("BENCH_PROFILE").into(),
        rustflags: env!("BENCH_RUSTFLAGS").into(),
        versions: serde_json::json!({"oxideav-vp8":"0.2.7", "rav1e":"0.8.1", "rav1d":"1.1.0", "rav1d_commit":"782dab2135ea64a057c097088a13eb8ed3cc3320"}),
        assembly_enabled: cfg!(feature = "asm"),
        command: std::env::args().collect(),
        cases: vec![],
    };
    if let Some(parent) = args.output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    eprintln!(
        "{} / {} / assembly={} / {} AV1 thread(s)",
        report.cpu, report.target, report.assembly_enabled, args.threads
    );
    if let Some(dir) = &args.export_streams {
        fs::create_dir_all(dir)?;
    }
    let mut requests = vec![];
    // Reverse codec order on alternating repeats to reduce systematic thermal/order bias.
    for repeat in 0..args.repeats {
        for &(width, height) in &sizes {
            for workload in &args.workloads {
                let mut codecs = args.codecs.clone();
                if repeat % 2 == 1 {
                    codecs.reverse();
                }
                for codec in codecs {
                    let req = Request {
                        codec: codec.clone(),
                        workload: workload.clone(),
                        settings: Settings {
                            width,
                            height,
                            fps: args.fps,
                            threads: args.threads,
                            vp8_q: args.vp8_q,
                            av1_q: args.av1_q,
                            av1_speed: args.av1_speed,
                            av1_tiles: args.av1_tiles,
                        },
                        frames: args.frames,
                        warmup: args.warmup,
                        repeat,
                        replay: None,
                        export: args.export_streams.as_ref().map(|dir| {
                            dir.join(format!(
                                "{codec}-{workload}-{width}x{height}-r{repeat}.espbench"
                            ))
                        }),
                    };
                    if args.decode_stream.is_empty() {
                        requests.push(req);
                    }
                }
            }
        }
        for path in &args.decode_stream {
            let (meta, _) = archive::load(path)?;
            let mut req = meta.request;
            req.settings.threads = args.threads;
            req.repeat = repeat;
            req.warmup = args.warmup.min(req.frames);
            req.export = None;
            req.replay = Some(fs::canonicalize(path)?);
            requests.push(req);
        }
    }
    for req in requests {
        eprintln!(
            "{} {} {}x{} repeat {}{} ...",
            req.codec,
            req.workload,
            req.settings.width,
            req.settings.height,
            req.repeat + 1,
            if req.replay.is_some() {
                " decode-only"
            } else {
                ""
            }
        );
        let outcome = run_worker(&req, args.timeout);
        let (result, error) = match outcome {
            Ok(m) => {
                eprintln!(
                    "  enc {:.1} fps, dec {:.1} fps, {:.3} Mbps, PSNR-Y {:?}, buffer {} frames",
                    m.encode_fps,
                    m.decode_fps,
                    m.bitrate_mbps_at_target_fps,
                    m.psnr_y_db,
                    m.max_additional_inputs_before_packet
                );
                (Some(m), None)
            }
            Err(e) => {
                eprintln!("  FAILED: {e:#}");
                (None, Some(format!("{e:#}")))
            }
        };
        report.cases.push(Case {
            request: req,
            result,
            error,
        });
        // Checkpoint after every case; completed work survives a later interruption.
        fs::write(&args.output, serde_json::to_vec_pretty(&report)?)?;
    }
    eprintln!(
        "Saved {} cases to {}",
        report.cases.len(),
        args.output.display()
    );
    ensure!(
        report.cases.iter().all(|c| c.error.is_none()),
        "some cases failed; see JSON report"
    );
    Ok(())
}
fn parse_size(size: &str) -> Result<(usize, usize)> {
    let (w, h) = size.split_once('x').context("size must be WIDTHxHEIGHT")?;
    let (w, h): (usize, usize) = (w.parse()?, h.parse()?);
    ensure!(
        (64..=4096).contains(&w) && (64..=2160).contains(&h) && w % 2 == 0 && h % 2 == 0,
        "sizes must be even and between 64x64 and 4096x2160"
    );
    Ok((w, h))
}
fn run_worker(req: &Request, timeout: u64) -> Result<Measurement> {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("request.json");
    let output = dir.path().join("result.json");
    let log = dir.path().join("stderr.txt");
    fs::write(&input, serde_json::to_vec(req)?)?;
    let mut child = Command::new(std::env::current_exe()?)
        .arg("--worker")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log)?)
        .spawn()?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(
                status.success(),
                "worker {status}: {}",
                fs::read_to_string(&log)?
            );
            return Ok(serde_json::from_slice(&fs::read(output)?)?);
        }
        if start.elapsed() >= Duration::from_secs(timeout) {
            child.kill()?;
            child.wait()?;
            bail!("case timed out after {timeout}s (includes warmup)");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn measure(req: &Request, count: usize, export: bool) -> Result<Measurement> {
    let s = &req.settings;
    let started = Instant::now();
    let mut encoder = if req.replay.is_none() {
        Some(Encoder::new(&req.codec, s)?)
    } else {
        None
    };
    let encode_setup_ms = if req.replay.is_none() {
        elapsed_ms(started)
    } else {
        0.0
    };
    let mut packets: Vec<(Packet, f64, usize)> = vec![];
    let mut input_times = vec![];
    let mut encode_calls = vec![];
    let mut encode_total = 0.0;
    let mut encode_cpu = 0.0;
    let mut bytes_total = 0usize;
    let mut flush_ms = 0.0;
    if let Some(encoder) = encoder.as_mut() {
        for index in 0..=count {
            let source =
                (index < count).then(|| frames::generate(s.width, s.height, index, &req.workload));
            input_times.push(encode_total);
            let cpu = cpu_ms();
            let start = Instant::now();
            let output = encoder.push(source.as_ref(), index)?;
            let ms = elapsed_ms(start);
            encode_cpu += cpu_ms() - cpu;
            encode_total += ms;
            if index < count {
                encode_calls.push(ms);
            } else {
                flush_ms = ms;
            }
            for p in output {
                ensure!(
                    p.index < count && p.index == packets.len(),
                    "missing, duplicated, or reordered output frame {}",
                    p.index
                );
                bytes_total += p.bytes.len();
                ensure!(
                    bytes_total <= 256 * 1024 * 1024,
                    "encoded stream exceeded benchmark 256 MiB safety limit"
                );
                let residence = encode_total - input_times[p.index];
                let extra = index.min(count - 1) - p.index;
                packets.push((p, residence, extra));
            }
        }
    } else {
        let (_, replay) = archive::load(req.replay.as_ref().unwrap())?;
        for p in replay.into_iter().take(count) {
            bytes_total += p.bytes.len();
            packets.push((p, 0.0, 0));
        }
    }
    if export && let Some(path) = &req.export {
        archive::save(path, req, &packets)?;
    }
    ensure!(
        packets.len() == count,
        "expected {count} frames; got {}",
        packets.len()
    );
    drop(encoder);
    let started = Instant::now();
    let mut decoder = Decoder::new(&req.codec, s)?;
    let decode_setup_ms = elapsed_ms(started);
    let mut samples = vec![];
    let mut total_y_error = 0u64;
    let mut total_error = 0u64;
    let mut decode_cpu = 0.0;
    for (p, residence, extra) in packets {
        let reference = frames::generate(s.width, s.height, p.index, &req.workload);
        let cpu = cpu_ms();
        let start = Instant::now();
        let decoded = decoder.decode(&p.bytes)?;
        let ms = elapsed_ms(start);
        decode_cpu += cpu_ms() - cpu;
        ensure!(
            decoded.width == s.width && decoded.height == s.height,
            "decoded dimensions mismatch"
        );
        let (y_error, error) = squared_error(&reference, &decoded)?;
        total_y_error += y_error;
        total_error += error;
        samples.push(Sample {
            frame: p.index,
            bytes: p.bytes.len(),
            keyframe: p.key,
            decode_ms: ms,
            encoder_residence_codec_ms: residence,
            additional_inputs_before_packet: extra,
            psnr_y_db: psnr(y_error, s.width * s.height),
            psnr_yuv_db: psnr(error, s.width * s.height * 3 / 2),
            decoded_checksum: checksum(&decoded),
            tile_grid: decoder.tile_grid(),
        });
    }
    let decode_times: Vec<_> = samples.iter().map(|s| s.decode_ms).collect();
    let residence: Vec<_> = samples
        .iter()
        .map(|s| s.encoder_residence_codec_ms)
        .collect();
    let decode_total: f64 = decode_times.iter().sum();
    let frame_budget = 1000.0 / s.fps as f64;
    Ok(Measurement {
        mode: if req.replay.is_some() {
            "decode-only"
        } else {
            "encode-decode"
        }
        .into(),
        encode_setup_ms,
        decode_setup_ms,
        encode_total_ms: encode_total,
        encode_flush_ms: flush_ms,
        decode_total_ms: decode_total,
        encode_cpu_ms: encode_cpu,
        decode_cpu_ms: decode_cpu,
        encode_fps: if encode_total > 0.0 {
            count as f64 * 1000.0 / encode_total
        } else {
            0.0
        },
        decode_fps: count as f64 * 1000.0 / decode_total,
        serial_codec_fps: count as f64 * 1000.0 / (encode_total + decode_total),
        encoded_bytes: bytes_total,
        bitrate_mbps_at_target_fps: bytes_total as f64 * 8.0 * s.fps as f64 / count as f64 / 1e6,
        encode_call_ms: distribution(&encode_calls),
        decode_ms: distribution(&decode_times),
        encoder_residence_codec_ms: distribution(&residence),
        max_additional_inputs_before_packet: samples
            .iter()
            .map(|s| s.additional_inputs_before_packet)
            .max()
            .unwrap_or(0),
        psnr_y_db: psnr(total_y_error, count * s.width * s.height),
        psnr_yuv_db: psnr(total_error, count * s.width * s.height * 3 / 2),
        encode_calls_over_frame_budget: encode_calls.iter().filter(|&&t| t > frame_budget).count(),
        decode_frames_over_frame_budget: decode_times.iter().filter(|&&t| t > frame_budget).count(),
        peak_rss_bytes: peak_rss(),
        encode_call_samples_ms: encode_calls,
        samples,
    })
}
fn checksum(f: &Frame) -> String {
    let hash = f
        .planes
        .iter()
        .flatten()
        .fold(0xcbf29ce484222325u64, |h, &b| {
            (h ^ b as u64).wrapping_mul(0x100000001b3)
        });
    format!("{hash:016x}")
}
fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
fn squared_error(a: &Frame, b: &Frame) -> Result<(u64, u64)> {
    let mut errors = [0u64; 3];
    for (i, error) in errors.iter_mut().enumerate() {
        ensure!(
            a.planes[i].len() == b.planes[i].len(),
            "decoded plane length mismatch"
        );
        *error = a.planes[i]
            .iter()
            .zip(&b.planes[i])
            .map(|(&x, &y)| {
                let d = x as i64 - y as i64;
                (d * d) as u64
            })
            .sum();
    }
    Ok((errors[0], errors.iter().sum()))
}
// null in JSON means lossless (positive infinity), never a missing measurement.
fn psnr(error: u64, samples: usize) -> Option<f64> {
    (error > 0).then(|| 10.0 * (255.0 * 255.0 * samples as f64 / error as f64).log10())
}
fn usage() -> libc::rusage {
    let mut u = std::mem::MaybeUninit::zeroed();
    // SAFETY: getrusage initializes this correctly sized allocation on success.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, u.as_mut_ptr()) };
    assert_eq!(rc, 0, "getrusage failed");
    unsafe { u.assume_init() }
}
fn cpu_ms() -> f64 {
    let u = usage();
    (u.ru_utime.tv_sec + u.ru_stime.tv_sec) as f64 * 1000.0
        + (u.ru_utime.tv_usec + u.ru_stime.tv_usec) as f64 / 1000.0
}
fn peak_rss() -> u64 {
    let rss = usage().ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        rss
    } else {
        rss * 1024
    }
}
fn cpu_name() -> String {
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo")
        && let Some(line) = cpuinfo.lines().find(|s| s.starts_with("model name"))
    {
        return line.split_once(':').unwrap().1.trim().into();
    }
    Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().into())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stats_and_quality() {
        let d = distribution(&[4.0, 1.0, 2.0, 3.0]);
        assert_eq!((d.mean, d.p50, d.p95, d.max), (2.5, 2.0, 4.0, 4.0));
        assert_eq!(psnr(0, 1), None);
        assert_eq!(psnr(65025, 1), Some(0.0));
        assert!(parse_size("1920x1080").is_ok());
        assert!(parse_size("1919x1080").is_err());
    }
    #[test]
    fn codec_roundtrips_multiple_frames() {
        for codec in ["vp8", "av1"] {
            let dir = tempfile::tempdir().unwrap();
            let corpus = dir.path().join("stream.espbench");
            let mut req = Request {
                codec: codec.into(),
                workload: "windows".into(),
                frames: 4,
                warmup: 0,
                repeat: 0,
                export: Some(corpus.clone()),
                replay: None,
                settings: Settings {
                    width: 256,
                    height: 256,
                    fps: 30,
                    threads: 1,
                    vp8_q: 32,
                    av1_q: 100,
                    av1_speed: 10,
                    av1_tiles: if codec == "av1" { 4 } else { 0 },
                },
            };
            let m = measure(&req, 4, true).unwrap();
            assert_eq!(m.samples.len(), 4);
            if codec == "av1" {
                assert!(m.samples[0].tile_grid.unwrap().iter().product::<usize>() > 1);
            }
            assert!(m.samples[0].keyframe);
            assert!(m.samples[1..].iter().any(|s| !s.keyframe));
            assert!(m.encoded_bytes > 0);
            assert!(m.psnr_y_db.unwrap_or(f64::INFINITY) > 15.0);
            req.export = None;
            req.replay = Some(corpus.clone());
            let replay = measure(&req, 4, false).unwrap();
            assert_eq!(replay.mode, "decode-only");
            assert_eq!(m.encoded_bytes, replay.encoded_bytes);
            for (a, b) in m.samples.iter().zip(&replay.samples) {
                assert_eq!(a.decoded_checksum, b.decoded_checksum);
            }
            let mut bytes = fs::read(&corpus).unwrap();
            bytes.pop();
            fs::write(&corpus, &bytes).unwrap();
            assert!(archive::load(&corpus).is_err());
            bytes[0] = 0;
            fs::write(&corpus, &bytes).unwrap();
            assert!(archive::load(&corpus).is_err());
        }
    }
}
