//! What this machine can do for density, found out rather than assumed.
//!
//! Both levers here are plain Linux and plain runsc -- no CPU feature, no
//! kernel patch, no particular cloud -- but whether each one *helps*
//! depends on the machine, so each is probed at startup and either turned
//! on or left off with the reason logged. A node where neither applies
//! behaves exactly as it did before.
//!
//! Measured on bm (2 vCPU, 3.6 GiB, ~110 MB/s cloud disk, kernel 7.0) with
//! a 376 MiB Python heap -- 40 MiB random, the rest objects and JSON:
//!
//! | frozen, as before                          | 376 MiB held | thaw + touch all:   60 ms |
//! | frozen + reclaim into zswap, no writeback  | 113 MiB held | thaw + touch all:  310 ms |
//! | frozen + reclaim, writeback allowed        |  13-115 MiB  | thaw + touch all: 0.4-3.9 s |
//!
//! | snapshot image, uncompressed | 363 MiB | restore cold 3.3 s, warm 138 ms |
//! | snapshot image, flate        |  84 MiB | restore cold 1.4 s, warm 696 ms |
//!
//! Also tried and not adopted, because they did nothing there: `runsc
//! restore --background` (returns early, but the app cannot run until the
//! whole image is in -- 2.06 s either way), `--exclude-committed-zero-pages`
//! (gVisor already leaves zero pages out), and `--direct` (3.2 s warm,
//! since it bypasses the page cache that makes warm restores fast).

use std::path::Path;
use std::time::Instant;

/// Whether to use a lever: decided by probing, or forced either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lever {
    #[default]
    Auto,
    On,
    Off,
}

impl std::str::FromStr for Lever {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "auto" => Ok(Self::Auto),
            "on" => Ok(Self::On),
            "off" => Ok(Self::Off),
            _ => Err(format!("{s}: expected auto, on or off")),
        }
    }
}

/// Swap that lands in compressed RAM, if this machine has any.
///
/// That is what makes reclaiming a frozen sandbox worth it. Reclaimed into
/// zswap or zram, its pages come back at memory speed -- 310 ms for all of
/// a 376 MiB heap on bm. Reclaimed onto a disk swap file they come back at
/// disk speed, 3.9 s, which is worse than a snapshot restore and gains
/// nothing the kernel would not do by itself under pressure.
pub fn compressed_swap() -> Option<&'static str> {
    let swaps = std::fs::read_to_string("/proc/swaps").ok()?;
    let devices: Vec<&str> = swaps
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    if devices.is_empty() {
        return None;
    }
    if devices.iter().any(|d| d.starts_with("/dev/zram")) {
        return Some("zram");
    }
    let zswap = std::fs::read_to_string("/sys/module/zswap/parameters/enabled")
        .map(|s| matches!(s.trim(), "Y" | "1"))
        .unwrap_or(false);
    zswap.then_some("zswap")
}

/// Decide whether to reclaim frozen sandboxes. Returns the decision and
/// why, for the startup log.
pub fn decide_reclaim(lever: Lever) -> (bool, String) {
    match (lever, compressed_swap()) {
        (Lever::Off, _) => (false, "turned off".into()),
        (Lever::On, Some(kind)) => (true, format!("forced on; swap is {kind}")),
        (Lever::On, None) => (
            true,
            "forced on, but no compressed swap: frozen pages will go to disk".into(),
        ),
        (Lever::Auto, Some(kind)) => (true, format!("swap is {kind}")),
        (Lever::Auto, None) => (
            false,
            "no zswap or zram; reclaiming to disk swap would thaw slower than a snapshot restores"
                .into(),
        ),
    }
}

/// Below this read throughput, a compressed snapshot restores faster from
/// a cold cache than an uncompressed one.
///
/// From bm: flate cut a 363 MiB image to 84 MiB and decompressed at about
/// 650 MB/s of output. Restoring uncompressed takes 363/R s, compressed
/// about 0.56 + 84/R, and the two meet at R ≈ 500 MB/s. Cloud block disks
/// are mostly well under that; local NVMe is well over it.
pub const COMPRESS_BELOW_MBPS: f64 = 500.0;

/// Sequential read throughput of the filesystem holding `dir`, uncached.
///
/// Writes a 64 MiB file, has the kernel drop it from the page cache, and
/// times reading it back. `posix_fadvise(DONTNEED)` on a synced file is
/// how any process can do that without root or `drop_caches`, and it works
/// on every Linux filesystem.
pub fn disk_read_mbps(dir: &Path) -> std::io::Result<f64> {
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;

    const SIZE: usize = 64 * 1024 * 1024;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(".forkd-disk-probe");
    let result = (|| {
        let mut f = std::fs::File::create(&path)?;
        // Not zeros: a filesystem that compresses or dedups would make
        // zeros look impossibly fast.
        let mut block = vec![0u8; 1024 * 1024];
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for chunk in block.chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            chunk.copy_from_slice(&x.to_le_bytes()[..chunk.len()]);
        }
        for i in 0..SIZE / block.len() {
            block[0] = i as u8;
            f.write_all(&block)?;
        }
        f.sync_all()?;
        drop_cached(f.as_raw_fd());

        let mut f = std::fs::File::open(&path)?;
        drop_cached(f.as_raw_fd());
        let t0 = Instant::now();
        let mut n = 0;
        loop {
            let r = f.read(&mut block)?;
            if r == 0 {
                break;
            }
            n += r;
        }
        let secs = t0.elapsed().as_secs_f64().max(1e-6);
        Ok(n as f64 / 1e6 / secs)
    })();
    let _ = std::fs::remove_file(&path);
    result
}

fn drop_cached(fd: i32) {
    // SAFETY: a plain advisory syscall on a descriptor we own; it has no
    // memory-safety preconditions and its failure only makes the probe
    // read from cache, which the caller sees as a fast disk.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = fd;
}

/// Decide whether to compress snapshots. Returns the decision and why.
pub fn decide_compression(lever: Lever, work_dir: &Path) -> (bool, String) {
    match lever {
        Lever::Off => (false, "turned off".into()),
        Lever::On => (true, "forced on".into()),
        Lever::Auto => match disk_read_mbps(work_dir) {
            Ok(mbps) if mbps < COMPRESS_BELOW_MBPS => (
                true,
                format!("disk reads {mbps:.0} MB/s, below {COMPRESS_BELOW_MBPS:.0}: smaller images restore faster"),
            ),
            Ok(mbps) => (
                false,
                format!("disk reads {mbps:.0} MB/s: decompressing would be the slower part"),
            ),
            Err(e) => (false, format!("could not probe the disk ({e}); left off")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levers_parse() {
        assert_eq!("auto".parse::<Lever>(), Ok(Lever::Auto));
        assert_eq!("on".parse::<Lever>(), Ok(Lever::On));
        assert_eq!("off".parse::<Lever>(), Ok(Lever::Off));
        assert!("yes".parse::<Lever>().is_err());
    }

    #[test]
    fn off_and_on_are_not_second_guessed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!decide_reclaim(Lever::Off).0);
        assert!(decide_reclaim(Lever::On).0);
        assert!(!decide_compression(Lever::Off, dir.path()).0);
        assert!(decide_compression(Lever::On, dir.path()).0);
    }

    #[test]
    fn the_disk_probe_measures_something_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let mbps = disk_read_mbps(dir.path()).unwrap();
        assert!(mbps > 0.0);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
