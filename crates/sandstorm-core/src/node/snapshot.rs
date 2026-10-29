//! Snapshot publication checks, shared by checkpoint, observation and restore.
//!
//! Successful runsc completion plus atomic rename establishes completion for new
//! images. The optional receipt detects missing/truncated files after publication;
//! it is not a checksum or a substitute for runsc compatibility at restore time.
//! Legacy images remain readable without a receipt. Their format has no universal
//! completion marker, so offline validation cannot prove every old image complete.
//! Format: https://github.com/google/gvisor/blob/master/pkg/state/statefile/statefile.go

use super::*;
use std::collections::BTreeMap;
use std::io::Read;

pub(super) type ValidationCache = std::sync::Arc<
    parking_lot::Mutex<
        std::collections::HashMap<PathBuf, Vec<(String, u64, std::time::SystemTime)>>,
    >,
>;

const RECEIPT: &str = "sandstorm-checkpoint.json";

impl Runtime {
    pub(super) fn pending_snapshots(&self, id: &str) -> PathBuf {
        self.cfg.work_dir.join("checkpoint-pending").join(id)
    }

    /// runsc owns the encoding; never try to decode its object graph ourselves.
    pub(super) fn validate_snapshot(&self, image: &Path) -> Result<()> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(image)? {
            let entry = entry?;
            let metadata = entry.path().symlink_metadata()?;
            if !metadata.is_file() {
                bail!("unexpected checkpoint entry {}", entry.path().display());
            }
            files.push((
                entry.file_name().to_string_lossy().into_owned(),
                metadata.len(),
                metadata.modified()?,
            ));
        }
        files.sort();
        if self.validated_snapshots.lock().get(image) == Some(&files) {
            return Ok(());
        }
        let lengths: BTreeMap<_, _> = files
            .iter()
            .map(|(name, len, _)| (name.clone(), *len))
            .collect();
        let mut state = std::fs::File::open(image.join("checkpoint.img"))?;
        let mut header = [0; 16];
        state
            .read_exact(&mut header)
            .context("reading checkpoint header")?;
        if &header[..8] != b"gVisorSF" {
            bail!("invalid checkpoint statefile header");
        }
        let metadata_len = u64::from_be_bytes(header[8..].try_into().unwrap());
        if metadata_len > 16 * 1024 * 1024 || state.metadata()?.len() <= 16 + metadata_len {
            bail!("truncated checkpoint statefile");
        }
        let mut metadata = vec![0; metadata_len as usize];
        state.read_exact(&mut metadata)?;
        let _: BTreeMap<String, String> =
            serde_json::from_slice(&metadata).context("reading checkpoint metadata")?;
        // Older images (including uncompressed ones) embed memory; split images
        // need both companions. A pages file may be empty when all pages are zero.
        match (lengths.get("pages_meta.img"), lengths.get("pages.img")) {
            (Some(meta), Some(_)) if *meta > 0 => (),
            (None, None) => (),
            _ => bail!("incomplete checkpoint pages files"),
        }
        if lengths.contains_key(RECEIPT) {
            let expected: BTreeMap<String, u64> =
                serde_json::from_slice(&std::fs::read(image.join(RECEIPT))?)?;
            let actual: BTreeMap<_, _> = lengths
                .iter()
                .filter(|(name, _)| name.as_str() != RECEIPT)
                .map(|(name, len)| (name.clone(), *len))
                .collect();
            if expected != actual {
                bail!("checkpoint files differ from the successfully published image");
            }
        }
        // shortcut: legacy files have no completion receipt; runsc's decoder
        // cannot distinguish an old single-file image from a split image missing both
        // companions. Upgrade this check when runsc exposes a full validator.
        self.runsc_timeout(
            &[
                "statefile",
                "--output=/dev/null",
                &image.join("checkpoint.img").to_string_lossy(),
            ],
            RUNSC_SNAPSHOT_TIMEOUT,
        )
        .context("validating checkpoint statefile")?;
        self.validated_snapshots
            .lock()
            .insert(image.to_path_buf(), files);
        Ok(())
    }

    pub(super) fn record_checkpoint(&self, image: &Path) -> Result<()> {
        let mut lengths = BTreeMap::new();
        for entry in std::fs::read_dir(image)? {
            let entry = entry?;
            lengths.insert(
                entry.file_name().to_string_lossy().into_owned(),
                entry.metadata()?.len(),
            );
        }
        std::fs::write(image.join(RECEIPT), serde_json::to_vec(&lengths)?)
            .context("recording successful checkpoint file lengths")
    }
}

// Linux renameat2 keeps the no-overwrite check atomic with publication.
#[cfg(target_os = "linux")]
pub(super) fn publish(source: &Path, destination: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let source = std::ffi::CString::new(source.as_os_str().as_bytes())?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())?;
    // Both C strings live through the syscall; no pointer is retained.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn publish(_source: &Path, _destination: &Path) -> Result<()> {
    bail!("atomic checkpoint publication requires Linux")
}
