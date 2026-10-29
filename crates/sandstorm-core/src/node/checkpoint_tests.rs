use super::*;
use std::os::unix::fs::PermissionsExt;

// The header follows runsc; the payload/decoder are deliberately fake. These
// tests exercise publication and failure handling, not real gVisor restoration.
pub(super) fn fixture(work: &Path, image: &Path) {
    std::fs::create_dir_all(image).unwrap();
    let metadata = br#"{"compression":"flate-best-speed"}"#;
    let mut bytes = b"gVisorSF".to_vec();
    bytes.extend_from_slice(&(metadata.len() as u64).to_be_bytes());
    bytes.extend_from_slice(metadata);
    bytes.extend_from_slice(b"fake encoded state");
    std::fs::write(image.join("checkpoint.img"), &bytes).unwrap();
    std::fs::write(work.join("fixture.img"), bytes).unwrap();
    std::fs::write(work.join("fake-runsc"), r#"#!/bin/sh
set -eu
work="$2"
shift 2
command="$1"
shift
printf '%s\n' "$command" >> "$work/calls"
mode=$(cat "$work/mode" 2>/dev/null || printf success)
case "$command" in
checkpoint)
  image="${1#--image-path=}"
  case "$mode" in
    nonzero) printf partial > "$image/checkpoint.img"; echo checkpoint-failed >&2; exit 23 ;;
    timeout) printf partial > "$image/checkpoint.img"; exec sleep 10 ;;
    empty) exit 0 ;;
    malformed) cp "$work/fixture.img" "$image/checkpoint.img"; printf invalid >> "$image/checkpoint.img"; exit 0 ;;
    partial) cp "$work/fixture.img" "$image/checkpoint.img"; printf partial > "$image/pages_meta.img"; exit 0 ;;
  esac
  cp "$work/fixture.img" "$image/checkpoint.img"
  : > "$work/cgroups/sb1/cgroup.procs"
  if [ "$mode" = collision ]; then mkdir -p "$work/snapshots/sb1"; echo keep > "$work/snapshots/sb1/existing"; fi
  ;;
statefile)
  cmp "$2" "$work/fixture.img" >/dev/null || { echo malformed-state >&2; exit 24; }
  ;;
delete)
  if [ "$mode" = delete-failure ]; then echo delete-failed >&2; exit 25; fi
  if [ "$mode" = staging-cleanup-failure ]; then mv "$work/checkpoint-pending/sb1" "$work/retained-attempts"; echo blocked > "$work/checkpoint-pending/sb1"; fi
  ;;
restore)
  echo 123 > "$work/cgroups/sb1/cgroup.procs"
  if [ "$mode" = cleanup-failure ]; then mv "$work/snapshots/sb1" "$work/saved-image"; echo blocked > "$work/snapshots/sb1"; fi
  ;;
*) exit 0 ;;
esac
"#).unwrap();
    std::fs::set_permissions(
        work.join("fake-runsc"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}

fn setup() -> (tempfile::TempDir, Runtime) {
    let work = tempfile::tempdir().unwrap();
    fixture(work.path(), &work.path().join("fixture"));
    std::fs::create_dir_all(work.path().join("bundles/sb1")).unwrap();
    std::fs::write(
        work.path().join("bundles/sb1/config.json"),
        "original bundle",
    )
    .unwrap();
    std::fs::create_dir_all(work.path().join("cgroups/sb1")).unwrap();
    std::fs::write(work.path().join("cgroups/sb1/cgroup.procs"), "123").unwrap();
    let mut runtime = Runtime::new(RuntimeConfig {
        runsc: work
            .path()
            .join("fake-runsc")
            .to_string_lossy()
            .into_owned(),
        runsc_root: work.path().to_path_buf(),
        work_dir: work.path().to_path_buf(),
        volume_root: work.path().join("volumes"),
        ..Default::default()
    })
    .unwrap();
    runtime.cgroup_root = Some(work.path().join("cgroups"));
    (work, runtime)
}

#[test]
fn checkpoint_failures_never_publish_and_running_sandboxes_can_retry() {
    for mode in ["nonzero", "timeout", "empty", "partial", "malformed"] {
        let (work, runtime) = setup();
        std::fs::write(work.path().join("mode"), mode).unwrap();
        let timeout = if mode == "timeout" {
            Duration::from_millis(80)
        } else {
            Duration::from_secs(5)
        };
        let error = runtime.checkpoint_timeout("sb1", timeout).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("checkpoint"), "{mode}: {message}");
        if mode == "nonzero" {
            assert!(message.contains("checkpoint-failed"));
        }
        if mode == "timeout" {
            assert!(message.contains("did not finish"));
        }
        if mode == "malformed" {
            assert!(message.contains("malformed-state"));
        }
        if mode == "partial" {
            assert!(message.contains("incomplete checkpoint pages"));
        }
        assert!(!work.path().join("snapshots/sb1").exists());
        assert_eq!(runtime.observe().unwrap()[0].tier, Tier::Hot);
        assert!(runtime.pending_snapshots("sb1").exists());
        std::fs::write(work.path().join("mode"), "success").unwrap();
        runtime.checkpoint("sb1").unwrap();
        assert_eq!(runtime.observe().unwrap()[0].tier, Tier::Snapshot);
        assert!(!runtime.pending_snapshots("sb1").exists());
        runtime.restore("sb1").unwrap();
        assert_eq!(runtime.observe().unwrap()[0].tier, Tier::Hot);
        assert!(!work.path().join("snapshots/sb1").exists());
        std::fs::write(work.path().join("cgroups/sb1/cgroup.procs"), "").unwrap();
        assert_eq!(runtime.dead(Duration::ZERO), vec!["sb1"]);
    }
}

#[test]
fn pending_data_survives_restart_without_becoming_a_snapshot_or_being_reaped() {
    let (work, runtime) = setup();
    std::fs::write(work.path().join("mode"), "nonzero").unwrap();
    runtime.checkpoint("sb1").unwrap_err();
    std::fs::write(work.path().join("cgroups/sb1/cgroup.procs"), "").unwrap();
    let mut restarted = Runtime::new(runtime.cfg.clone()).unwrap();
    restarted.cgroup_root = runtime.cgroup_root.clone();
    assert!(restarted.observe().unwrap().is_empty());
    assert!(restarted.dead(Duration::ZERO).is_empty());
    let error = restarted
        .create(&CreateRequest {
            id: "sb1",
            template: "missing",
            spec: &serde_json::json!({}),
            port: 80,
            volume: None,
            net_index: None,
            from_tag: None,
            gateway_port: None,
            token: "",
        })
        .unwrap_err();
    assert!(error.to_string().contains("refusing to recreate"));
    assert_eq!(
        std::fs::read_to_string(work.path().join("bundles/sb1/config.json")).unwrap(),
        "original bundle"
    );
}

#[test]
fn publication_failure_preserves_both_images_and_reports_the_path() {
    let (work, runtime) = setup();
    std::fs::write(work.path().join("mode"), "collision").unwrap();
    let error = format!("{:#}", runtime.checkpoint("sb1").unwrap_err());
    assert!(error.contains("destination already exists"), "{error}");
    assert_eq!(
        std::fs::read_to_string(work.path().join("snapshots/sb1/existing")).unwrap(),
        "keep\n"
    );
    let attempt = std::fs::read_dir(runtime.pending_snapshots("sb1"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(attempt.join("checkpoint.img").is_file());
    assert!(runtime.observe().unwrap().is_empty());
    assert!(runtime.dead(Duration::ZERO).is_empty());
}

#[test]
fn successful_snapshot_is_not_overwritten_and_detects_later_truncation() {
    let (work, runtime) = setup();
    runtime.checkpoint("sb1").unwrap();
    let image = work.path().join("snapshots/sb1/checkpoint.img");
    let original = std::fs::read(&image).unwrap();
    assert!(runtime
        .checkpoint("sb1")
        .unwrap_err()
        .to_string()
        .contains("overwrite"));
    assert_eq!(std::fs::read(&image).unwrap(), original);
    assert_eq!(runtime.observe().unwrap()[0].tier, Tier::Snapshot);
    std::fs::write(&image, &original[..original.len() - 1]).unwrap();
    assert!(runtime.observe().unwrap().is_empty());
    assert!(runtime.restore("sb1").is_err());
}

#[test]
fn restore_cleanup_failure_is_reported_without_hiding_running_sandbox() {
    let (work, runtime) = setup();
    runtime.checkpoint("sb1").unwrap();
    std::fs::write(work.path().join("mode"), "cleanup-failure").unwrap();
    let error = runtime.restore("sb1").unwrap_err();
    assert!(error.to_string().contains("cleaning restored checkpoint"));
    assert_eq!(runtime.observe().unwrap()[0].tier, Tier::Hot);
    assert!(work.path().join("saved-image/checkpoint.img").exists());
}

#[test]
fn delete_failure_keeps_the_published_recovery_image() {
    let (work, runtime) = setup();
    std::fs::write(work.path().join("mode"), "delete-failure").unwrap();
    let error = format!("{:#}", runtime.checkpoint("sb1").unwrap_err());
    assert!(error.contains("delete-failed"));
    assert_eq!(runtime.observe().unwrap()[0].tier, Tier::Snapshot);
}

#[test]
fn atomic_publication_never_replaces_an_existing_directory() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    let destination = work.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(source.join("keep"), "data").unwrap();
    assert!(snapshot::publish(&source, &destination).is_err());
    assert!(source.join("keep").exists());
    assert!(destination.is_dir());
}

#[test]
fn legacy_empty_directory_does_not_block_a_live_retry() {
    let (work, runtime) = setup();
    std::fs::create_dir_all(work.path().join("snapshots/sb1")).unwrap();
    runtime.checkpoint("sb1").unwrap();
    assert_eq!(runtime.observe().unwrap()[0].tier, Tier::Snapshot);
    assert!(!runtime.pending_snapshots("sb1").exists());
}

#[test]
fn incomplete_legacy_images_are_not_observed() {
    for missing in ["checkpoint.img", "pages.img", "pages_meta.img"] {
        let (work, runtime) = setup();
        let image = work.path().join("snapshots/sb1");
        fixture(work.path(), &image);
        std::fs::write(image.join("pages_meta.img"), "metadata").unwrap();
        std::fs::write(image.join("pages.img"), "pages").unwrap();
        std::fs::remove_file(image.join(missing)).unwrap();
        std::fs::write(work.path().join("cgroups/sb1/cgroup.procs"), "").unwrap();
        assert!(runtime.observe().unwrap().is_empty(), "{missing}");
    }
}

#[test]
fn a_receipt_detects_both_missing_page_files_after_restart() {
    let (work, runtime) = setup();
    let image = work.path().join("snapshots/sb1");
    fixture(work.path(), &image);
    std::fs::write(image.join("pages_meta.img"), "metadata").unwrap();
    std::fs::write(image.join("pages.img"), "pages").unwrap();
    runtime.record_checkpoint(&image).unwrap();
    std::fs::remove_file(image.join("pages_meta.img")).unwrap();
    std::fs::remove_file(image.join("pages.img")).unwrap();
    std::fs::write(work.path().join("cgroups/sb1/cgroup.procs"), "").unwrap();
    let mut restarted = Runtime::new(runtime.cfg.clone()).unwrap();
    restarted.cgroup_root = runtime.cgroup_root.clone();
    assert!(restarted.observe().unwrap().is_empty());
}

#[test]
fn explicit_destroy_removes_retained_attempts() {
    let (work, runtime) = setup();
    std::fs::write(work.path().join("mode"), "nonzero").unwrap();
    runtime.checkpoint("sb1").unwrap_err();
    std::fs::write(work.path().join("cgroups/sb1/cgroup.procs"), "").unwrap();
    runtime.destroy("sb1").unwrap();
    assert!(!runtime.pending_snapshots("sb1").exists());
}

#[test]
fn staging_cleanup_failure_reports_error_and_preserves_published_snapshot() {
    let (work, runtime) = setup();
    std::fs::write(work.path().join("mode"), "staging-cleanup-failure").unwrap();
    let error = runtime.checkpoint("sb1").unwrap_err();
    assert!(error
        .to_string()
        .contains("cleaning superseded checkpoint attempts"));
    assert_eq!(runtime.observe().unwrap()[0].tier, Tier::Snapshot);
    assert!(work.path().join("snapshots/sb1/checkpoint.img").exists());
}

#[test]
fn unchanged_snapshot_is_not_decoded_on_every_poll() {
    let (work, runtime) = setup();
    runtime.checkpoint("sb1").unwrap();
    runtime.observe().unwrap();
    let before = std::fs::read_to_string(work.path().join("calls")).unwrap();
    runtime.observe().unwrap();
    assert_eq!(
        std::fs::read_to_string(work.path().join("calls")).unwrap(),
        before
    );
}

#[test]
fn restore_after_interrupted_cleanup_removes_superseded_attempts() {
    let (work, runtime) = setup();
    runtime.checkpoint("sb1").unwrap();
    let pending = runtime.pending_snapshots("sb1").join("interrupted");
    std::fs::create_dir_all(&pending).unwrap();
    std::fs::write(pending.join("checkpoint.img"), "partial").unwrap();
    let mut restarted = Runtime::new(runtime.cfg.clone()).unwrap();
    restarted.cgroup_root = runtime.cgroup_root.clone();
    assert_eq!(restarted.observe().unwrap()[0].tier, Tier::Snapshot);
    restarted.restore("sb1").unwrap();
    assert!(!runtime.pending_snapshots("sb1").exists());
    std::fs::write(work.path().join("cgroups/sb1/cgroup.procs"), "").unwrap();
    assert_eq!(restarted.dead(Duration::ZERO), vec!["sb1"]);
}

#[test]
fn a_running_sandbox_can_retry_after_restore_left_a_valid_snapshot() {
    let (work, runtime) = setup();
    runtime.checkpoint("sb1").unwrap();
    // State after restore succeeded but removing its source directory failed.
    std::fs::write(work.path().join("cgroups/sb1/cgroup.procs"), "123").unwrap();
    let original = std::fs::read(work.path().join("snapshots/sb1/checkpoint.img")).unwrap();
    std::fs::write(work.path().join("mode"), "nonzero").unwrap();
    let error = format!("{:#}", runtime.checkpoint("sb1").unwrap_err());
    assert!(error.contains("checkpoint-failed"), "{error}");
    let retained = std::fs::read_dir(runtime.pending_snapshots("sb1"))
        .unwrap()
        .filter_map(|entry| std::fs::read(entry.unwrap().path().join("checkpoint.img")).ok())
        .any(|bytes| bytes == original);
    assert!(
        retained,
        "the previous valid image must survive the failed retry"
    );
    std::fs::write(work.path().join("mode"), "success").unwrap();
    runtime.checkpoint("sb1").unwrap();
    assert_eq!(runtime.observe().unwrap()[0].tier, Tier::Snapshot);
    assert!(!runtime.pending_snapshots("sb1").exists());
}
