//! Tree copies from a hostile peer: whatever the tar stream says, nothing
//! is written outside the target, and only plain files and directories
//! without setuid bits appear.
#![no_main]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use libfuzzer_sys::fuzz_target;

fn check(dir: &Path) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let meta = std::fs::symlink_metadata(e.path()).unwrap();
        assert!(meta.is_dir() || meta.is_file(), "{:?}", e.path());
        assert_eq!(meta.permissions().mode() & 0o7000, 0, "{:?}", e.path());
        if meta.is_dir() {
            check(&e.path());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let root = tempfile::tempdir().unwrap();
    let dest = root.path().join("dest");
    std::fs::create_dir(&dest).unwrap();
    let _ = qsh::tree::extract_tree(data, &dest);
    check(&dest);
    let names: Vec<_> = std::fs::read_dir(root.path()).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(names, ["dest"], "wrote outside the target");
    let mut chunked = qsh::tree::Unchunk::new(data);
    let _ = std::io::copy(&mut std::io::Read::take(&mut chunked, 1 << 16), &mut std::io::sink());
});
