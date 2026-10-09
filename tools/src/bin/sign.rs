//! Signing tool for the VexZygisk module.
//!
//! Implements module signing according to the following scheme:
//!   - machikado: runtime file signatures
//!   - misaki:    whole-module signature
//!   - sha256:    per-file SHA-256 hashes
//!
//! Usage:
//!   sign <module_dir> <private_key> <public_key>
//!   sign --no-sign <module_dir>
//!
//! The signature is over the exact bytes the Python fed Ed25519: a name, a NUL,
//! the file size as a little-endian i64, then the contents. Changing any of
//! that changes every signature, so it is reproduced here rather than tidied up.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ed25519_compact::{KeyPair, Seed};
use sha2::{Digest, Sha256};
use vex_tools::{sort_key, sort_key_str, sorted_children};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    // `--no-sign <dir>` is the only two-argument form; everything else needs
    // three. Both are checked before any of them is indexed, which is the whole
    // reason this is a match on the length rather than a series of guards.
    match argv.len() {
        0 | 1 => {
            usage();
            ExitCode::FAILURE
        }
        2 if argv[0] == "--no-sign" => {
            no_sign(Path::new(&argv[1]));
            ExitCode::SUCCESS
        }
        2 => {
            usage();
            ExitCode::FAILURE
        }
        // argv here has already had the program name removed, so these three
        // are what Python called sys.argv[1], [2] and [3].
        _ => sign(Path::new(&argv[0]), &argv[1], &argv[2]),
    }
}

fn usage() {
    eprintln!("Usage: sign <module_dir> <private_key> <public_key>");
    eprintln!("       sign --no-sign <module_dir>");
}

fn sign(root: &Path, private_key_path: &str, public_key_path: &str) -> ExitCode {
    let seed_bytes = match std::fs::read(private_key_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("cannot read {private_key_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let public_key = match std::fs::read(public_key_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("cannot read {public_key_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The Python read a 32-byte seed and passed it to
    // Ed25519PrivateKey.from_private_bytes, so this takes a seed and not a
    // full 64-byte secret key: KeyPair::from_slice would want seed+public and
    // would derive a different key from the same file.
    //
    // try_from_seed rather than from_seed, because from_seed panics on an
    // all-zero seed and this is fed by a file on disk.
    let seed = match Seed::from_slice(&seed_bytes) {
        Ok(seed) => seed,
        Err(_) => {
            eprintln!("{private_key_path} is not a 32-byte Ed25519 seed");
            return ExitCode::FAILURE;
        }
    };

    let key = match KeyPair::try_from_seed(seed) {
        Ok(key) => key,
        Err(_) => {
            eprintln!("{private_key_path} is an unusable Ed25519 seed");
            return ExitCode::FAILURE;
        }
    };

    println!("=== Guards the peace of Machikado ===");
    sign_machikado(root, &key, &public_key);
    compute_sha256_hashes(root);

    println!("===   At the kitsune's wedding   ===");
    sign_misaki(root, &key, &public_key);

    ExitCode::SUCCESS
}

fn no_sign(root: &Path) {
    println!("No private_key and public_key found, this build will not be signed");

    touch(&root.join("machikado.arm64"));
    compute_sha256_hashes(root);
    touch(&root.join("misaki.sig"));
}

fn touch(path: &Path) {
    if let Ok(mut file) = std::fs::File::create(path) {
        let _ = file.flush();
    }
}

/// Builds the sign data block for a single file:
/// name + NUL + 8-byte-LE file size + contents.
///
/// The Python streamed the contents in 8 KiB chunks, but the result is the same
/// byte string; what matters here is that the size is the size on disk and that
/// the file is not modified while it is read.
fn file_sign_data(name: &str, path: &Path) -> std::io::Result<Vec<u8>> {
    let size = std::fs::metadata(path)?.len();

    let mut data = Vec::with_capacity(name.len() + 9 + size as usize);
    data.extend_from_slice(name.as_bytes());
    data.push(0);
    data.extend_from_slice(&size.to_le_bytes());

    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);
    }

    Ok(data)
}

/// The signature block: the Ed25519 signature followed by the raw public key,
/// which is what the on-device verifier reads back.
fn write_signature(
    path: &Path,
    data: &[u8],
    key: &KeyPair,
    public_key: &[u8],
) -> std::io::Result<()> {
    // The Python's Ed25519 sign was the plain deterministic one, so noise is
    // None: a noisy signature would be a different byte string for the same
    // input, and the verifier expects the plain form.
    let signature = key.sk.sign(data, None);

    let mut out = Vec::with_capacity(signature.len() + public_key.len());
    out.extend_from_slice(signature.as_ref());
    out.extend_from_slice(public_key);

    std::fs::write(path, out)
}

/// Sign machikado for the single shipped architecture.
fn sign_machikado(root: &Path, key: &KeyPair, public_key: &[u8]) {
    // (real path, virtual name as it appears in the signature)
    let mut entries: Vec<(PathBuf, String)> = Vec::new();

    // The files where virtual = real. A name this module does not ship
    // (service.sh) is skipped rather than read, which would abort the build;
    // the verifier walks the files that are there.
    for name in [
        "module.prop",
        "rezygisk.sh",
        "late-load.sh",
        "sepolicy.rule",
        "post-fs-data.sh",
        "service.sh",
        "uninstall.sh",
    ] {
        let path = root.join(name);
        if path.is_file() {
            entries.push((path, name.to_string()));
        }
    }

    // lib64/libzygisk.so -> lib/arm64-v8a/libzygisk.so, signed as libzygisk.so
    entries.push((
        root.join("lib64").join("libzygisk.so"),
        "libzygisk.so".to_string(),
    ));

    // bin/zygisk-ptrace64 -> lib/arm64-v8a/libzygisk_ptrace.so
    entries.push((
        root.join("bin").join("zygisk-ptrace64"),
        "zygisk-ptrace64".to_string(),
    ));

    // bin/zygiskd64 -> bin/arm64-v8a/zygiskd
    entries.push((root.join("bin").join("zygiskd64"), "zygiskd64".to_string()));

    // Sort by virtual path, then by real path so the order is total: the Python
    // sorted on the tuple's first element alone, which left entries sharing a
    // virtual path in filesystem order.
    entries.sort_by(|a, b| {
        sort_key(&a.0)
            .cmp(&sort_key(&b.0))
            .then_with(|| sort_key_str(&a.1).cmp(&sort_key_str(&b.1)))
    });

    let mut data = Vec::new();
    for (real, virtual_name) in &entries {
        // An entry whose real file is absent is skipped: reading it would abort
        // the whole build.
        if !real.is_file() {
            continue;
        }

        match file_sign_data(virtual_name, real) {
            Ok(block) => data.extend_from_slice(&block),
            Err(e) => {
                eprintln!("  skipping [{}]: {e}", real.display());
            }
        }
    }

    let sig_path = root.join("machikado.arm64");
    if let Err(e) = write_signature(&sig_path, &data, key, public_key) {
        eprintln!("  cannot write machikado.arm64: {e}");
        return;
    }

    println!("  Signed machikado.arm64");
}

/// SHA-256 for every file in the module directory, each written next to it as
/// `<name>.sha256`.
fn compute_sha256_hashes(root: &Path) {
    walk(root, &mut |path: &Path| {
        // Don't hash the .sha256 files themselves.
        if path.extension().is_some_and(|e| e == "sha256") {
            return;
        }

        let Ok(mut file) = std::fs::File::open(path) else {
            return;
        };

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 4096];
        loop {
            let read = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => return,
            };
            hasher.update(&buffer[..read]);
        }

        let mut hash_path = path.as_os_str().to_os_string();
        hash_path.push(".sha256");
        let _ = std::fs::write(PathBuf::from(hash_path), format!("{:x}", hasher.finalize()));
    });
}

/// Sign misaki.sig for the entire module, excluding misaki.sig itself.
fn sign_misaki(root: &Path, key: &KeyPair, public_key: &[u8]) {
    let mut all_files = Vec::new();
    walk(root, &mut |path: &Path| {
        if path.file_name().is_some_and(|n| n == "misaki.sig") {
            return;
        }
        all_files.push(path.to_path_buf());
    });

    // The Python sorted the collected paths before signing.
    all_files.sort_by_key(|p| sort_key(p));

    let mut data = Vec::new();
    for path in &all_files {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        match file_sign_data(name, path) {
            Ok(block) => data.extend_from_slice(&block),
            Err(e) => eprintln!("  skipping [{}]: {e}", path.display()),
        }
    }

    let sig_path = root.join("misaki.sig");
    if let Err(e) = write_signature(&sig_path, &data, key, public_key) {
        eprintln!("  cannot write misaki.sig: {e}");
        return;
    }

    println!("  Signed misaki.sig");
}

/// Depth-first walk yielding files only, sorted at every level so the traversal
/// order is the same on every filesystem.
///
/// `Path::rglob` walks in whatever order the readdir returns, which the Python
/// then re-sorted; sorting here instead means a tree written twice produces
/// byte-identical signatures.
fn walk(dir: &Path, visit: &mut impl FnMut(&Path)) {
    for entry in sorted_children(dir) {
        if entry.is_dir() {
            walk(&entry, visit);
        } else if entry.is_file() {
            visit(&entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vex-sign-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sign_data_is_name_nul_size_contents() {
        let dir = temp_dir("block");
        let file = dir.join("a.bin");
        std::fs::write(&file, b"hello").unwrap();

        let data = file_sign_data("a.bin", &file).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(b"a.bin");
        expected.push(0);
        expected.extend_from_slice(&5u64.to_le_bytes());
        expected.extend_from_slice(b"hello");

        assert_eq!(data, expected);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_file_still_carries_its_name_and_size() {
        let dir = temp_dir("empty");
        let file = dir.join("empty");
        std::fs::write(&file, b"").unwrap();

        let data = file_sign_data("empty", &file).unwrap();

        assert_eq!(data, b"empty\0\0\0\0\0\0\0\0\0".to_vec());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_walk_is_sorted_and_skips_nothing_under_a_directory() {
        let dir = temp_dir("walk");
        std::fs::create_dir_all(dir.join("z")).unwrap();
        std::fs::create_dir_all(dir.join("a")).unwrap();
        std::fs::write(dir.join("z").join("2"), b"2").unwrap();
        std::fs::write(dir.join("a").join("1"), b"1").unwrap();
        std::fs::write(dir.join("top"), b"t").unwrap();

        let mut seen = Vec::new();
        walk(&dir, &mut |p: &Path| {
            seen.push(sort_key(p));
        });

        assert_eq!(
            seen,
            vec![
                sort_key(&dir.join("a").join("1")),
                sort_key(&dir.join("top")),
                sort_key(&dir.join("z").join("2")),
            ]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_signature_block_is_signature_then_public_key() {
        let dir = temp_dir("block2");
        let key = test_key();

        let path = dir.join("sig");
        write_signature(&path, b"data", &key, key.pk.as_ref()).unwrap();

        let written = std::fs::read(&path).unwrap();
        assert_eq!(written.len(), 64 + 32);

        // The trailing 32 bytes are the public key the verifier reads.
        assert_eq!(&written[64..], key.pk.as_ref());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A key pair from a fixed non-zero seed, the way the signer builds one.
    fn test_key() -> KeyPair {
        KeyPair::try_from_seed(Seed::from_slice(&[7u8; 32]).unwrap()).unwrap()
    }

    #[test]
    fn a_seed_of_the_wrong_length_is_refused() {
        // 16 bytes and 64 bytes are the two mistakes worth naming: the second is
        // what a seed concatenated with its public key would look like.
        assert!(Seed::from_slice(&[0u8; 16]).is_err());
        assert!(Seed::from_slice(&[7u8; 64]).is_err());
        assert!(Seed::from_slice(&[]).is_err());
        assert!(Seed::from_slice(&[7u8; 32]).is_ok());
    }

    #[test]
    fn an_all_zero_seed_is_refused_rather_than_panicking() {
        // from_seed would panic here, which is why the signer uses try_from_seed.
        let zero = Seed::from_slice(&[0u8; 32]).unwrap();
        assert!(KeyPair::try_from_seed(zero).is_err());
    }

    #[test]
    fn signing_is_deterministic_so_a_release_signs_identically_twice() {
        let key = test_key();
        assert_eq!(key.sk.sign(b"same", None), key.sk.sign(b"same", None));
        assert_ne!(key.sk.sign(b"same", None), key.sk.sign(b"different", None));
    }
}
