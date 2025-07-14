// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use once_cell::sync::Lazy;
use std::{
    fs,
    io::{BufRead, BufReader, Error, ErrorKind},
    path::{Path, PathBuf},
};
use walkdir::DirEntry;

static PROJECT_ROOT: Lazy<PathBuf> = Lazy::new(|| {
    std::path::Path::new(&env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
});

const REQUIRED_TEXT: &str = "Licensed under the Apache-2.0 license";
const EXTENSIONS: &[&str] = &["rs", "toml", "sh", "py", "yml", "yaml"];
const IGNORED_DIRS: &[&str] = &[".git", "target", "xtask"];
const IGNORED_FILES: &[&str] = &["Cargo.lock"];

pub fn check() -> Result<()> {
    println!("Checking license headers...");

    let files = find_files(&PROJECT_ROOT, EXTENSIONS)?;
    let mut failed = false;

    for file in files.iter() {
        if let Err(e) = check_file(file) {
            println!("{}", e);
            failed = true;
        }
    }

    if failed {
        bail!("Some files failed license header check. Run 'cargo xtask header-fix' to fix.");
    }

    println!("✅ All files have correct license headers");
    Ok(())
}

pub fn fix() -> Result<()> {
    println!("Fixing license headers...");

    let files = find_files(&PROJECT_ROOT, EXTENSIONS)?;
    let mut fixed_count = 0;

    for file in files.iter() {
        if check_file(file).is_err() {
            fix_file(file)?;
            fixed_count += 1;
            println!("Fixed: {}", relative_path(file));
        }
    }

    if fixed_count == 0 {
        println!("✅ No files needed license header fixes");
    } else {
        println!("✅ Fixed license headers in {} files", fixed_count);
    }

    Ok(())
}

fn find_files(dir: &Path, extensions: &[&str]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry?;

        if !allow_file(&entry) {
            continue;
        }

        if let Some(ext) = entry.path().extension() {
            if let Some(ext_str) = ext.to_str() {
                if extensions.contains(&ext_str) {
                    files.push(entry.into_path());
                }
            }
        }
    }

    files.sort();
    Ok(files)
}

fn allow_file(entry: &DirEntry) -> bool {
    let path = entry.path();

    // Skip ignored directories
    if path.is_dir() {
        if let Some(name) = path.file_name() {
            if let Some(name_str) = name.to_str() {
                if IGNORED_DIRS.contains(&name_str) {
                    return false;
                }
            }
        }
    }

    // Skip ignored files
    if path.is_file() {
        if let Some(name) = path.file_name() {
            if let Some(name_str) = name.to_str() {
                if IGNORED_FILES.contains(&name_str) {
                    return false;
                }
            }
        }
    }

    true
}

fn check_file(path: &Path) -> Result<(), Error> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);

    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        if line.contains(REQUIRED_TEXT) {
            return Ok(());
        }

        // Only check first 5 lines
        if line_num >= 4 {
            break;
        }
    }

    Err(Error::new(
        ErrorKind::Other,
        format!(
            "File {:?} doesn't contain \"{}\" in the first 5 lines",
            relative_path(path),
            REQUIRED_TEXT
        ),
    ))
}

fn fix_file(path: &Path) -> Result<(), Error> {
    let contents = fs::read_to_string(path)?;

    let header = match path.extension().and_then(|s| s.to_str()) {
        Some("rs") => format!("// {}\n\n", REQUIRED_TEXT),
        Some("toml" | "sh" | "py" | "yml" | "yaml") => format!("# {}\n\n", REQUIRED_TEXT),
        _ => return Err(Error::new(ErrorKind::Other, "Unknown file extension")),
    };

    let new_contents = if contents.starts_with('\n') {
        format!("{}{}", header, contents)
    } else {
        format!("{}{}", header, contents)
    };

    fs::write(path, new_contents)?;
    Ok(())
}

fn relative_path(path: &Path) -> String {
    match path.strip_prefix(&*PROJECT_ROOT) {
        Ok(rel_path) => rel_path.to_string_lossy().to_string(),
        Err(_) => path.to_string_lossy().to_string(),
    }
}
