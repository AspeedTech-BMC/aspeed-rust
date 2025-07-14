// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::process::Command;

static PROJECT_ROOT: Lazy<PathBuf> = Lazy::new(|| {
    std::path::Path::new(&env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
});

pub fn clippy() -> Result<()> {
    println!("Running clippy...");

    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args([
            "clippy",
            "--workspace",
            "--lib",
            "--bins",
            "--exclude",
            "xtask", // Exclude xtask from clippy checks
            "--target",
            "thumbv7em-none-eabihf",
            "--",
            "-D",
            "warnings",
            "-D",
            "clippy::all",
            "-W",
            "clippy::pedantic",
            "-A",
            "clippy::module_name_repetitions", // Allow common pattern in embedded
            "-A",
            "clippy::missing_errors_doc", // Not always needed for internal APIs
            "-A",
            "clippy::missing_panics_doc", // Not always needed for internal APIs
        ])
        .status()?;

    if !status.success() {
        bail!("Clippy found issues");
    }

    println!("✅ Clippy checks passed");
    Ok(())
}
