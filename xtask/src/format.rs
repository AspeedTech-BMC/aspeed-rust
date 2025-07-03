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

pub fn format(fix: bool) -> Result<()> {
    if fix {
        println!("Formatting code...");

        let status = Command::new("cargo")
            .current_dir(&*PROJECT_ROOT)
            .args(["fmt", "--all"])
            .status()?;

        if !status.success() {
            bail!("Code formatting failed");
        }

        println!("✅ Code formatted successfully");
    } else {
        println!("Checking code formatting...");

        let status = Command::new("cargo")
            .current_dir(&*PROJECT_ROOT)
            .args(["fmt", "--all", "--check"])
            .status()?;

        if !status.success() {
            bail!("Code formatting check failed. Run 'cargo xtask format --fix' to fix formatting issues.");
        }

        println!("✅ Code formatting is correct");
    }

    Ok(())
}
