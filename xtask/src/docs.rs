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

pub fn docs(open: bool) -> Result<()> {
    println!("Building documentation...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT);
    cmd.args([
        "doc",
        "--workspace",
        "--exclude",
        "xtask",
        "--target",
        "thumbv7em-none-eabihf",
        "--no-deps",
    ]);

    if open {
        cmd.arg("--open");
    }

    let status = cmd.status()?;
    if !status.success() {
        bail!("Documentation build failed");
    }

    println!("✅ Documentation built successfully");
    if !open {
        println!("Open documentation with: cargo doc --open");
    }

    Ok(())
}
