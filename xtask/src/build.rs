// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use once_cell::sync::Lazy;
use std::path::{Path, PathBuf};
use std::process::Command;

static PROJECT_ROOT: Lazy<PathBuf> = Lazy::new(|| {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
});

pub fn build(release: bool, target: &str, features: &[String]) -> Result<()> {
    println!("Building ASPEED DDK for target: {}", target);

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT);

    // Build the main project (exclude xtask) for the specified target
    cmd.args([
        "build",
        "--workspace",
        "--exclude",
        "xtask",
        "--target",
        target,
    ]);

    if release {
        cmd.arg("--release");
    }

    if !features.is_empty() {
        cmd.arg("--features");
        cmd.arg(features.join(","));
    }

    let status = cmd.status()?;
    if !status.success() {
        bail!("Build failed");
    }

    println!("✅ Build completed successfully for target: {}", target);
    Ok(())
}

pub fn gen_boot_image(input: &Path, output: &Path) -> Result<()> {
    println!("Generating UART boot image...");

    let script_path = PROJECT_ROOT.join("scripts/gen_uart_booting_image.sh");
    if !script_path.exists() {
        bail!(
            "UART boot image generation script not found at {:?}",
            script_path
        );
    }

    let status = Command::new("bash")
        .arg(&script_path)
        .arg(input)
        .arg(output)
        .current_dir(&*PROJECT_ROOT)
        .status()?;

    if !status.success() {
        bail!("Failed to generate boot image");
    }

    println!("✅ Boot image generated: {:?}", output);
    Ok(())
}

#[allow(dead_code)]
pub fn clean() -> Result<()> {
    println!("Cleaning build artifacts...");

    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(["clean"])
        .status()?;

    if !status.success() {
        bail!("Clean failed");
    }

    println!("✅ Clean completed");
    Ok(())
}
