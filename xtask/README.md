# ASPEED DDK XTask

This crate provides development automation tasks for the ASPEED DDK project, inspired by the [xtask pattern](https://github.com/matklad/cargo-xtask).

## Usage

All commands should be run from the project root:

```bash
# Build the project
cargo xtask build

# Build for release
cargo xtask build --release

# Build with specific features
cargo xtask build --features "test-rsa,test-hash"

# Run clippy
cargo xtask clippy

# Check code formatting
cargo xtask format

# Fix code formatting
cargo xtask format --fix

# Build documentation
cargo xtask docs

# Open documentation after building
cargo xtask docs --open

# Check license headers
cargo xtask header-check

# Fix license headers
cargo xtask header-fix

# Run tests
cargo xtask test

# Run only unit tests
cargo xtask test --unit

# Run only integration tests  
cargo xtask test --integration

# Generate UART boot image
cargo xtask gen-boot-image --input target/thumbv7em-none-eabihf/release/aspeed-ddk --output boot.img

# Run hardware tests (requires hardware setup)
cargo xtask hardware-test --uart /dev/ttyUSB0

# Run specific hardware test suite
cargo xtask hardware-test --uart /dev/ttyUSB0 --suite rsa

# Run all pre-commit checks
cargo xtask precommit
```

## Available Hardware Test Suites

- `rsa` - RSA cryptographic tests
- `ecdsa` - ECDSA cryptographic tests  
- `hash` - Hash function tests
- `hmac` - HMAC tests

## Pre-commit Checks

The `precommit` command runs all quality checks:
- Code formatting check
- Clippy linting
- License header check
- Unit and integration tests

This is useful to run before committing changes to ensure code quality.

## Implementation

The xtask implementation includes:

- **Build automation** - Cross-compilation for ARM Cortex-M targets
- **Code quality** - Clippy linting with embedded-specific rules
- **Documentation** - Automated doc generation
- **Testing** - Unit, integration, and hardware tests
- **License management** - Automated license header checks and fixes
- **Boot image generation** - UART boot image creation for hardware testing

Each module is designed to be maintainable and extensible for future development needs.
