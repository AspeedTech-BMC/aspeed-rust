# Minimalist binary crate for ASPEED

> Based on the  template for building applications for ARM Cortex-M microcontrollers


## Dependencies

To build embedded programs using this template you'll need:

- Rust  toolchain. 

- `rust-std` components (pre-compiled `core` crate) for the ARM Cortex-M
  targets. Run:

``` console
$ rustup target add thumbv7em-none-eabihf
```

## Building this app

$ cargo build --release

## Using this app

1. **Start the JLinkGDBServer**:
    ```sh
    JLinkGDBServer -device cortex-m4 -if swd
    ```

2. **Run the program with GDB**:
    ```sh
    gdb-multiarch target/thumbv7em-none-eabihf/release/aspeed-ddk
    
    ```

3. **Enable semihosting in GDB**:
    ```gdb
    target remote :2331
    monitor semihosting IOClient 2
    load
    continue
    ```

## Generate Image for AST1060

- Generate Image for Programming

   ```sh
   cargo build;cargo objcopy -- -O binary ast10x0.bin
   ```

- Generate Image for Boot from UART
   ```sh
   cargo build;cargo objcopy -- -O binary ast10x0.bin
   scripts/gen_uart_booting_image.py ast10x0.bin uart_ast10x0.bin
   ```

## Runing the app on QEMU

### Build QEMU
1. git clone https://github.com/qemu/qemu
2. Run the following commands to build qemu
   ```sh
   mkdir build
   cd build
   ../qemu/configure --target-list=arm-linux-user,arm-softmmu,aarch64-softmmu,aarch64-linux-user,riscv32-softmmu --enable-docs --enable-slirp --enable-gcrypt
   make -j 4
   ```

### Run
1. Run the image in QEMU using `ast1030-evb` machine
   ```sh
   qemu-system-arm -M ast1030-evb -nographic -kernel ~/work/rot/aspeed/aspeed-rust/target/thumbv7em-none-eabihf/debug/aspeed-ddk
   Hello, world!
   aspeed_ddk!
   ```
