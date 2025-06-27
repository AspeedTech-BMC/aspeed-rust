use crate::uart::UartController;
use crate::i2c::common::I2cConfig;
use embedded_hal::i2c::{Operation, SevenBitAddress};
use embedded_io::Write;

trait HardwareInterface {
    type Error: embedded_hal::i2c::Error + core::fmt::Debug;
    
    // Methods return hardware-specific errors
    fn reset(&mut self);
    fn configure_timing(&mut self, config: &I2cConfig) -> Result<(), Self::Error>;
    fn enable_interrupts(&mut self, mask: u32);
    fn clear_interrupts(&mut self, mask: u32);
    //fn start_transfer(&mut self, state: &TransferState, mode: TransferMode) -> Result<(), Self::Error>;
    //fn handle_interrupt(&mut self) -> InterruptStatus;
    fn is_bus_busy(&self) -> bool;
    fn recover_bus(&mut self) -> Result<(), Self::Error>;


    
}

trait Logger {
    fn debug(&mut self, msg: &str);
    fn error(&mut self, msg: &str);
}

// No-op implementation for production builds
struct NoOpLogger;
impl Logger for NoOpLogger {
    fn debug(&mut self, _msg: &str) {}
    fn error(&mut self, _msg: &str) {}
}

// UART logger adapter (separate concern)
struct UartLogger<'a> {
    uart: &'a mut UartController<'a>,
}

impl<'a> Logger for UartLogger<'a> {
    fn debug(&mut self, msg: &str) {
        writeln!(self.uart, "{}", msg).ok();
    }
    fn error(&mut self, msg: &str) {
        writeln!(self.uart, "ERROR: {}", msg).ok();
    }
}
pub struct I2cController<H: HardwareInterface, L: Logger = NoOpLogger> {
    hardware: H,
    logger: L,
}

impl<H: HardwareInterface, L: Logger> embedded_hal::i2c::ErrorType for I2cController<H, L> {
    type Error = H::Error;
}
impl<H: HardwareInterface, L: Logger> embedded_hal::i2c::I2c for I2cController<H, L> {
    fn read(&mut self, addr: SevenBitAddress, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.hardware.read(addr, buffer)
    }

    fn write(&mut self, addr: SevenBitAddress, bytes: &[u8]) -> Result<(), Self::Error> {
        self.hardware.write(addr, bytes)
    }

    fn write_read(
        &mut self,
        addr: SevenBitAddress,
        bytes: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), Self::Error> {
        self.hardware.write_read(addr, bytes, buffer)
    }

    fn transaction(
        &mut self,
        addr: SevenBitAddress,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Self::Error> {
        self.hardware.transaction_slice(addr, operations)
    }
}