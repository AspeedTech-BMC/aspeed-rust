use crate::common::{Logger, NoOpLogger};
use crate::i2c::common::I2cConfig;
use embedded_hal::i2c::{Operation, SevenBitAddress};


pub trait HardwareInterface {
    type Error: embedded_hal::i2c::Error + core::fmt::Debug;
    
    // Methods return hardware-specific errors
    fn init(&mut self, config: &mut I2cConfig);
    fn configure_timing(&mut self, config: &mut I2cConfig);
    fn enable_interrupts(&mut self, mask: u32);
    fn clear_interrupts(&mut self, mask: u32);
    #[cfg(feature = "i2c_target")]
    fn enable_slave_interrupts(&mut self, mask: u32);
    #[cfg(feature = "i2c_target")]
    fn clear_slave_interrupts(&mut self, mask: u32);
    //fn start_transfer(&mut self, state: &TransferState, mode: TransferMode) -> Result<(), Self::Error>;
    fn handle_interrupt(&mut self);
    //fn is_bus_busy(&self) -> bool;
    //fn recover_bus(&mut self) -> Result<(), Self::Error>;


    
}

pub struct I2cController<H: HardwareInterface, L: Logger = NoOpLogger> {
    hardware: H,
    config: I2cConfig,
    logger: L,
}

impl<H: HardwareInterface, L: Logger> embedded_hal::i2c::ErrorType for I2cController<H, L> {
    type Error = H::Error;
}
impl<H: HardwareInterface, L: Logger> embedded_hal::i2c::I2c for I2cController<H, L> {
    fn read(&mut self, addr: SevenBitAddress, buffer: &mut [u8]) -> Result<(), Self::Error> {
        //self.hardware.read(addr, buffer)
        Ok(())
    }

    fn write(&mut self, addr: SevenBitAddress, bytes: &[u8]) -> Result<(), Self::Error> {
        //self.hardware.write(addr, bytes)
        Ok(())
    }

    fn write_read(
        &mut self,
        addr: SevenBitAddress,
        bytes: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), Self::Error> {
        //self.hardware.write_read(addr, bytes, buffer)
        Ok(())
    }

    fn transaction(
        &mut self,
        addr: SevenBitAddress,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Self::Error> {
        //self.hardware.transaction_slice(addr, operations)
        Ok(())
    }
}