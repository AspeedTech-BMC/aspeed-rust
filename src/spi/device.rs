use embedded_hal::spi::{ErrorType, Operation, SpiDevice};

use super::SpiBusWithCs;

#[derive(Debug)]
pub struct ChipSelectDevice<'a, B>
where
    B: SpiBusWithCs,
{
    pub bus: &'a mut B,
    pub cs: usize,
}

impl<'a, B> ErrorType for ChipSelectDevice<'a, B>
where
    B: SpiBusWithCs,
{
    type Error = B::Error;
}

impl<'a, B> SpiDevice for ChipSelectDevice<'a, B>
where
    B: SpiBusWithCs,
{
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        self.bus.select_cs(self.cs);

        for op in operations {
            match op {
                Operation::Read(buf) => self.bus.read(buf)?,
                Operation::Write(buf) => self.bus.write(buf)?,
                Operation::Transfer(read, write) => self.bus.transfer(read, write)?,
                Operation::TransferInPlace(buf) => self.bus.transfer_in_place(buf)?,
                Operation::DelayNs(_) => todo!(),
            };
        }

        self.bus.deselect_cs(self.cs);
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.transaction(&mut [Operation::Read(buf)])
    }

    fn write(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.transaction(&mut [Operation::Write(buf)])
    }

    fn transfer(&mut self, read: &mut [u8], write: &[u8]) -> Result<(), Self::Error> {
        self.transaction(&mut [Operation::Transfer(read, write)])
    }

    fn transfer_in_place(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.transaction(&mut [Operation::TransferInPlace(buf)])
    }
}
