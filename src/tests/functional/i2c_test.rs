use crate::common::{DummyDelay, NoOpLogger, UartLogger};
use crate::i2c::ast1060_i2c::Ast1060I2c;
use crate::i2c::common::{I2cConfigBuilder, I2cSpeed, I2cXferMode};
use crate::i2c::i2c::{HardwareInterface, I2cController};
use crate::pinctrl;
use crate::uart::{self, Config, UartController};
use ast1060_pac::Peripherals;
use embedded_hal::delay::DelayNs;
use embedded_hal::i2c::ErrorKind;
use embedded_io::Write;
use proposed_traits::i2c_target::{
    I2CCoreTarget, ReadTarget, RegisterAccess, WriteReadTarget, WriteTarget,
};

#[derive(Debug)]
pub enum DummyI2CError {
    OtherError,
}

impl embedded_hal::i2c::Error for DummyI2CError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

impl embedded_hal::i2c::ErrorType for DummyI2CTarget {
    type Error = DummyI2CError;
}

struct DummyI2CTarget {
    address: u8,
    buffer: [u8; 16],
    read_idx: usize,
}

impl I2CCoreTarget for DummyI2CTarget {
    fn init(&mut self, address: u8) -> Result<(), Self::Error> {
        if address == 0 {
            return Err(DummyI2CError::OtherError);
        }
        self.address = address;
        Ok(())
    }
    fn on_transaction_start(&mut self, _repeated: bool) {}
    fn on_stop(&mut self) {}
    fn on_address_match(&mut self, address: u8) -> bool {
        self.address == address
    }
}

impl ReadTarget for DummyI2CTarget {
    fn on_read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        buffer[0] = self.buffer[self.read_idx];
        self.read_idx += 1;
        if self.read_idx == self.buffer.len() {
            self.read_idx = 0;
        }
        Ok(1)
    }
}

impl WriteTarget for DummyI2CTarget {
    fn on_write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        for i in 0..data.len() {
            self.buffer[i] = data[i];
        }
        self.read_idx = 0;
        Ok(())
    }
}

impl WriteReadTarget for DummyI2CTarget {}

impl RegisterAccess for DummyI2CTarget {
    fn write_register(&mut self, address: u8, data: u8) -> Result<(), Self::Error> {
        if address as usize >= self.buffer.len() {
            return Err(DummyI2CError::OtherError);
        }
        self.buffer[address as usize] = data;
        Ok(())
    }
    fn read_register(&mut self, address: u8, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        if address as usize >= self.buffer.len() {
            return Err(DummyI2CError::OtherError);
        }
        buffer[0] = self.buffer[address as usize];
        Ok(1)
    }
}

pub fn test_i2c_master(uart: &mut UartController<'_>) {
    let _peripherals = unsafe { Peripherals::steal() };
    let mut delay = DummyDelay {};
    let mut dbg_uart = UartController::new(_peripherals.uart, &mut delay);

    writeln!(uart, "\r\n####### I2C master test #######\r\n").unwrap();
    unsafe {
        dbg_uart.init(&Config {
            baud_rate: 115200,
            word_length: uart::WordLength::Eight as u8,
            parity: uart::Parity::None,
            stop_bits: uart::StopBits::One,
            clock: 24_000_000,
        });
    }
    let i2c_config = I2cConfigBuilder::new()
        .xfer_mode(I2cXferMode::DmaMode)
        .multi_master(true)
        .smbus_timeout(true)
        .smbus_alert(false)
        .speed(I2cSpeed::Standard)
        .build();
    let mut i2c1: I2cController<
        Ast1060I2c<ast1060_pac::I2c1, DummyI2CTarget, UartLogger>,
        NoOpLogger,
    > = I2cController {
        hardware: Ast1060I2c::new(UartLogger::new(&mut dbg_uart)),
        config: i2c_config,
        logger: NoOpLogger {},
    };

    pinctrl::Pinctrl::apply_pinctrl_group(pinctrl::PINCTRL_I2C1);
    i2c1.hardware.init(&mut i2c1.config);

    let addr = 0x2e; //device ADT7490
    let mut buf = [0x4e];
    if true {
        match i2c1.hardware.write(addr, &mut buf) {
            Ok(val) => {
                writeln!(uart, "i2c write ok: {:?}\r", val).unwrap();
            }
            Err(e) => {
                writeln!(uart, "i2c write err: {:?}\r", e).unwrap();
            }
        }
        match i2c1.hardware.read(addr, &mut buf) {
            Ok(val) => {
                writeln!(uart, "i2c read ok: {:?}\r", val).unwrap();
            }
            Err(e) => {
                writeln!(uart, "i2c read err: {:?}\r", e).unwrap();
            }
        }
        writeln!(uart, "after read data {:#x}, expected: 0x81\r\n", buf[0]).unwrap();
    } else {
        let reg_addr = [0x82, 0x4e, 0x4f, 0x45, 0x3d];
        let reg_val = [0x0, 0x81, 0x7f, 0xff, 0x0];
        let mut buf = [0x0];
        for (i, &off) in reg_addr.iter().enumerate() {
            buf[0] = off;
            match i2c1.hardware.write(addr, &mut buf) {
                Ok(val) => {
                    writeln!(uart, "i2c write ok: {:?}\r", val).unwrap();
                }
                Err(e) => {
                    writeln!(uart, "i2c write err: {:?}\r", e).unwrap();
                }
            }
            match i2c1.hardware.read(addr, &mut buf) {
                Ok(val) => {
                    writeln!(uart, "i2c read ok: {:?}\r", val).unwrap();
                }
                Err(e) => {
                    writeln!(uart, "i2c read err: {:?}\r", e).unwrap();
                }
            }
            writeln!(
                uart,
                "after read data {:#x}, expected: {:#x}\r\n",
                buf[0], reg_val[i]
            )
            .unwrap();
        }
        if false {
            writeln!(uart, "########### write 0x3 to offset 0x82 \r\n").unwrap();
            let mut buf2 = [0x82, 0x3];
            match i2c1.hardware.write(addr, &mut buf2) {
                Ok(val) => {
                    writeln!(uart, "i2c write ok: {:?}\r", val).unwrap();
                }
                Err(e) => {
                    writeln!(uart, "i2c write err: {:?}\r", e).unwrap();
                }
            }
            buf[0] = 0x82;
            writeln!(uart, "########### read 0x82 \r\n").unwrap();
            match i2c1.hardware.write(addr, &mut buf) {
                Ok(val) => {
                    writeln!(uart, "i2c write ok: {:?}\r", val).unwrap();
                }
                Err(e) => {
                    writeln!(uart, "i2c write err: {:?}\r", e).unwrap();
                }
            }
            match i2c1.hardware.read(addr, &mut buf) {
                Ok(val) => {
                    writeln!(uart, "i2c read ok: {:?}\r", val).unwrap();
                }
                Err(e) => {
                    writeln!(uart, "i2c read err: {:?}\r", e).unwrap();
                }
            }
            writeln!(
                uart,
                "after read data {:#x}, expected: {:#x}\r\n",
                buf[0], buf2[1]
            )
            .unwrap();
        }
    }
}

#[cfg(feature = "i2c_target")]
static mut TEST_TARGET: DummyI2CTarget = DummyI2CTarget {
    address: 0x42,
    buffer: [0; 16],
    read_idx: 0,
};
#[cfg(feature = "i2c_target")]
pub fn test_i2c_slave(uart: &mut UartController<'_>) {
    let _peripherals = unsafe { Peripherals::steal() };
    let mut delay = DummyDelay {};
    let mut dbg_uart = UartController::new(_peripherals.uart, &mut delay);

    writeln!(uart, "\r\n####### I2C slave test #######\r\n").unwrap();
    unsafe {
        dbg_uart.init(&Config {
            baud_rate: 115200,
            word_length: uart::WordLength::Eight as u8,
            parity: uart::Parity::None,
            stop_bits: uart::StopBits::One,
            clock: 24_000_000,
        });
    }
    let i2c_config = I2cConfigBuilder::new()
        .xfer_mode(I2cXferMode::DmaMode)
        .multi_master(true)
        .smbus_timeout(true)
        .smbus_alert(false)
        .speed(I2cSpeed::Standard)
        .build();
    //i2c2 as slave
    let mut i2c2: I2cController<
        Ast1060I2c<ast1060_pac::I2c2, DummyI2CTarget, UartLogger>,
        NoOpLogger,
    > = I2cController {
        hardware: Ast1060I2c::new(UartLogger::new(&mut dbg_uart)),
        config: i2c_config,
        logger: NoOpLogger {},
    };

    pinctrl::Pinctrl::apply_pinctrl_group(pinctrl::PINCTRL_I2C2);
    i2c2.hardware.init(&mut i2c2.config);

    unsafe {
        match i2c2
            .hardware
            .i2c_aspeed_slave_register(TEST_TARGET.address, Some(&mut TEST_TARGET))
        {
            Ok(val) => {
                writeln!(uart, "i2c slave register ok: {:?}\r", val).unwrap();
            }
            Err(e) => {
                writeln!(uart, "i2c slave register err: {:?}\r", e).unwrap();
            }
        }
    }
    let mut delay_slave = DummyDelay {};
    let mut test_count = 100000;
    while test_count > 0 {
        delay_slave.delay_ms(10);
        i2c2.hardware.handle_interrupt();
        test_count -= 1;
    }
}
