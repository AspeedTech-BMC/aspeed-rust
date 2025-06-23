use crate::pinctrl;
use crate::uart::{self, Config, UartController};
use crate::common::DummyDelay;
use crate::i2c::{self, I2cController};
use ast1060_pac::Peripherals;
use embedded_hal::delay::DelayNs;
use embedded_hal::i2c::ErrorKind;
use embedded_io::Write;
use proposed_traits::i2c_target::{I2CCoreTarget, ReadTarget, RegisterAccess, WriteReadTarget, WriteTarget};

#[derive(Debug)]
pub enum DummyI2CError {
    OtherError,
}

impl embedded_hal::i2c::Error for DummyI2CError {
    fn kind(&self) -> ErrorKind {
        match *self {
            _ => ErrorKind::Other,
        }
    }
}

impl embedded_hal::i2c::ErrorType for DummyI2CTarget {
    type Error = DummyI2CError;
}

struct DummyI2CTarget {
    address: u8,
    buffer: [u8;16],
}

impl I2CCoreTarget for DummyI2CTarget {
    fn init(&mut self, address: u8) -> Result<(), Self::Error> {
        if address == 0 {
            return Err(DummyI2CError::OtherError);
        }
        self.address = address;
        Ok(())
    }
    fn on_transaction_start(&mut self, repeated: bool) {}
    fn on_stop(&mut self){}
    fn on_address_match(&mut self, address: u8) -> bool {
        self.address == address
    }
}

impl ReadTarget for DummyI2CTarget {
    fn on_read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        for i in 0..buffer.len() {
            buffer[i] = self.buffer[i];
        }
        Ok(())
    }
}

impl WriteTarget for DummyI2CTarget {
    fn on_write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        for i in 0..data.len() {
            self.buffer[i] = data[i];
        }
        Ok(())
    }
}

impl WriteReadTarget for DummyI2CTarget{}

impl RegisterAccess for DummyI2CTarget {
    fn write_register(&mut self, address: u8, data: u8) -> Result<(), Self::Error> {
        Ok(())
    }
    fn read_register(&mut self, address: u8, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        Ok((1))
    }
}

pub fn test_i2c_master(uart:&mut UartController<'_>) {
    let _peripherals = unsafe { Peripherals::steal() };
    let mut delay = DummyDelay {};
    let mut dbg_uart = UartController::new(_peripherals.uart, &mut delay);

    writeln!(uart, "\r\n####### I2C master test #######\r\n").unwrap();
    unsafe {
        dbg_uart.init(Config {
            baud_rate: 115200,
            word_length: uart::WordLength::Eight as u8,
            parity: uart::Parity::None,
            stop_bits: uart::StopBits::One,
            clock: 24_000_000,
        });
    }    
    let mut i2c1: I2cController<_, DummyI2CTarget> = I2cController::new(_peripherals.i2c1, i2c::I2cConfig{
        xfer_mode: i2c::I2cXferMode::DmaMode,
        multi_master: true,
        smbus_timeout: true,
        manual_scl_high: 0,
        manual_scl_low: 0,
        manual_sda_hold: 0,
        smbus_alert: false,
        clk_src: 0, // will be updated in driver
        mode: i2c::Mode::Standard,
    }, Some(&mut dbg_uart));
    
    pinctrl::Pinctrl::apply_pinctrl_group(pinctrl::PINCTRL_I2C1);
    i2c1.i2c_init();
    
    let addr = 0x2e; //device ADT7490
    let mut buf = [0x4e];
    if true {
        match i2c1.write(addr, &mut buf) {
            Ok(val) => {writeln!(uart, "i2c write ok: {:?}\r", val).unwrap();},
            Err(e) => {writeln!(uart, "i2c write err: {:?}\r", e).unwrap();},
        }
        match i2c1.read(addr, &mut buf) {
            Ok(val) => {writeln!(uart, "i2c read ok: {:?}\r", val).unwrap();},
            Err(e) => {writeln!(uart, "i2c read err: {:?}\r", e).unwrap();},
        }
        writeln!(uart, "after read data {:#x}, expected: 0x81\r\n", buf[0]).unwrap();
    } else {
        let reg_addr = [0x82, 0x4e, 0x4f, 0x45, 0x3d];
        let reg_val = [0x0, 0x81, 0x7f, 0xff, 0x0];
        let mut buf = [0x0];
        for (i, &off) in reg_addr.iter().enumerate() {
            buf[0] = off;
            match i2c1.write(addr, &mut buf) {
                Ok(val) => {writeln!(uart, "i2c write ok: {:?}\r", val).unwrap();},
                Err(e) => {writeln!(uart, "i2c write err: {:?}\r", e).unwrap();},
            }
            match i2c1.read(addr, &mut buf) {
                Ok(val) => {writeln!(uart, "i2c read ok: {:?}\r", val).unwrap();},
                Err(e) => {writeln!(uart, "i2c read err: {:?}\r", e).unwrap();},
            }
            writeln!(uart, "after read data {:#x}, expected: {:#x}\r\n", buf[0], reg_val[i]).unwrap();
        }
        if false {
            writeln!(uart, "########### write 0x3 to offset 0x82 \r\n").unwrap();
            let mut buf2 = [0x82, 0x3];
            match i2c1.write(addr, &mut buf2) {
                Ok(val) => {writeln!(uart, "i2c write ok: {:?}\r", val).unwrap();},
                Err(e) => {writeln!(uart, "i2c write err: {:?}\r", e).unwrap();},
            }
            buf[0] = 0x82;
            writeln!(uart, "########### read 0x82 \r\n").unwrap();
            match i2c1.write(addr, &mut buf) {
                Ok(val) => {writeln!(uart, "i2c write ok: {:?}\r", val).unwrap();},
                Err(e) => {writeln!(uart, "i2c write err: {:?}\r", e).unwrap();},
            }
            match i2c1.read(addr, &mut buf) {
                Ok(val) => {writeln!(uart, "i2c read ok: {:?}\r", val).unwrap();},
                Err(e) => {writeln!(uart, "i2c read err: {:?}\r", e).unwrap();},
            }
            writeln!(uart, "after read data {:#x}, expected: {:#x}\r\n", buf[0], buf2[1]).unwrap();
        }
    }
}

pub fn test_i2c_slave(uart:&mut UartController<'_>) {
    let _peripherals = unsafe { Peripherals::steal() };
    let mut delay = DummyDelay {};
    let mut dbg_uart = UartController::new(_peripherals.uart, &mut delay);
    let mut test_count = 100000;

    writeln!(uart, "\r\n####### I2C slave test #######\r\n").unwrap();
    unsafe {
        dbg_uart.init(Config {
            baud_rate: 115200,
            word_length: uart::WordLength::Eight as u8,
            parity: uart::Parity::None,
            stop_bits: uart::StopBits::One,
            clock: 24_000_000,
        });
    }
    //i2c2 as slave
    let mut i2c2: I2cController<_, DummyI2CTarget> = I2cController::new(_peripherals.i2c2, i2c::I2cConfig{
        xfer_mode: i2c::I2cXferMode::DmaMode,
        multi_master: true,
        smbus_timeout: true,
        manual_scl_high: 0,
        manual_scl_low: 0,
        manual_sda_hold: 0,
        smbus_alert: false,
        clk_src: 0, // will be updated in driver
        mode: i2c::Mode::Standard,
    }, Some(&mut dbg_uart));
    
    pinctrl::Pinctrl::apply_pinctrl_group(pinctrl::PINCTRL_I2C2);
    i2c2.i2c_init();
    
    match i2c2.i2c_aspeed_slave_register(0x42, None) {
        Ok(val) => {writeln!(uart, "i2c slave register ok: {:?}\r", val).unwrap();},
        Err(e) => {writeln!(uart, "i2c slave register err: {:?}\r", e).unwrap();},
    }
    let mut delay_slave = DummyDelay {};
    while test_count>0 {
        delay_slave.delay_ms(10);
        i2c2.aspeed_i2c_isr();
        test_count -= 1;
    }

}