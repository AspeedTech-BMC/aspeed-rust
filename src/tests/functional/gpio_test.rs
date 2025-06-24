use ast1060_pac::Peripherals;
use embedded_hal::digital::{InputPin, OutputPin, StatefulOutputPin};
use embedded_io::Write;

use crate::uart::UartController;
use crate::gpio::{gpioa, Floating, GpioExt};


pub fn test_gpioa(uart:&mut UartController<'_>) {
    let _peripherals = unsafe { Peripherals::steal() };
    let gpio = _peripherals.gpio;

    let gpioa = gpioa::GPIOA::new(gpio).split();
    uart.write_all(b"\r\n####### GPIO test #######\r\n").unwrap();
    // input test
    let mut pa0 = gpioa.pa0.into_pull_down_input();
    if pa0.is_low().unwrap() {
        uart.write_all(b"\rGPIOA pin0 is low\r\n").unwrap();
    }
    let mut pa1 = gpioa.pa1.into_pull_up_input();
    if pa1.is_high().unwrap() {
        uart.write_all(b"\rGPIOA pin1 is high\r\n").unwrap();
    }
    // output test
    let mut pa3 = gpioa.pa3.into_open_drain_output::<Floating>();
    pa3.set_low().unwrap();
    if pa3.is_set_low().unwrap() {
        uart.write_all(b"\rGPIOA pin3 set low successfully\r\n").unwrap();
    }
    pa3.set_high().unwrap();
    if pa3.is_set_high().unwrap() {
        uart.write_all(b"\rGPIOA pin3 set high successfully\r\n").unwrap();
    }

    let mut pa4 = gpioa.pa4.into_push_pull_output();
    pa4.set_low().unwrap();
    if pa4.is_set_low().unwrap() {
        uart.write_all(b"\rGPIOA pin4 set low successfully\r\n").unwrap();
    }
    pa4.set_high().unwrap();
    if pa4.is_set_high().unwrap() {
        uart.write_all(b"\rGPIOA pin4 set high successfully\r\n").unwrap();
    }
}
